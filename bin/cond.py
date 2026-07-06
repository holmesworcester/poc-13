#!/usr/bin/env python3
"""cond — the poc-13 daemon.  Usage: cond <db> [--listen HOST:PORT]

Owns the db exclusively and amortizes replay: load once, then serve verbs over a
unix socket at <db>.sock (con.py proxies to it) and reconcile facts with peers
over TCP. One single-threaded select loop over the runtime seam (bin/runtime.py):
each iteration collects an inbox, `cycle`s it (HOST IN admit + ENGINE DRAIN one
turn), then `pump`s the validated outbox offers (HOST OUT). The daemon decides no
authority and authors nothing outbound — every inbound fact enters through the
admission gate, and there is ONE out door: `pump` reads the `send`/`ship` offers
and `deliver` seals iff the route yields a session secret, else sends bare, so the
handshake response and a sync frame leave the same way.

Transport is ADDRESS-KEYED: facts name a destination
(a connection id, or a raw address pre-session) and the daemon connects there;
nothing binds a fact to a socket. A wire message is 4-byte BE length + 1
discriminator byte + body: 0x00 a bare handshake fact (the sealed request /
connection, which carry their own X25519 envelopes), 0x01 a sealed frame. A frame
is self-describing — its connection id selects the session secret — so which
socket delivered it is irrelevant; the daemon opens it via a frame-family query,
holding no sync policy. The sync re-descend cadence is a fact (sync.cadence, whose
wake@clock alarm sets the select timeout via runtime.next_wake); only the
socket-level request re-dial stays a process-local cadence.
The outbound path never re-ships a fact already sent this session: a per-connection
`sent` set (source-side dedup) means a re-descend that re-asks for an in-flight fact
costs O(diff) discovery, not O(diff) re-shipping — else a bulk catch-up re-ships the
outstanding diff on every re-descend, O(n^2) on the wire. A full outbox parks the
owner (it re-pumps once the buffer drains); a peer's socket break clears its `sent`
so a reconnect re-ships (the connection id outlives the socket)."""
import errno, os, select, signal, socket, sys, time
BIN = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [BIN, os.path.dirname(BIN)]
from kernel import Node, Store, _rd, decode, fact_id, frame
from facts import ROOT
from facts.sync import cadence
from facts.auth import local_signer_secret, endpoint
from facts.connection import request, connection as conn, frame as frames
from runtime import cycle, outbox, pump, next_wake, load, flush, BOUND

OUTCAP = 32 << 20                        # per-address outbox byte cap: overflow parks (healed by re-descend).
                                         # Larger = fewer catch-up round-trips (each re-descend re-fingerprints),
                                         # bounded by the memory a stalled peer may hold. The buffer is a
                                         # bytearray drained by offset, so a big cap stays O(1)-amortized.
CADENCE = 0.5                            # s between redials / periodic root compares per peer
RETAIN_FLOOR = 0                         # sync reconciles [RETAIN_FLOOR, inf) of (ts, FactId); the reserved
                                         # closure need pulls deps below it. The floor IS the retention horizon
                                         # — poc-13 has no retention/purge yet (Further Work), so it is 0
                                         # (reconcile all). A recent frontier-anchored floor is the armed form
                                         # once a coherent fact clock + purge land; test_sync proves the closure
                                         # need still carries below-floor deps into a windowed peer.
BARE, SEALED = 0, 1                      # wire discriminators
now_ms = lambda: int(time.time() * 1000)
now_s = lambda: int(time.time())         # fact-ts unit (kernel now())
_floor_key = lambda ts: b"" if ts <= 0 else ts.to_bytes(8, "big") + b"\x00" * 32   # window floor -> radix key

def serve(node, s, store, flushed):      # one framed verb request per unix connection
    try:
        s.settimeout(1); b = b""
        while (c := s.recv(65536)): b += c
        path, i = _rd(b, 0); args = []
        while i < len(b): a, i = _rd(b, i); args.append(a.decode())
        *segs, verb = path.decode().split(".")
        out = getattr(ROOT.resolve([x.encode() for x in segs]), "CLI", {})[verb](node, *args)
        node.run(); flush(node, store, flushed)
        s.sendall(frame(b"+" + (out or "").encode()))
    except Exception as e:
        try: s.sendall(frame(b"-" + f"{type(e).__name__}: {e}".encode()))
        except OSError: pass
    s.close()

# --- outbound: a persistent socket per destination address ----------------------
# The outbox is a bytearray drained by a send offset (`off`), never re-sliced per
# send, so append and drain are amortized O(1) regardless of buffer size — a fresh
# peer's whole catch-up can queue without the O(n^2) that byte-string concat costs.
SENDWIN = 1 << 20                        # bytes copied out per send() — a bound, not the whole buffer
pending = lambda p: len(p["out"]) - p["off"]   # unsent bytes still buffered

def link(links, addr):                   # get-or-make the outbound link for an address
    p = links.get(addr)
    if p is None: p = links[addr] = {"s": None, "out": bytearray(), "off": 0, "down": 0.0}
    return p

def enqueue(p, kind, body):              # frame one wire message (drop on overflow; deliver pre-checks capacity)
    if pending(p) <= OUTCAP:
        w = bytes([kind]) + body
        p["out"] += len(w).to_bytes(4, "big") + w

def drain(p):                            # push a bounded window; compact the sent prefix amortized
    seg = bytes(p["out"][p["off"]:p["off"] + SENDWIN])
    k = p["s"].send(seg); p["off"] += k
    if p["off"] >= len(p["out"]): p["out"], p["off"] = bytearray(), 0   # fully sent: reset
    elif p["off"] > SENDWIN: del p["out"][:p["off"]]; p["off"] = 0      # reclaim the sent prefix
    return k

def dial(p):                             # non-blocking (re)connect to the address
    h, pt = p["addr"].rsplit(":", 1)
    s = socket.socket(); s.setblocking(False)
    if s.connect_ex((h, int(pt))) not in (0, errno.EINPROGRESS):
        s.close(); p["down"] = time.monotonic() + 0.05
    else: p["s"] = s

# --- inbound: accepted sockets are anonymous byte sources -----------------------
def messages(src):                       # yield (kind, body) for each complete wire message
    while True:
        b = src["inb"]
        if len(b) < 4 or (ln := int.from_bytes(b[:4], "big")) + 4 > len(b): return
        w = b[4:4 + ln]; src["inb"] = b[4 + ln:]
        if w: yield w[0], w[1:]

def main(db, *argv):
    listen, it = None, iter(argv)
    for a in it:
        if a == "--listen": listen = next(it)
        else: sys.exit(f"unknown arg: {a}")
    store = Store(db); node = Node(ROOT); load(node, store); flushed = set(node.durable)
    if not local_signer_secret.current(node): local_signer_secret.keygen(node, int(time.time()))
    if not endpoint.current(node): endpoint.keygen(node, int(time.time()))
    node.run(); flush(node, store, flushed)
    sp = db + ".sock"
    if os.path.exists(sp): os.unlink(sp)
    usock = socket.socket(socket.AF_UNIX); usock.bind(sp); usock.listen(8)
    tsock = None
    if listen:
        h, pt = listen.rsplit(":", 1)
        tsock = socket.create_server((h, int(pt))); tsock.setblocking(False)
    links, inbound = {}, []              # links: addr -> outbound socket; inbound: read sources
    redial, armed = {}, set()                         # redial: addr -> last dial ; armed cids (their sync cadence)
    to_ship = set()                                   # flushed senders awaiting their reap
    sent = {}                                         # cid -> set of what was sent this session: a shipped fact by id
                                                      # AND a sync compare by content hash (both 32-byte digests). The
                                                      # pump skips a repeat, so a re-descend re-asks the still-missing
                                                      # diff but ships each fact once, and a static source re-authoring
                                                      # its same split ships that compare once (else a bulk catch-up is
                                                      # O(n^2) wire). Handshake frames are exempt (must re-send). Cleared
                                                      # for a peer on its socket break, since the connection id is
                                                      # deterministic and outlives the socket — a reconnect re-syncs in
                                                      # full. Process-local, wiped on restart (poc-10 network_outgoing
                                                      # parity). Memory is O(sent) per peer, below the resident set.
    for sg in (signal.SIGINT, signal.SIGTERM): signal.signal(sg, lambda *a: sys.exit(0))
    print("listening:", "%s:%s" % tsock.getsockname()[:2] if tsock else sp, flush=True)
    work = True
    try:
        while True:
            for a, p in list(links.items()):         # bring up outbound links that owe bytes
                if not p["s"] and pending(p) and time.monotonic() >= p["down"]:
                    p["addr"] = a; dial(p)
            reads = [usock] + ([tsock] if tsock else []) + \
                    [p["s"] for p in links.values() if p["s"]] + [i["s"] for i in inbound]
            writes = [p["s"] for p in links.values() if p["s"] and pending(p)]
            r, w, _ = select.select(reads, writes, [], 0 if work else next_wake(node, now_ms(), CADENCE))
            work = False; nowm = time.monotonic()
            # HOST IN — clients, new inbound peers, peer bytes.
            for s in r:
                if s is usock: serve(node, s.accept()[0], store, flushed); work = True
                elif s is tsock:
                    try:
                        c = s.accept()[0]; c.setblocking(False)
                        inbound.append({"s": c, "inb": b""})
                    except OSError: pass
                else:
                    src = next((i for i in inbound if i["s"] is s), None) or \
                          next((p for p in links.values() if p["s"] is s), None)
                    try: c = s.recv(65536)
                    except OSError: c = b""
                    if c: src["inb"] = src.get("inb", b"") + c; work = True
                    elif src in inbound: s.close(); inbound.remove(src)
            n, arrived, inbox = 0, [], []             # collect inbound, bounded per turn
            for src in inbound + [p for p in links.values() if p["s"]]:
                if "inb" not in src: continue
                for kind, body in messages(src):
                    if kind == BARE:
                        inbox.append(body)            # a handshake fact: admit as-is in the cycle
                        rid = _peek_request(body)     # a request fid, peeked (decode, no admit): react after
                        if rid: arrived.append(rid)
                    else:
                        inbox += _open_frame(node, body)   # a sealed frame -> its inner fact bytes
                    n += 1; work = True
                    if n >= BOUND: break
                if n >= BOUND: break
            # ENGINE DRAIN — admit the inbox and drain one bounded turn, presenting the wire's
            # flush reports: a flushed sender that Watches shipped reaps this turn; keep
            # re-presenting until it does, then prune the acted-on. Leftover frontier is next turn.
            cycle(node, inbox, now_ms(), to_ship, BOUND); work |= bool(node.frontier)
            to_ship &= {o for o, _, _ in outbox(node)}     # keep only owners still offering send/ship
            # respond seam: the onus is on the requester — its durable request re-dials on
            # a cadence; the responder just answers each ARRIVAL (no cadence of its own), so
            # a peer that lost its volatile session simply re-asks until it re-handshakes.
            for rid in arrived:
                reply = next((a.value for o, _, a in node.watched(b"respond", conn.SC)
                              if o == rid and a.value), None)
                if reply: conn.respond(node, rid, reply, now_s()); work = True   # response ships via the pump
            # HOST OUT — flush, redial, pump data, open sync rounds (one per peer), drain writes.
            flush(node, store, flushed)
            for addr, env in request.dials(node):     # (re)dial unanswered requests
                a = addr.decode()
                if nowm - redial.get(a, 0) >= CADENCE:
                    enqueue(link(links, a), BARE, env); redial[a] = nowm; work = True
            def deliver(cid, addr, secret, inners):        # one out door: seal iff a session secret, else bare.
                p = link(links, addr.decode()); n = 0      # returns how many inners went out (a prefix): a full
                if secret:                                 # outbox stops the tail, which pump leaves unmarked so
                    for blob, cnt in frames.pack_counts(inners):     # the next re-descend re-ships it. Capacity is
                        if pending(p) > OUTCAP: break      # checked BEFORE sealing, so a wedged peer costs no crypto.
                        enqueue(p, SEALED, frames.seal(blob, cid, secret, os.urandom(24))); n += cnt
                else:
                    for inner in inners:                   # pre-session handshake fact(s), unsealed
                        if pending(p) > OUTCAP: break
                        enqueue(p, BARE, inner); n += 1
                return n
            fired = pump(node, lambda cid: conn.route(node, cid) or (cid, None), deliver, to_ship, sent)
            to_ship |= fired; work |= bool(fired)          # flushed: next turn presents shipped@o and it reaps
            if not node.frontier:
                for _ep, _addr, cid, _who in conn.peers(node):     # a new connection: arm its periodic sync cadence
                    if cid not in armed:                           # the sole round-opener (rounds are facts, not a
                        cadence.arm(node, cid, now_ms()); armed.add(cid); work = True   # daemon reaction)
            for addr, p in links.items():
                if p["s"] and pending(p) and p["s"] in w:
                    try: work |= drain(p) > 0
                    except OSError:
                        p["s"].close(); p["s"], p["out"], p["off"], p["down"] = None, bytearray(), 0, nowm + 0.05
                        for _e, _a, cid, _w in conn.peers(node):     # link down: forget what we shipped this addr,
                            if _a.decode() == addr: sent.pop(cid, None)   # so a reconnect re-ships (cid persists)
    finally:
        usock.close(); os.unlink(sp)
        for p in links.values():
            if p["s"]: p["s"].close()
        for i in inbound: i["s"].close()

def _peek_request(body):                 # a bare handshake fact's fid iff it is a sealed request (no admit)
    try: f = decode(body)
    except Exception: return None
    return fact_id(f) if f.type_tag == request.TAG else None

def _open_frame(node, body):             # a sealed data frame -> its inner fact bytes (opened by connection id)
    cid = frames.frame_cid(body)         # the daemon opens via a family query; it holds no sync policy
    r = conn.route(node, cid) if cid else None
    if not r: return []                  # no session secret yet: drop (sync re-descends next cadence)
    blob = frames.open_frame(body, r[1])
    return list(frames.unframe(blob)) if blob is not None else []   # tamper/wrong key -> whole-frame miss

if __name__ == "__main__":
    main(*sys.argv[1:])
