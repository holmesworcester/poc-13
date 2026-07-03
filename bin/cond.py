#!/usr/bin/env python3
"""cond — the poc-13 daemon.  Usage: cond <db> [--listen HOST:PORT]

Owns the db exclusively and amortizes replay: load once, then serve verbs over a
unix socket at <db>.sock (con.py proxies to it) and reconcile facts with peers
over TCP. One single-threaded select loop; each iteration is the three-phase host
turn (HOST IN admit / ENGINE DRAIN / HOST OUT perform). The daemon decides no
authority — every inbound fact enters through the admission gate, the pump reads
only validated offers, and time is the OS clock handed to the turn.

Transport is ADDRESS-KEYED, like poc-10's network queue: facts name a destination
ADDRESS and the daemon connects there; nothing binds a fact to a socket. A wire
message is 4-byte BE length + 1 discriminator byte + body: 0x00 a bare handshake
fact (the sealed request / connection, which carry their own X25519 envelopes),
0x01 a sealed frame (frame(version, connection_id, nonce, ciphertext)). A frame
is self-describing — its connection id selects the session secret from the fact
store — so which socket delivered it is irrelevant. Retries (redial an unanswered
request, re-open a sync compare) are process-local cadence, as poc-10 keeps
them. Backpressure parks, never drops: bounded admits per turn, per-address
outbox cap, select-gated writes."""
import errno, os, select, signal, socket, sys, time
BIN = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [BIN, os.path.dirname(BIN)]
from kernel import Node, Store, _rd, decode, fact_id, frame
from facts import ROOT
from facts.outbox import sent
from facts.sync import compare as sync, reply as sreply
from facts.auth import local_signer_secret, endpoint
from facts.connection import request, connection as conn, frame as frames
from con import flush, load

BOUND = 64                               # admits per turn; engine drain bound
OUTCAP = 1 << 20                         # per-address outbox byte cap: overflow parks
CADENCE = 0.5                            # s between redials / root compares per peer
BARE, SEALED = 0, 1                      # wire discriminators
now_ms = lambda: int(time.time() * 1000)

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
def link(links, addr):                   # get-or-make the outbound link for an address
    p = links.get(addr)
    if p is None: p = links[addr] = {"s": None, "out": b"", "down": 0.0}
    return p

def enqueue(p, kind, body):              # frame one wire message (park on overflow)
    if len(p["out"]) <= OUTCAP:
        w = bytes([kind]) + body
        p["out"] += len(w).to_bytes(4, "big") + w

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

def _ids(v):                             # a ship offer's value: length-framed fact ids
    out, i = [], 0
    while i < len(v): x, i = _rd(v, i); out.append(x)
    return out

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
    responded, redial, compared = set(), {}, {}      # process-local cadence markers
    shipped, known = set(), {fid for _, fid in sync.leaves(node)}
    for sg in (signal.SIGINT, signal.SIGTERM): signal.signal(sg, lambda *a: sys.exit(0))
    print("listening:", "%s:%s" % tsock.getsockname()[:2] if tsock else sp, flush=True)
    work = True
    try:
        while True:
            for a, p in list(links.items()):         # bring up outbound links that owe bytes
                if not p["s"] and p["out"] and time.monotonic() >= p["down"]:
                    p["addr"] = a; dial(p)
            reads = [usock] + ([tsock] if tsock else []) + \
                    [p["s"] for p in links.values() if p["s"]] + [i["s"] for i in inbound]
            writes = [p["s"] for p in links.values() if p["s"] and p["out"]]
            r, w, _ = select.select(reads, writes, [], 0 if work else 0.05)
            work = False
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
            n = 0                                     # admit inbound, bounded per turn
            for src in inbound + [p for p in links.values() if p["s"]]:
                if "inb" not in src: continue
                for kind, body in messages(src):
                    if kind == BARE: _admit_bare(node, body)
                    else: _admit_frame(node, body, sreply)
                    n += 1; work = True
                    if n >= BOUND: break
                if n >= BOUND: break
            # respond seam: only the addressee offers `respond`; author + ship the connection.
            for o, _, a in node.watched(b"respond", conn.SC):
                rid, reply = a.target[1], a.value
                if rid in responded or not reply: continue
                cid = conn.respond(node, rid, reply, int(time.time()))
                if cid:
                    responded.add(rid)
                    enqueue(link(links, reply.decode()), BARE, node.durable.get(cid) or _enc(node, cid))
                    work = True
            # ENGINE DRAIN — bounded; leftover frontier is next turn's work.
            node.turn(now_ms(), BOUND); work |= bool(node.frontier)
            # HOST OUT — flush, redial, pump data, sync cadence + live tail, drain writes.
            flush(node, store, flushed)
            nowm = time.monotonic()
            for addr, env in request.dials(node):     # (re)dial unanswered requests
                a = addr.decode()
                if nowm - redial.get(a, 0) >= CADENCE:
                    enqueue(link(links, a), BARE, env); redial[a] = nowm; work = True
            work |= _pump_data(node, links, shipped)
            if not node.frontier:
                ls = sync.leaves(node)
                fresh = [fid for _, fid in ls if fid not in known]
                if fresh:                             # live tail: fresh leaves straight to peers
                    known.update(fresh); seen = set()
                    for fid in fresh: seen |= sync.closure(node, fid)
                    for _ep, _addr, cid in conn.peers(node):
                        sreply.tail(node, cid, sorted(seen), int(time.time())); work = True
                for _ep, _addr, cid in conn.peers(node):   # cadence: fresh root compares
                    if nowm - compared.get(cid, 0) >= CADENCE:
                        sreply.open_round(node, cid, int(time.time()), sync.initiate(node, ls)[0])
                        compared[cid], work = nowm, True
            for p in links.values():
                if p["s"] and p["out"] and p["s"] in w:
                    try: k = p["s"].send(p["out"]); p["out"] = p["out"][k:]; work |= k > 0
                    except OSError: p["s"].close(); p["s"], p["out"], p["down"] = None, b"", nowm + 0.05
    finally:
        usock.close(); os.unlink(sp)
        for p in links.values():
            if p["s"]: p["s"].close()
        for i in inbound: i["s"].close()

def _enc(node, fid):
    from kernel import encode
    return encode(node.facts[fid])

def _admit_bare(node, body):             # a handshake fact (sealed request / connection)
    try: node.admit(body)
    except Exception: pass

def _admit_frame(node, body, sreply):    # a sealed data frame: open by its own connection id
    cid = frames.frame_cid(body)
    r = conn.route(node, cid) if cid else None
    if not r: return                     # no session secret yet: drop (sync will resend)
    blob = frames.open_frame(body, r[1])
    if blob is None: return              # tamper / wrong key: whole-frame miss
    for inner in frames.unframe(blob):
        try: fid = node.admit(inner)
        except Exception: fid = None
        if fid and node.facts[fid].type_tag == sync.TAG:
            sreply.answer(node, fid, cid, int(time.time()))

def _pump_data(node, links, shipped):    # stage validated send/ship offers as sealed frames
    rows = {}
    for role in (b"send", b"ship"):
        for o, _, a in node.watched(role, b"outbox"):
            if o not in shipped: rows.setdefault(o, []).append(a)
    moved = False
    for o, atoms in sorted(rows.items()):
        cid = atoms[0].target[1]
        r = conn.route(node, cid)
        if not r: continue               # no route yet: the offer stands (park)
        addr, secret = r; p = link(links, addr.decode())
        if len(p["out"]) > OUTCAP: continue
        inners = []
        for a in sorted(atoms, key=lambda a: (a.role, a.value)):
            if a.role == b"send": inners.append(a.value)
            else: inners += [node.durable[x] for x in _ids(a.value) if x in node.durable]
        for blob in frames.pack(inners):
            enqueue(p, SEALED, frames.seal(blob, cid, secret, os.urandom(24)))
        shipped.add(o); sent.report(node, o, int(time.time())); moved = True
    return moved

if __name__ == "__main__":
    main(*sys.argv[1:])
