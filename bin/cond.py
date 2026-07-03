#!/usr/bin/env python3
"""cond — the poc-13 daemon.  Usage: cond <db> [--listen HOST:PORT] [--peer HOST:PORT ...]

Owns the db exclusively and amortizes replay: load once, then serve verbs over
a unix socket at <db>.sock (con.py proxies to it) and reconcile facts with peers
over TCP. One single-threaded select loop; each iteration is the three-phase
host turn (HOST IN / ENGINE DRAIN / HOST OUT). The wire carries ONE message
type — 4-byte big-endian length + one fact's canonical bytes. Most fact frames
are connection.frame BUNDLES: many facts packed into one wire frame, so a peer
absorbs a whole batch per turn instead of one fact — that closes the bulk
catch-up gap where per-turn gating, not the pipe, set the pace. Peers come from
connection.request facts (--peer flags author one each at startup); on connect
each side sends a signed connection.hello binding the session to its identity
key. Backpressure mirrors the frontier: overflow parks, never drops — bounded
admits per turn, bounded per-peer outboxes, select-gated non-blocking writes."""
import errno, os, select, signal, socket, sys, time
BIN = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [BIN, os.path.dirname(BIN)]
from kernel import Node, Store, _rd, decode, fact_id, frame
from facts import ROOT
from facts.sync import compare as sync
from facts.auth import local_signer_secret
from facts.connection import request, hello, connection as conn, frame as bundles
from con import flush, load

BOUND = 64                               # admits per peer per turn; engine drain bound
OUTCAP = 1 << 20                         # per-peer outbox byte cap: overflow stays unsent

def serve(node, s, store, flushed):      # one framed verb request per connection
    try:
        s.settimeout(1); b = b""
        while (c := s.recv(65536)): b += c           # client shut down its write side
        path, i = _rd(b, 0); args = []
        while i < len(b): a, i = _rd(b, i); args.append(a.decode())
        *segs, verb = path.decode().split(".")
        out = getattr(ROOT.resolve([x.encode() for x in segs]), "CLI", {})[verb](node, *args)
        node.run(); flush(node, store, flushed)      # durable before the reply
        s.sendall(frame(b"+" + (out or "").encode()))
    except Exception as e:
        try: s.sendall(frame(b"-" + f"{type(e).__name__}: {e}".encode()))
        except OSError: pass
    s.close()

def peer(s, addr):                       # a full-duplex link; addr set only for outbound peers
    return {"s": s, "addr": addr, "out": b"", "inb": b"", "pend": [], "down": 0.0, "fp": None}

def connect(p):                          # outbound (re)connect: recurrence = liveness
    h, pt = p["addr"].rsplit(":", 1)
    s = socket.socket(); s.setblocking(False)
    if s.connect_ex((h, int(pt))) not in (0, errno.EINPROGRESS):
        s.close(); p["down"] = time.monotonic() + 0.05
    else: p["s"], p["fp"] = s, None

def drop(p, peers):                      # dead link: outbound damps + reconnects, inbound is forgotten
    if p["s"]: p["s"].close()
    p["s"], p["inb"], p["pend"] = None, b"", []
    if p["addr"]: p["out"], p["fp"], p["down"] = b"", None, time.monotonic() + 0.05
    else: peers.remove(p)

def enqueue(p, fb):                      # frame one wire message into the outbox; overflow parks
    if len(p["out"]) <= OUTCAP: p["out"] += len(fb).to_bytes(4, "big") + fb

def ship(p, frames):                     # pack fact frames into bundles, then onto the wire
    for w in bundles.pack(frames): enqueue(p, w)

def unpack(fb):                          # one wire fact -> the fact frames it delivers
    try: f = decode(fb)
    except Exception: return [fb]        # a bad wire frame: admit it, miss it, count it as one
    return bundles.items(f) if f.type_tag == bundles.TAG else [fb]   # a bundle -> its inners

def admit_one(node, fb, fresh):          # admit one inner fact through the normal gate
    try: new = fact_id(decode(fb)) not in node.facts
    except Exception: return              # strict decode: a bad inner is inert, siblings unaffected
    fid = node.admit(fb)
    if fid and new: fresh.append((fid, node.facts[fid].type_tag))

def intake(node, p):                     # admit up to BOUND inner facts; a half-drained bundle parks
    n, fresh, q = 0, [], p["pend"]
    while n < BOUND:
        if not q:                        # refill from the next whole wire frame (bundle or bare fact)
            b = p["inb"]
            if len(b) < 4 or (ln := int.from_bytes(b[:4], "big")) + 4 > len(b): break
            q, p["inb"] = unpack(b[4:4 + ln]), b[4 + ln:]
        admit_one(node, q.pop(0), fresh); n += 1
    p["pend"] = q
    return fresh

def main(db, *argv):
    listen, addrs, it = None, [], iter(argv)
    for a in it:
        if a == "--listen": listen = next(it)
        elif a == "--peer": addrs.append(next(it))
        else: sys.exit(f"unknown arg: {a}")
    store = Store(db)                    # daemon full-loads: residency is its job
    node = Node(ROOT); load(node, store); flushed = set(node.durable)
    if not local_signer_secret.current(node):        # a stable identity to sign hellos with
        local_signer_secret.keygen(node, int(time.time()))
    for a in addrs:                                  # --peer flags: author a dial request each
        if a.encode() not in request.dials(node): request.connect(node, a.encode(), int(time.time()))
    node.run(); flush(node, store, flushed)
    sk, pk = local_signer_secret.current(node)
    sp = db + ".sock"
    if os.path.exists(sp): os.unlink(sp)
    usock = socket.socket(socket.AF_UNIX); usock.bind(sp); usock.listen(8)
    tsock = None
    if listen:
        h, pt = listen.rsplit(":", 1)
        tsock = socket.create_server((h, int(pt))); tsock.setblocking(False)
    my_addr = ("%s:%s" % tsock.getsockname()[:2]).encode() if tsock else b""
    hi = hello.greeting(sk, pk, my_addr, int(time.time()))   # our signed handshake, sent on every connect
    peers = []
    for sg in (signal.SIGINT, signal.SIGTERM): signal.signal(sg, lambda *a: sys.exit(0))
    print("listening:", "%s:%s" % tsock.getsockname()[:2] if tsock else sp, flush=True)
    work = True
    try:
        while True:
            want = {a.decode() for a in request.dials(node)}   # dial set from valid request facts
            for a in want - {p["addr"] for p in peers if p["addr"]}: peers.append(peer(None, a))
            for p in list(peers):                    # a closed request: forget the link, stop dialing
                if p["addr"] and p["addr"] not in want:
                    if p["s"]: p["s"].close()
                    peers.remove(p)
            for p in peers:                          # bring up outbound links; greet the moment one is up
                if p["addr"] and not p["s"] and time.monotonic() >= p["down"]:
                    connect(p)
                    if p["s"]: ship(p, [hi])
            live = [p for p in peers if p["s"]]
            rd = [usock] + ([tsock] if tsock else []) + [p["s"] for p in live]
            wr = [p["s"] for p in live if p["out"]]
            r, w, _ = select.select(rd, wr, [], 0 if work else 0.05)  # idle turn: brief sleep
            work = False
            # HOST IN — clients, new inbound peers, peer bytes.
            for s in r:
                if s is usock: serve(node, s.accept()[0], store, flushed); work = True
                elif s is tsock:
                    try:
                        c = s.accept()[0]; c.setblocking(False)
                        np = peer(c, None); ship(np, [hi]); peers.append(np)
                    except OSError: pass
                else:
                    p = next(p for p in live if p["s"] is s)
                    try: c = s.recv(65536)
                    except OSError: c = b""
                    if c: p["inb"] += c; work = True
                    else: drop(p, peers)
            hellos = []
            for p in list(peers):                    # admit peer frames; answer compares, note hellos
                if not p["s"]: continue
                for fid, tag in intake(node, p):
                    if tag == sync.TAG: ship(p, sync.respond(node, fid)); work = True
                    elif tag == hello.TAG: hellos.append(fid)
                if p["pend"]: work = True            # a bundle still draining: don't idle-sleep on it
            for hid in hellos:                       # record each verified peer as a live connection
                conn.observe(node, *hello.claim(node, hid), int(time.time())); work = True
            if not node.frontier and any(p["s"] for p in peers):
                mf = sync.myfp(node)                 # quiescent: only now is our leaf set settled
                for p in peers:                      # open a round on connect / on leaf-fp change
                    if p["s"] and p["fp"] != mf:     # deferring while draining kills the catch-up storm:
                        ship(p, sync.initiate(node)); p["fp"], work = mf, True  # a peer re-inits once, not per turn
            # ENGINE DRAIN — bounded; leftover frontier is next turn's work.
            node.turn(BOUND); work |= bool(node.frontier)
            # HOST OUT — flush new durables, drain per-peer outboxes (select-gated).
            flush(node, store, flushed)
            for p in list(peers):
                if p["s"] and p["out"] and p["s"] in w:
                    try: k = p["s"].send(p["out"]); p["out"] = p["out"][k:]; work |= k > 0
                    except OSError: drop(p, peers)
    finally:
        usock.close(); os.unlink(sp)
        for p in peers:
            if p["s"]: p["s"].close()

if __name__ == "__main__":
    main(*sys.argv[1:])
