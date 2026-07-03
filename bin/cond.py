#!/usr/bin/env python3
"""cond — the poc-13 daemon.  Usage: cond <db> [--listen HOST:PORT] [--peer HOST:PORT ...]

Owns the db exclusively and amortizes replay: load once, then serve verbs over
a unix socket at <db>.sock (con.py proxies to it) and reconcile facts with peers
over TCP. One single-threaded select loop; each iteration is the three-phase
host turn (HOST IN / ENGINE DRAIN / HOST OUT). The wire carries ONE message
type — 4-byte big-endian length + one fact's canonical bytes — so a sync compare
frame, being a fact, needs no second vocabulary. Every peer link is full-duplex:
egress is the sync family, not a push-everything scan. A daemon opens a round
toward each peer on connect and whenever its own leaf-fingerprint changes, and
answers an admitted peer compare with the driver's reply frames. Backpressure
mirrors the frontier: overflow parks, never drops — bounded admits per turn,
bounded per-peer outboxes, select-gated non-blocking writes."""
import errno, os, select, signal, socket, sys, time
BIN = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [BIN, os.path.dirname(BIN)]
from kernel import Node, _rd, decode, fact_id, frame
from facts import ROOT
from facts.sync import compare as sync
from con import load

BOUND = 64                               # admits per peer per turn; engine drain bound
OUTCAP = 1 << 20                         # per-peer outbox byte cap: overflow stays unsent

def flush(node, db, flushed):            # append newly-durable facts to the db file
    if len(flushed) == len(node.durable): return
    with open(db, "ab") as f:
        for fid, fb in node.durable.items():
            if fid not in flushed: f.write(frame(fb)); flushed.add(fid)

def serve(node, s, db, flushed):         # one framed verb request per connection
    try:
        s.settimeout(1); b = b""
        while (c := s.recv(65536)): b += c           # client shut down its write side
        path, i = _rd(b, 0); args = []
        while i < len(b): a, i = _rd(b, i); args.append(a.decode())
        *segs, verb = path.decode().split(".")
        out = getattr(ROOT.resolve([x.encode() for x in segs]), "CLI", {})[verb](node, *args)
        node.run(); flush(node, db, flushed)         # durable before the reply
        s.sendall(frame(b"+" + (out or "").encode()))
    except Exception as e:
        try: s.sendall(frame(b"-" + f"{type(e).__name__}: {e}".encode()))
        except OSError: pass
    s.close()

def peer(s, addr):                       # a full-duplex link; addr set only for outbound peers
    return {"s": s, "addr": addr, "out": b"", "inb": b"", "down": 0.0, "fp": None}

def connect(p):                          # outbound (re)connect: recurrence = liveness
    h, pt = p["addr"].rsplit(":", 1)
    s = socket.socket(); s.setblocking(False)
    if s.connect_ex((h, int(pt))) not in (0, errno.EINPROGRESS):
        s.close(); p["down"] = time.monotonic() + 0.05
    else: p["s"], p["fp"] = s, None

def drop(p, peers):                      # dead link: outbound damps + reconnects, inbound is forgotten
    if p["s"]: p["s"].close()
    p["s"], p["inb"] = None, b""
    if p["addr"]: p["out"], p["fp"], p["down"] = b"", None, time.monotonic() + 0.05
    else: peers.remove(p)

def enqueue(p, fb):                      # frame a fact into the outbox; overflow parks, never drops
    if len(p["out"]) <= OUTCAP: p["out"] += len(fb).to_bytes(4, "big") + fb

def intake(node, p):                     # admit up to BOUND buffered frames; the rest parks
    b, n, fresh = p["inb"], 0, []
    while n < BOUND and len(b) >= 4 and (ln := int.from_bytes(b[:4], "big")) + 4 <= len(b):
        fb, b, n = b[4:4 + ln], b[4 + ln:], n + 1
        try: new = fact_id(decode(fb)) not in node.facts
        except Exception: continue                   # strict decode: a bad frame is inert
        fid = node.admit(fb)                          # peer input goes through the normal gate
        if fid and new and node.facts[fid].type_tag == sync.TAG: fresh.append(fid)
    p["inb"] = b
    return fresh

def main(db, *argv):
    listen, addrs, it = None, [], iter(argv)
    for a in it:
        if a == "--listen": listen = next(it)
        elif a == "--peer": addrs.append(next(it))
        else: sys.exit(f"unknown arg: {a}")
    node = Node(ROOT); load(node, db); flushed = set(node.durable)
    sp = db + ".sock"
    if os.path.exists(sp): os.unlink(sp)
    usock = socket.socket(socket.AF_UNIX); usock.bind(sp); usock.listen(8)
    tsock = None
    if listen:
        h, pt = listen.rsplit(":", 1)
        tsock = socket.create_server((h, int(pt))); tsock.setblocking(False)
    peers = [peer(None, a) for a in addrs]
    for sg in (signal.SIGINT, signal.SIGTERM): signal.signal(sg, lambda *a: sys.exit(0))
    print("listening:", "%s:%s" % tsock.getsockname()[:2] if tsock else sp, flush=True)
    work = True
    try:
        while True:
            for p in peers:                          # bring up outbound links
                if p["addr"] and not p["s"] and time.monotonic() >= p["down"]: connect(p)
            live = [p for p in peers if p["s"]]
            rd = [usock] + ([tsock] if tsock else []) + [p["s"] for p in live]
            wr = [p["s"] for p in live if p["out"]]
            r, w, _ = select.select(rd, wr, [], 0 if work else 0.05)  # idle turn: brief sleep
            work = False
            # HOST IN — clients, new inbound peers, peer bytes.
            for s in r:
                if s is usock: serve(node, s.accept()[0], db, flushed); work = True
                elif s is tsock:
                    try: c = s.accept()[0]; c.setblocking(False); peers.append(peer(c, None))
                    except OSError: pass
                else:
                    p = next(p for p in live if p["s"] is s)
                    try: c = s.recv(65536)
                    except OSError: c = b""
                    if c: p["inb"] += c; work = True
                    else: drop(p, peers)
            for p in list(peers):                    # admit peer frames; answer fresh compares
                if not p["s"]: continue
                for cid in intake(node, p):
                    for fb in sync.respond(node, cid): enqueue(p, fb); work = True
            mf = sync.myfp(node) if any(p["s"] for p in peers) else None
            for p in peers:                          # open a round on connect / on leaf-fp change
                if p["s"] and p["fp"] != mf:
                    for fb in sync.initiate(node): enqueue(p, fb)
                    p["fp"], work = mf, True
            # ENGINE DRAIN — bounded; leftover frontier is next turn's work.
            node.turn(BOUND); work |= bool(node.frontier)
            # HOST OUT — flush new durables, drain per-peer outboxes (select-gated).
            flush(node, db, flushed)
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
