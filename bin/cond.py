#!/usr/bin/env python3
"""cond — the poc-13 daemon.  Usage: cond <db> [--listen HOST:PORT] [--peer HOST:PORT ...]

Owns the db exclusively and amortizes replay: load once, then serve verbs over
a unix socket at <db>.sock (con.py proxies to it) and exchange facts with peers
over TCP. One single-threaded select loop; each iteration is the three-phase
host turn (HOST IN / ENGINE DRAIN / HOST OUT). The wire carries ONE message
type — 4-byte big-endian length + one fact's canonical bytes — so wave 2's
sync compare frames, being facts, need no second vocabulary. Backpressure
mirrors the frontier: overflow parks, never drops — bounded admits per turn,
bounded per-peer outboxes, select-gated non-blocking writes."""
import errno, os, select, signal, socket, sys, time
BIN = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [BIN, os.path.dirname(BIN)]
from kernel import Node, _rd, frame
from facts import ROOT
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

def drop(p):                             # dead peer: brief damper, then recur
    if p["s"]: p["s"].close()
    p["s"], p["down"] = None, time.monotonic() + 0.05

def pump(node, addr, p, w):              # egress: fill the outbox, select-gated send
    if not p["s"] and time.monotonic() >= p["down"]: # reconnect: recurrence = liveness
        h, pt = addr.rsplit(":", 1)
        p["s"], p["sent"], p["buf"] = socket.socket(), set(), b""
        p["s"].setblocking(False)
        if p["s"].connect_ex((h, int(pt))) not in (0, errno.EINPROGRESS): drop(p)
    if not p["s"]: return False
    for fid, fb in node.durable.items(): # seam: wave 2's sync family replaces this what-to-send scan
        if len(p["buf"]) > OUTCAP: break                 # outbox full: parks, never drops
        if fid not in p["sent"] and node.root.extract(node.facts[fid])[1]:
            p["buf"] += len(fb).to_bytes(4, "big") + fb; p["sent"].add(fid)
    if p["s"] not in w or not p["buf"]: return False
    try: n = p["s"].send(p["buf"]); p["buf"] = p["buf"][n:]; return n > 0
    except OSError: drop(p); return False

def main(db, *argv):
    listen, peers, it = None, [], iter(argv)
    for a in it:
        if a == "--listen": listen = next(it)
        elif a == "--peer": peers.append(next(it))
        else: sys.exit(f"unknown arg: {a}")
    node = Node(ROOT); load(node, db); flushed = set(node.durable)
    sp = db + ".sock"
    if os.path.exists(sp): os.unlink(sp)
    usock = socket.socket(socket.AF_UNIX); usock.bind(sp); usock.listen(8)
    tsock = None
    if listen:
        h, pt = listen.rsplit(":", 1)
        tsock = socket.create_server((h, int(pt))); tsock.setblocking(False)
    P = {a: {"s": None, "buf": b"", "sent": set(), "down": 0.0} for a in peers}
    conns = {}                           # inbound peer conn -> receive buffer
    for sg in (signal.SIGINT, signal.SIGTERM): signal.signal(sg, lambda *a: sys.exit(0))
    print("listening:", "%s:%s" % tsock.getsockname()[:2] if tsock else sp, flush=True)
    work = True
    try:
        while True:
            rd = [usock] + ([tsock] if tsock else []) + list(conns)
            wr = [p["s"] for p in P.values() if p["s"] and p["buf"]]
            r, w, _ = select.select(rd, wr, [], 0 if work else 0.05)  # idle turn: brief sleep
            work = False
            # HOST IN — accept + read clients and peer frames; admit bounded.
            for s in r:
                if s is usock: serve(node, s.accept()[0], db, flushed); work = True
                elif s is tsock:
                    try: c = s.accept()[0]; c.setblocking(False); conns[c] = b""
                    except OSError: pass
                else:
                    try: c = s.recv(65536)
                    except OSError: c = b""
                    if c: conns[s] += c
                    else: s.close(); conns.pop(s)
            for s in list(conns):        # admit up to BOUND buffered frames; the rest parks
                b, n = conns[s], 0
                while n < BOUND and len(b) >= 4 and (ln := int.from_bytes(b[:4], "big")) + 4 <= len(b):
                    node.admit(b[4:4 + ln]); b = b[4 + ln:]; n += 1
                conns[s] = b; work |= n > 0
            # ENGINE DRAIN — bounded; leftover frontier is next turn's work.
            node.turn(BOUND); work |= bool(node.frontier)
            # HOST OUT — flush new durables to the file, pump per-peer outboxes.
            flush(node, db, flushed)
            for addr, p in P.items(): work |= pump(node, addr, p, w)
    finally:
        usock.close(); os.unlink(sp)

if __name__ == "__main__":
    main(*sys.argv[1:])
