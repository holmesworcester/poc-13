#!/usr/bin/env python3
"""con — the poc-13 CLI.  Usage: con <db> <scope.fact.verb> [args...]

The db is sqlite holding one dumb table — facts(fid, bytes), canonical fact
bytes and nothing else — plus a derived atom index the kernel Store owns. A
daemon owns the db exclusively (<db>.sock); con's only job is to proxy the
verb to it: one framed request out, one framed +ok/-err reply back. With no
daemon reachable there is nobody to answer, so con refuses and names the
daemon to start — it never opens the db itself."""
import os, socket, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from kernel import _rd, frame

def load(node, store):                   # full replay: own db passed the gate once
    for fb in store.all(): node.admit(fb, checked=True)
    node.run()

def flush(node, store, flushed):         # one transaction per host turn; the
    if len(flushed) == len(node.durable): return      # flushed set keeps repeats cheap
    for fid, fb in node.durable.items():
        if fid not in flushed: store.add(fb, hot=True); flushed.add(fid)
    store.commit()

def proxy(s, path, args):                # the daemon owns the db; just ask it
    s.sendall(frame(path.encode(), *(a.encode() for a in args)))
    s.shutdown(socket.SHUT_WR)
    b = b""
    while (c := s.recv(65536)): b += c
    r, _ = _rd(b, 0)
    if not r.startswith(b"+"): sys.exit(r[1:].decode())
    if len(r) > 1: print(r[1:].decode())

def main(db, path, *args):
    s = socket.socket(socket.AF_UNIX)
    try: s.connect(db + ".sock")
    except OSError: sys.exit("no daemon for %s (start: cond %s)" % (db, db))
    return proxy(s, path, args)

if __name__ == "__main__":
    main(*sys.argv[1:])
