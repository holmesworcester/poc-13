#!/usr/bin/env python3
"""con — the poc-13 CLI.  Usage: con <db> <scope.fact.verb> [args...]

The db is sqlite holding the persisted atom relation the kernel Store owns —
one row per atom, canonical bytes derived on read. A daemon owns the db
exclusively (<db>.sock); con's only job is to proxy the
verb to it: one framed request out, one framed +ok/-err reply back. With no
daemon reachable there is nobody to answer, so con refuses and names the
daemon to start — it never opens the db itself."""
import os, socket, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from kernel import _rd, frame

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
