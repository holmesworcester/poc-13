#!/usr/bin/env python3
"""con — the poc-13 CLI.  Usage: con <db> <scope.fact.verb> [args...]

The db is the dumb file: length-framed canonical fact bytes, append-only,
nothing else. If a daemon owns the db (<db>.sock connects), the verb is
proxied to it: one framed request out, one framed +ok/-err reply back.
Otherwise every invocation is a crash-and-demand — index the file cold, run
one verb, and let hydration pull only what the verb's facts and queries ask
about; append whatever new durable facts appeared."""
import os, socket, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from kernel import Node, Store, _rd, frame
from facts import ROOT

def load(node, path):                    # own file: already passed the gate once
    if os.path.exists(path):
        b, i = open(path, "rb").read(), 0
        while i < len(b):
            fb, i = _rd(b, i); node.admit(fb, checked=True)
    node.run()

def index(path):                         # cold index: nothing admitted yet
    s = Store()
    if os.path.exists(path):
        b, i = open(path, "rb").read(), 0
        while i < len(b):
            fb, i = _rd(b, i); s.add(fb)
    return s

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
    except OSError: s = None             # no daemon: crash-and-demand below
    if s: return proxy(s, path, args)
    store = index(db)
    node = Node(ROOT, store)
    *segs, verb = path.split(".")
    mod = ROOT.resolve([x.encode() for x in segs])
    if mod is None or verb not in getattr(mod, "CLI", {}):
        sys.exit(f"unknown verb: {path}")
    out = mod.CLI[verb](node, *args)
    node.run()
    with open(db, "ab") as f:
        for fid, fb in node.durable.items():
            if fid not in store.ids: f.write(frame(fb))   # hydrated ≠ new
    if out: print(out)

if __name__ == "__main__":
    main(*sys.argv[1:])
