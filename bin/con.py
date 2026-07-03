#!/usr/bin/env python3
"""con — the poc-13 CLI.  Usage: con <db> <scope.fact.verb> [args...]

The db is the dumb file: length-framed canonical fact bytes, append-only,
nothing else. Every invocation is a crash-and-replay — load, replay to
quiescence, run one verb, append whatever new durable facts appeared."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from kernel import Node, _rd, frame
from facts import ROOT

def load(node, path):
    if os.path.exists(path):
        b, i = open(path, "rb").read(), 0
        while i < len(b):
            fb, i = _rd(b, i); node.admit(fb)
    node.run()

def main(db, path, *args):
    node = Node(ROOT); load(node, db)
    *segs, verb = path.split(".")
    mod = ROOT.resolve([s.encode() for s in segs])
    if mod is None or verb not in getattr(mod, "CLI", {}):
        sys.exit(f"unknown verb: {path}")
    before = set(node.durable)
    out = mod.CLI[verb](node, *args)
    node.run()
    with open(db, "ab") as f:
        for fid, fb in node.durable.items():
            if fid not in before: f.write(frame(fb))
    if out: print(out)

if __name__ == "__main__":
    main(*sys.argv[1:])
