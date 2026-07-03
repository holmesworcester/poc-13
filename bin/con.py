#!/usr/bin/env python3
"""con — the poc-13 CLI.  Usage: con <db> <scope.fact.verb> [args...]

The db is sqlite holding one dumb table — facts(fid, bytes), canonical fact
bytes and nothing else — plus a derived atom index the kernel Store owns. If
a daemon owns the db (<db>.sock connects), the verb is proxied to it: one
framed request out, one framed +ok/-err reply back. Otherwise every
invocation is a crash-and-demand — open the db cold, run one verb, and let
hydration pull only what the verb's facts and queries ask about; flush
whatever new durable facts appeared."""
import os, socket, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from kernel import Node, Store, _rd, frame
from facts import ROOT

def load(node, store):                   # full replay: own db passed the gate once
    for fb in store.all(): node.admit(fb, checked=True)
    node.run()

def flush(node, store, flushed=None):    # one transaction per host turn; a
    if flushed is not None:              # flushed set makes repeat calls cheap
        if len(flushed) == len(node.durable): return
        new = [fb for fid, fb in node.durable.items() if fid not in flushed]
        flushed.update(node.durable)
    else: new = node.durable.values()
    for fb in new: store.add(fb, hot=True)
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
    except OSError: s = None             # no daemon: crash-and-demand below
    if s: return proxy(s, path, args)
    store = Store(db)
    node = Node(ROOT, store)
    *segs, verb = path.split(".")
    mod = ROOT.resolve([x.encode() for x in segs])
    if mod is None or verb not in getattr(mod, "CLI", {}):
        sys.exit(f"unknown verb: {path}")
    out = mod.CLI[verb](node, *args)
    node.run()
    flush(node, store)                   # add is idempotent: hydrated ≠ new
    if out: print(out)

if __name__ == "__main__":
    main(*sys.argv[1:])
