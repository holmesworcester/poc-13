#!/usr/bin/env python3
"""tiny — the TinyP2P CLI.  Usage: tiny <db> <scope.fact.verb> [args...]

The db is sqlite holding the persisted atom relation the kernel Store owns —
one row per atom, canonical bytes derived on read. A daemon owns the db
exclusively (<db>.sock); tiny's only job is to proxy the
verb to it: one framed request out, one framed +ok/-err reply back. With no
daemon reachable there is nobody to answer, so tiny refuses and names the
daemon to start — it never opens the db itself. Two local affordances need no
daemon: `--commands` lists every verb, `--completion <shell>` prints a shell
completion script."""
import os, socket, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from kernel import Router, _rd, frame

def _commands(router=None, prefix=()):   # every dotted scope.fact.verb the router serves
    if router is None:
        from facts import ROOT as router
    out = []
    for seg, child in sorted(router.routes.items()):
        p = prefix + (seg.decode(),)
        if isinstance(child, Router): out += _commands(child, p)
        else: out += [".".join(p + (verb,)) for verb in sorted(getattr(child, "CLI", {}))]
    return out

def _completion(shell):
    if shell == "bash":
        return ('_tiny_complete() {\n'
                '  local cur="${COMP_WORDS[COMP_CWORD]}"\n'
                '  if [[ $COMP_CWORD -eq 2 ]]; then\n'
                '    COMPREPLY=($(compgen -W "$("${COMP_WORDS[0]}" --commands 2>/dev/null)" -- "$cur"))\n'
                '  fi\n'
                '}\n'
                'complete -F _tiny_complete tiny tiny.py\n')
    raise SystemExit("completion shell must be: bash")

def proxy(s, path, args):                # the daemon owns the db; just ask it
    s.sendall(frame(path.encode(), *(a.encode() for a in args)))
    s.shutdown(socket.SHUT_WR)
    b = b""
    while (c := s.recv(65536)): b += c
    r, _ = _rd(b, 0)
    if not r.startswith(b"+"): sys.exit(r[1:].decode())
    if len(r) > 1: print(r[1:].decode())

def main(*argv):
    if not argv:
        raise SystemExit("usage: tiny <db> <scope.fact.verb> [args...]")
    if argv[0] == "--commands":
        print("\n".join(_commands())); return
    if argv[0] == "--completion":
        if len(argv) != 2: raise SystemExit("usage: tiny --completion bash")
        print(_completion(argv[1]), end=""); return
    if len(argv) < 2:
        raise SystemExit("usage: tiny <db> <scope.fact.verb> [args...]")
    db, path, *args = argv
    s = socket.socket(socket.AF_UNIX)
    try: s.connect(db + ".sock")
    except OSError: sys.exit("no daemon for %s (start: tinyd %s)" % (db, db))
    return proxy(s, path, args)

if __name__ == "__main__":
    main(*sys.argv[1:])
