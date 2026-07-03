"""facts/auth/workspace.py — the authority root. Self-valid (no requires);
everything else Requires its `workspace` offer. A fact cannot embed its own
id, so the offer targets SELF, which materializes to the workspace id on the
derived row — consumers Require b"workspace" at Exact(workspace_id)."""
from kernel import Atom, OFFER, Out, SELF, encode, fact, now, ts_atom
from facts.store import hydrate

TAG = b"auth.workspace"

# SHAPE — the canonical atom set; the only place atoms are chosen.
def workspace(name, t):
    return fact(TAG, ts_atom(t, b"auth"),
                Atom(OFFER, b"workspace", b"auth", SELF, name))

# EXTRACT — content-pure: (durable, shareable).
def extract(f): return True, True

# PROJECT — the only place this family's meaning lives.
def project(f, ctx, sl):
    return Out(offers=tuple(a for a in f.atoms if a.role == b"workspace"))

# COMMANDS — build a fact, admit it, stop.
def create(node, name, t):
    return node.admit(encode(workspace(name, t)))

# QUERIES — observations over validated state only, ordered by (ts, owner).
def index(node):
    hydrate.demand(node, b"workspace", b"auth"); node.run()
    return [(o, a.value) for o, t, a in sorted(node.watched(b"workspace", b"auth"),
                                               key=lambda r: (r[1], r[0]))]

# CLI — string boundary over COMMANDS/QUERIES.
CLI = {"create": lambda n, name, t=None: create(n, name.encode(), int(t or now())).hex(),
       "index": lambda n: "\n".join(f"{o.hex()} {v.decode()}" for o, v in index(n))}
