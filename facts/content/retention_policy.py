"""facts/content/retention_policy.py — the retention window for a workspace,
as an LWW slice entry: latest (ts, owner) wins by kernel rule, replacement is
free. Recording only — the purge machinery that enforces the window is a
later family (DESIGN.md, Retention and purge)."""
from kernel import Atom, Exact, NEED, OFFER, Out, REQUIRE, encode, fact, now, ts_atom
from facts.store import hydrate

TAG = b"content.retention_policy"

# SHAPE — the canonical atom set; the only place atoms are chosen.
def policy(workspace_id, ttl, t):
    return fact(TAG, ts_atom(t, workspace_id),
                Atom(NEED, b"workspace", b"auth", Exact(workspace_id), effect=REQUIRE),
                Atom(OFFER, b"retention", workspace_id, Exact(b"window"),
                     ttl.to_bytes(8, "little")))

# EXTRACT — content-pure: (durable, shareable).
def extract(f): return True, True

# PROJECT — the only place this family's meaning lives.
def project(f, ctx, sl):
    a = next(a for a in f.atoms if a.role == b"retention")
    return Out(slice_delta={("retention", a.scope): a.value})

# COMMANDS — build a fact, admit it, stop.
def set_window(node, workspace_id, ttl, t):
    return node.admit(encode(policy(workspace_id, ttl, t)))

# QUERIES — observations over validated state only (here: the LWW slice).
def window(node, workspace_id):
    hydrate.demand(node, b"retention", workspace_id); node.run()
    row = node.slices.get(("retention", workspace_id))
    return int.from_bytes(row[1], "little") if row else None

# CLI — string boundary over COMMANDS/QUERIES.
CLI = {"set": lambda n, wid, ttl, t=None:
           set_window(n, bytes.fromhex(wid), int(ttl), int(t or now())).hex(),
       "window": lambda n, wid: str(window(n, bytes.fromhex(wid)) or "")}
