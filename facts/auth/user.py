"""facts/auth/user.py — workspace membership: a named user and their declared
key (bytes, unverified in wave 1). Requires the workspace's offer, so a user
that arrives first parks until its workspace does. Wave-2 signatures land as
one added Require in SHAPE: Atom(NEED, b"sig", workspace_id, SELF,
effect=REQUIRE), gating membership on a detached signature offer."""
from kernel import (Atom, Exact, NEED, OFFER, Out, REQUIRE, SELF, encode,
                    fact, now, ts_atom)

TAG = b"auth.user"

# SHAPE — the canonical atom set; the only place atoms are chosen.
def user(workspace_id, name, key, t):
    return fact(TAG, ts_atom(t, workspace_id),
                Atom(NEED, b"workspace", b"auth", Exact(workspace_id), effect=REQUIRE),
                Atom(OFFER, b"member", workspace_id, SELF, name),
                Atom(OFFER, b"key", workspace_id, SELF, key))

# EXTRACT — content-pure: (durable, shareable).
def extract(f): return True, True

# PROJECT — the only place this family's meaning lives.
def project(f, ctx, sl):
    return Out(offers=tuple(a for a in f.atoms if a.role in (b"member", b"key")))

# COMMANDS — build a fact, admit it, stop.
def join(node, workspace_id, name, key, t):
    return node.admit(encode(user(workspace_id, name, key, t)))

# QUERIES — observations over validated state only, ordered by (ts, owner).
def roster(node, workspace_id):
    return [a.value for o, t, a in sorted(node.watched(b"member", workspace_id),
                                          key=lambda r: (r[1], r[0]))]

# CLI — string boundary over COMMANDS/QUERIES.
CLI = {"join": lambda n, wid, name, key, t=None:
           join(n, bytes.fromhex(wid), name.encode(), key.encode(), int(t or now())).hex(),
       "roster": lambda n, wid: b"\n".join(roster(n, bytes.fromhex(wid))).decode()}
