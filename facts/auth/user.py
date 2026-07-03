"""facts/auth/user.py — workspace membership: a named user whose declared key
is now this node's real signer public key. SHAPE carries two Requires: the
workspace's offer (a user that arrives first parks until its workspace does)
and, wave-2, a detached signature over the membership fact itself —
Atom(NEED, b"sig", workspace_id, SELF, effect=REQUIRE), gated on an
auth.signature offering b"sig" at this fact's own id. join signs the fact with
the local signer secret and admits both the user and its signature; either can
land first (out-of-order safe). With no local key, join fails loudly."""
from kernel import (Atom, Exact, NEED, OFFER, Out, REQUIRE, SELF, encode,
                    fact, now, ts_atom)
from facts.auth import local_signer_secret, signature

TAG = b"auth.user"

# SHAPE — the canonical atom set; the only place atoms are chosen.
def user(workspace_id, name, pk, t):
    return fact(TAG, ts_atom(t, workspace_id),
                Atom(NEED, b"workspace", b"auth", Exact(workspace_id), effect=REQUIRE),
                Atom(NEED, b"sig", workspace_id, SELF, effect=REQUIRE),
                Atom(OFFER, b"member", workspace_id, SELF, name),
                Atom(OFFER, b"key", workspace_id, SELF, pk))

# EXTRACT — content-pure: (durable, shareable).
def extract(f): return True, True

# PROJECT — the only place this family's meaning lives.
def project(f, ctx, sl):
    return Out(offers=tuple(a for a in f.atoms if a.role in (b"member", b"key")))

# COMMANDS — build a fact, admit it, stop.
def join(node, workspace_id, name, t):
    key = local_signer_secret.current(node)
    if not key: raise RuntimeError("no local signer key: run auth.local_signer_secret.keygen first")
    sk, pk = key
    uid = node.admit(encode(user(workspace_id, name, pk, t)))
    signature.attest(node, workspace_id, sk, pk, uid, t)
    return uid

# QUERIES — observations over validated state only, ordered by (ts, owner).
def roster(node, workspace_id):
    return [a.value for o, t, a in sorted(node.watched(b"member", workspace_id),
                                          key=lambda r: (r[1], r[0]))]

# CLI — string boundary over COMMANDS/QUERIES.
CLI = {"join": lambda n, wid, name, t=None:
           join(n, bytes.fromhex(wid), name.encode(), int(t or now())).hex(),
       "roster": lambda n, wid: b"\n".join(roster(n, bytes.fromhex(wid))).decode()}
