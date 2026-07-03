"""facts/auth/admin.py — an admin grant naming a user. Requires that user's
membership offer, so a grant can never outrun the membership it elevates, and
(wave-2) a detached signature over the grant fact itself — the same one-atom
seam as auth.user, reusing auth.signature with the grant's own id as target.
grant signs the fact with the local signer secret and admits both."""
from kernel import Atom, Exact, NEED, OFFER, Out, REQUIRE, SELF, encode, fact, now, ts_atom
from facts.auth import local_signer_secret, signature

TAG = b"auth.admin"

# SHAPE — the canonical atom set; the only place atoms are chosen.
def admin(workspace_id, user_id, pk, t):
    return fact(TAG, ts_atom(t, workspace_id),
                Atom(NEED, b"member", workspace_id, Exact(user_id), effect=REQUIRE),
                Atom(NEED, b"sig", workspace_id, SELF, effect=REQUIRE),
                Atom(OFFER, b"admin", workspace_id, Exact(user_id)),
                Atom(OFFER, b"grantor", workspace_id, SELF, pk))

# EXTRACT — content-pure: (durable, shareable).
def extract(f): return True, True

# PROJECT — the only place this family's meaning lives.
def project(f, ctx, sl):
    return Out(offers=tuple(a for a in f.atoms if a.role == b"admin"))

# COMMANDS — build a fact, admit it, stop.
def grant(node, workspace_id, user_id, t):
    key = local_signer_secret.current(node)
    if not key: raise RuntimeError("no local signer key: run auth.local_signer_secret.keygen first")
    sk, pk = key
    aid = node.admit(encode(admin(workspace_id, user_id, pk, t)))
    signature.attest(node, workspace_id, sk, pk, aid, t)
    return aid

# QUERIES — observations over validated state only, ordered by (ts, owner).
def admins(node, workspace_id):
    return [a.target[1] for o, t, a in sorted(node.watched(b"admin", workspace_id),
                                              key=lambda r: (r[1], r[0]))]

# CLI — string boundary over COMMANDS/QUERIES.
CLI = {"grant": lambda n, wid, uid, t=None:
           grant(n, bytes.fromhex(wid), bytes.fromhex(uid), int(t or now())).hex(),
       "admins": lambda n, wid: "\n".join(u.hex() for u in admins(n, bytes.fromhex(wid)))}
