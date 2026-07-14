"""facts/auth/admin.py — an admin grant naming a user. Requires that user's
membership offer, so a grant can never outrun the membership it elevates, and
binds authority the same way the rest of the chain does: the grant is valid only
if the key that SIGNED it (b"pk" context) is the workspace root (b"root"). So a
random key cannot mint an admin any more than it can mint a member.

This is the BOOTSTRAP admin: workspace.create() authors one, signed by the
ephemeral root key, so the founder is admin. FOLLOW-UP (not yet built): admin
DELEGATION — an existing admin granting another — the way poc-10 does via an
`authority_fact_id` naming the granting admin. Until then, the root key is
dropped after bootstrap, so the founder's bootstrap admin is the only admin a
workspace has."""
from kernel import (Atom, Exact, NEED, OFFER, Out, REQUIRE, SELF, by, encode,
                    fact, now, ts_atom)
from facts.auth import local_signer_secret, signature
from facts.store import hydrate

TAG = b"auth.admin"

# SHAPE — the canonical atom set; the only place atoms are chosen.
def admin(workspace_id, user_id, t):
    return fact(TAG, ts_atom(t, workspace_id),
                Atom(NEED, b"member", workspace_id, Exact(user_id), effect=REQUIRE),
                Atom(NEED, b"root", b"auth", Exact(workspace_id), effect=REQUIRE),
                Atom(NEED, b"pk", workspace_id, SELF, effect=REQUIRE),
                Atom(OFFER, b"admin", workspace_id, Exact(user_id)))

# EXTRACT — content-pure: (durable, shareable).
def extract(f): return True, True
from facts.sync.index import settle      # opt in: these facts replicate (one line is the whole choice)

# PROJECT — the only place this family's meaning lives.
def project(f, ctx):                 # the granter's signer key must be the founder root
    blessed = {r[2].value for r in by(ctx, b"root")}
    if not blessed & {r[2].value for r in by(ctx, b"pk")}: return Out("Invalid")
    return Out(offers=tuple(a for a in f.atoms if a.role == b"admin"))

# COMMANDS — build a fact, admit it, stop.
def grant(node, workspace_id, user_id, t):
    local = local_signer_secret.current(node)
    if not local: raise RuntimeError("no local signer key: run auth.local_signer_secret.keygen first")
    sk, pk = local
    aid = node.admit(encode(admin(workspace_id, user_id, t)))
    signature.attest(node, workspace_id, sk, pk, aid, t)
    return aid

# QUERIES — observations over validated state only, ordered by (ts, owner).
def admins(node, workspace_id):
    hydrate.demand(node, b"admin", workspace_id)
    return [a.target[1] for o, t, a in sorted(node.watched(b"admin", workspace_id),
                                              key=lambda r: (r[1], r[0]))]

# CLI — string boundary over COMMANDS/QUERIES.
CLI = {"grant": lambda n, wid, uid, t=None:
           grant(n, bytes.fromhex(wid), bytes.fromhex(uid), int(t or now())).hex(),
       "admins": lambda n, wid: "\n".join(u.hex() for u in admins(n, bytes.fromhex(wid)))}
