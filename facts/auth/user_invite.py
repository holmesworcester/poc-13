"""facts/auth/user_invite.py — a bearer authorization to join. It blesses a
fresh INVITE public key (b"invite" at its own id); the matching secret is the
invite link, carried out-of-band to the joiner. The invite is valid only if the
key that SIGNED it belongs to an authority: the founder root (b"root") or any
existing member (b"key", the rendezvous of every member's own key). So authority
delegates one hop — a member invites, and the joiner's user Requires this exact
invite by id, climbing signer -> invite -> member/root -> workspace.

Simplest honest rule (stated): any member, or the founder, may invite a user.
A single-use or admin-only variant is a later value-compare, not new machinery."""
from kernel import (Atom, Exact, NEED, OFFER, Out, REQUIRE, SELF, WATCH, by,
                    encode, fact, now, ts_atom)
from facts.auth import local_signer_secret, signature
from crypto import ed25519_keygen as keygen
from facts.store import hydrate

TAG = b"auth.user_invite"

# SHAPE — the canonical atom set; the only place atoms are chosen.
def user_invite(workspace_id, invite_pk, t):
    return fact(TAG, ts_atom(t, workspace_id),
                Atom(NEED, b"root", b"auth", Exact(workspace_id), effect=REQUIRE),
                Atom(NEED, b"pk", workspace_id, SELF, effect=REQUIRE),
                Atom(NEED, b"key", workspace_id, Exact(workspace_id), effect=WATCH),
                Atom(OFFER, b"invite", workspace_id, SELF, invite_pk))

# EXTRACT — content-pure: (durable, shareable).
def extract(f): return True, True

# PROJECT — the only place this family's meaning lives.
def project(f, ctx, sl):                 # the inviter's signer key must be root or a member key
    blessed = {r[2].value for r in by(ctx, b"root") + by(ctx, b"key")}
    if not blessed & {r[2].value for r in by(ctx, b"pk")}: return Out("Invalid")
    return Out(offers=tuple(a for a in f.atoms if a.role == b"invite"))

# COMMANDS — build a fact, admit it, stop. Returns (invite_id, invite_secret):
# print both as the link; the joiner passes them to auth.user.join.
def invite(node, workspace_id, t):
    from facts.auth import endpoint, invite_accepted
    local = local_signer_secret.current(node)
    if not local: raise RuntimeError("no local signer key: run auth.local_signer_secret.keygen first")
    sk, pk = local                                   # the inviter signs with their own authority key
    secret, invite_pk = keygen()                     # the fresh invite keypair; secret is the link
    iid = node.admit(encode(user_invite(workspace_id, invite_pk, t)))
    signature.attest(node, workspace_id, sk, pk, iid, t)
    ep = endpoint.current(node)                      # the inviter retains the bootstrap secret so it
    if ep:                                           # can authorize the joiner's sealed request
        invite_accepted.accept(node, workspace_id, iid, secret, b"", ep[1], t)
    return iid, secret

# QUERIES — observations over validated state only.
def outstanding(node, workspace_id):
    hydrate.demand(node, b"invite", workspace_id); node.run()
    return [o for o, t, a in node.watched(b"invite", workspace_id)]

# CLI — string boundary over COMMANDS/QUERIES.
CLI = {"invite": lambda n, wid, t=None:
           (lambda iid, secret: iid.hex() + ":" + secret.hex())(
               *invite(n, bytes.fromhex(wid), int(t or now()))),
       "outstanding": lambda n, wid: "\n".join(o.hex() for o in outstanding(n, bytes.fromhex(wid)))}
