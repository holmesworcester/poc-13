"""facts/auth/device_invite.py — a member authorizes a new device (endpoint) to
act under the workspace. Literally the same shape as auth.user_invite: it
blesses a fresh device public key, is valid only if signed by an authority key
(founder root or a member key), and the device that joins Requires this invite
by id. Kept a distinct family because names carry meaning — a device edge and a
user edge are different authority statements even when their atoms rhyme.

Simplest honest rule (stated): any member, or the founder, may invite a device."""
from kernel import (Atom, Exact, NEED, OFFER, Out, REQUIRE, SELF, WATCH, by,
                    encode, fact, now, ts_atom)
from facts.auth import local_signer_secret, signature
from crypto import ed25519_keygen as keygen
from facts.store import hydrate

TAG = b"auth.device_invite"

# SHAPE — the canonical atom set; the only place atoms are chosen.
def device_invite(workspace_id, device_pk, t):
    return fact(TAG, ts_atom(t, workspace_id),
                Atom(NEED, b"root", b"auth", Exact(workspace_id), effect=REQUIRE),
                Atom(NEED, b"pk", workspace_id, SELF, effect=REQUIRE),
                Atom(NEED, b"key", workspace_id, Exact(workspace_id), effect=WATCH),
                Atom(OFFER, b"device_invite", workspace_id, SELF, device_pk))

# EXTRACT — content-pure durability.
def extract(f): return True
from facts.sync.index import sync_leaf

# PROJECT — the only place this family's meaning lives.
def project(f, ctx):                 # the inviter's signer key must be root or a member key
    blessed = {r[2].value for r in by(ctx, b"root") + by(ctx, b"key")}
    if not blessed & {r[2].value for r in by(ctx, b"pk")}: return Out("Invalid")
    return Out(offers=tuple(a for a in f.atoms if a.role == b"device_invite") + (sync_leaf(),))

# COMMANDS — build a fact, admit it, stop. Returns (invite_id, invite_secret).
def invite(node, workspace_id, t):
    local = local_signer_secret.current(node)
    if not local: raise RuntimeError("no local signer key: run auth.local_signer_secret.keygen first")
    sk, pk = local
    secret, device_pk = keygen()
    iid = node.admit(encode(device_invite(workspace_id, device_pk, t)))
    signature.attest(node, workspace_id, sk, pk, iid, t)
    return iid, secret

# QUERIES — observations over validated state only.
def outstanding(node, workspace_id):
    hydrate.demand(node, b"device_invite", workspace_id)
    return [o for o, t, a in node.watched(b"device_invite", workspace_id)]

# CLI — string boundary over COMMANDS/QUERIES.
CLI = {"invite": lambda n, wid, t=None:
           (lambda iid, secret: iid.hex() + ":" + secret.hex())(
               *invite(n, bytes.fromhex(wid), int(t or now()))),
       "outstanding": lambda n, wid: "\n".join(o.hex() for o in outstanding(n, bytes.fromhex(wid)))}
