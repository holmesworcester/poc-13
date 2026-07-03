"""facts/auth/device.py — a device (endpoint) admitted into the workspace,
bound to authority exactly as auth.user is. It offers its label and is valid
only if the key that SIGNED it equals the pk of the auth.device_invite it names
(b"device") — the joining device signs with the INVITE key from the link, and
the invite blessed that key. The device fact IS the acceptance. A distinct
family from auth.user because a device edge is its own authority statement."""
from kernel import (Atom, Exact, NEED, OFFER, Out, REQUIRE, SELF, by, encode,
                    fact, now, ts_atom)
from facts.auth import signature
from ed25519 import keygen

TAG = b"auth.device"

# SHAPE — the canonical atom set; the only place atoms are chosen.
def device(workspace_id, label, invite_id, t):
    return fact(TAG, ts_atom(t, workspace_id),
                Atom(NEED, b"device_invite", workspace_id, Exact(invite_id), effect=REQUIRE),
                Atom(NEED, b"pk", workspace_id, SELF, effect=REQUIRE),
                Atom(OFFER, b"device", workspace_id, SELF, label))

# EXTRACT — content-pure: (durable, shareable).
def extract(f): return True, True

# PROJECT — the only place this family's meaning lives.
def project(f, ctx, sl):                 # signer must equal the pk the named device_invite blessed
    blessed = {r[2].value for r in by(ctx, b"device_invite")}
    if not blessed & {r[2].value for r in by(ctx, b"pk")}: return Out("Invalid")
    return Out(offers=tuple(a for a in f.atoms if a.role == b"device"))

# COMMANDS — build a fact, admit it, stop. invite=(invite_id, invite_secret).
def enroll(node, workspace_id, label, invite, t):
    iid, secret = invite; sk, pk = keygen(secret)   # sign the device fact with the invite key
    did = node.admit(encode(device(workspace_id, label, iid, t)))
    signature.attest(node, workspace_id, sk, pk, did, t)
    return did

# QUERIES — observations over validated state only, ordered by (ts, owner).
def devices(node, workspace_id):
    return [a.value for o, t, a in sorted(node.watched(b"device", workspace_id),
                                          key=lambda r: (r[1], r[0]))]

# CLI — string boundary over COMMANDS/QUERIES. link is "invite_id:secret".
CLI = {"enroll": lambda n, wid, label, link, t=None:
           enroll(n, bytes.fromhex(wid), label.encode(),
                  (lambda i, s: (bytes.fromhex(i), bytes.fromhex(s)))(*link.split(":")),
                  int(t or now())).hex(),
       "list": lambda n, wid: b"\n".join(devices(n, bytes.fromhex(wid))).decode()}
