"""facts/auth/device.py — the per-workspace binding of this node's endpoint to a
member (poc-10 endpoint_shared, name=Device). The endpoint (X25519 key in
auth.endpoint) is node-level and the SAME across every workspace; this fact is
the per-workspace statement 'that endpoint is my device here', so a node that
joins two workspaces has two device facts carrying one identical endpoint. It is
durable and marker-emitting so peers learn each other's endpoints, self-attested by the
member's own signing key (the primary device needs no separate invite), and
valid only if that signer is an enrolled member (its key is a published member
key). It publishes `endpoint_shared@auth` — the frame(endpoint, signing_pk, wid)
the sealed request opens a membership handshake against — and `endpoint_key` for
the reverse endpoint->member lookup peers() shows."""
from kernel import (Atom, Exact, PROVIDE, Out, REQUIRE, SELF, by, encode,
                    fact, frame, now, ts_atom, ts_of, unframe)
from facts.auth import endpoint, local_signer_secret, signature
from facts.store import hydrate

TAG = b"auth.device"


# SHAPE — the canonical atom set; the only place atoms are chosen. The endpoint
# and signing pk are machine-wide; workspace_id scopes the binding.
def device(workspace_id, label, endpoint_pk, signing_pk, t):
    return fact(TAG, ts_atom(t, workspace_id),
                Atom(REQUIRE, b"pk", workspace_id, SELF),            # its own signature
                Atom(REQUIRE, b"key", workspace_id, Exact(workspace_id)),  # member keys
                Atom(PROVIDE, b"device", workspace_id, SELF, label),
                Atom(PROVIDE, b"endpoint_shared", b"auth", SELF,
                     frame(endpoint_pk, signing_pk, workspace_id)),
                Atom(PROVIDE, b"endpoint_key", workspace_id, Exact(endpoint_pk), signing_pk))

# EXTRACT — content-pure durability.
def extract(f): return True
from facts.sync.index import sync_leaf

# PROJECT — the embedded signing key must have signed this fact and be an
# enrolled member's key. Canonical form is the SHAPE rebuilt: every cross-field
# constraint (scopes, the endpoint_key mirror, the frame layout) comes for free.
def project(f, ctx):
    try:
        d = next(a for a in f.atoms if a.name == b"device")
        s = next(a for a in f.atoms if a.name == b"endpoint_shared")
        epk, spk, wid = unframe(s.value)
        if f != device(wid, d.value, epk, spk, ts_of(f)): return Out("Invalid")
    except Exception:
        return Out("Invalid")
    signer, members = signature.blessed(ctx)
    if spk not in signer or spk not in set(members.values()): return Out("Invalid")
    return Out(provides=tuple(a for a in f.atoms
                            if a.name in (b"device", b"endpoint_shared", b"endpoint_key"))
                       + (sync_leaf(),))

# COMMANDS — bind this node's endpoint into the workspace, self-signed. Ensures a
# node-level endpoint exists (one per node, shared across every workspace).
def bind(node, workspace_id, label, t):
    if not endpoint.current(node): endpoint.keygen(node, t); node.run()
    _, epk = endpoint.current(node)
    sk, signing_pk = local_signer_secret.current(node)
    did = node.admit(encode(device(workspace_id, label, epk, signing_pk, t)))
    signature.attest(node, workspace_id, sk, signing_pk, did, t)
    return did

# QUERIES — observations over validated state only.
def own(node, workspace_id):             # this node's own device (endpoint_shared) id in a workspace
    e = endpoint.current(node)
    if not e: return None
    _, epk = e
    return next((o for o, _, a in node.provided(b"endpoint_shared", b"auth")
                 if unframe(a.value)[0] == epk and unframe(a.value)[2] == workspace_id), None)

def devices(node, workspace_id):
    hydrate.demand(node, b"device", workspace_id)
    return [a.value for o, t, a in sorted(node.provided(b"device", workspace_id),
                                          key=lambda r: (r[1], r[0]))]

# CLI — string boundary over COMMANDS/QUERIES.
CLI = {"bind": lambda n, wid, label, t=None:
           bind(n, bytes.fromhex(wid), label.encode(), int(t or now())).hex(),
       "list": lambda n, wid: b"\n".join(devices(n, bytes.fromhex(wid))).decode()}
