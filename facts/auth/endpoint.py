"""facts/auth/endpoint.py — this node's static X25519 endpoint keypair as a
fact (poc-10 tag 128): the secret, and its public key which is the node's
endpoint id. Durable so the endpoint survives restart, but marker-free — the
static secret is the key every sealed connection request seals to and every
sealed connection response is sealed back to, so it must never leave the node.
keygen admits one and refuses a second: the endpoint is single and stable.
The Ed25519 signing pair stays in auth.local_signer_secret; auth.endpoint_shared
binds the two publicly for the workspace."""
from kernel import Atom, Exact, OFFER, Out, encode, fact, now, ts_atom
from crypto import x25519_keygen, x25519_pk
from facts.store import hydrate

TAG = b"auth.endpoint"

# SHAPE — the canonical atom set; the only place atoms are chosen.
def endpoint(esk, epk, t):
    return fact(TAG, ts_atom(t, b"local"),
                Atom(OFFER, b"esk", b"local", Exact(epk), esk),   # keyed by its own pub
                Atom(OFFER, b"endpoint", b"local", Exact(epk)))   # presence: "epk is me"

# EXTRACT — content-pure durability. The projector emits no sync marker.
def extract(f): return True

# CHECK — self-verification at the gate: the secret must derive the pub it names.
def check(f, local):                     # local-only: the endpoint secret is authored here, never off the wire
    v = {a.role: (a.target, a.value) for a in f.atoms}
    (tgt, esk) = v.get(b"esk", (None, None))
    return bool(esk) and tgt == Exact(x25519_pk(esk)) and local

# PROJECT — the only place this family's meaning lives.
def project(f, ctx):
    return Out(offers=tuple(a for a in f.atoms if a.role in (b"esk", b"endpoint")))

# COMMANDS — build a fact, admit it, stop.
def keygen(node, t):
    if current(node): return None            # single, stable endpoint: refuse a second
    esk, epk = x25519_keygen()
    return node.admit(encode(endpoint(esk, epk, t)))

# QUERIES — observations over validated state only.
def current(node):                           # (esk, epk) | None
    hydrate.demand(node, b"endpoint", b"local")
    epk = next((a.target[1] for _, _, a in node.watched(b"endpoint", b"local")), None)
    if not epk: return None
    hydrate.demand(node, b"esk", b"local")
    esk = next((a.value for _, _, a in node.watched(b"esk", b"local") if a.target[1] == epk), None)
    return (esk, epk) if esk else None

# CLI — string boundary over COMMANDS/QUERIES.
CLI = {"keygen": lambda n, t=None: (keygen(n, int(t or now())) or b"").hex(),
       "endpoint": lambda n: (current(n) or (b"", b""))[1].hex()}
