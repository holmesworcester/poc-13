"""facts/auth/local_signer_secret.py — this node's Ed25519 key material as a
fact: the seed (which IS the secret key) and its public key. Durable so the
identity survives restart; marker-free — a private key is the
one fact that must never sync. keygen admits one and refuses a second: the
identity is single and stable. current() hands commands the (sk, pk) they
sign with; whoami prints the public key. Trusting the durable file here is a
local-integrity assumption, not a protocol one — see docs/DESIGN.md."""
from kernel import Atom, OFFER, Out, SELF, encode, fact, now, ts_atom
from crypto import ed25519_keygen as _keygen
from facts.store import hydrate

TAG = b"auth.local_signer_secret"

# SHAPE — the canonical atom set; the only place atoms are chosen.
def secret(sk, pk, t):
    return fact(TAG, ts_atom(t, b"local"),
                Atom(OFFER, b"sk", b"local", SELF, sk),
                Atom(OFFER, b"pk", b"local", SELF, pk))

# EXTRACT — content-pure durability. The projector emits no sync marker.
def extract(f): return True

# PROJECT — the only place this family's meaning lives.
def project(f, ctx):
    return Out(offers=tuple(a for a in f.atoms if a.role in (b"sk", b"pk")))

# COMMANDS — build a fact, admit it, stop.
def keygen(node, t):
    if current(node): return None            # single, stable identity: refuse a second
    sk, pk = _keygen()
    return node.admit(encode(secret(sk, pk, t)))

# QUERIES — observations over validated state only.
def current(node):
    hydrate.demand(node, b"sk", b"local"); hydrate.demand(node, b"pk", b"local")
    sk = next((a.value for _, _, a in node.watched(b"sk", b"local")), None)
    pk = next((a.value for _, _, a in node.watched(b"pk", b"local")), None)
    return (sk, pk) if sk and pk else None

# CLI — string boundary over COMMANDS/QUERIES.
CLI = {"keygen": lambda n, t=None: (keygen(n, int(t or now())) or b"").hex(),
       "whoami": lambda n: (current(n) or (b"", b""))[1].hex()}
