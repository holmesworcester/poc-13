"""facts/connection/ephemeral_secret.py — one X25519 ephemeral keypair for a
single connection handshake (poc-10 tag 43). Durable and marker-free: kept so a
replayed request/connection can recompute the same handshake material, never
shared. It offers its secret keyed by its public key (the rendezvous the sealed
request and connection Watch to open envelopes) and dies with a connection.close
naming it, so severing a session purges the ephemeral that keyed it."""
from kernel import (Atom, Exact, NEED, OFFER, Out, SELF, SUPPRESS, encode, fact,
                    now, ts_atom)
from crypto import x25519_pk

TAG = b"connection.ephemeral_secret"
SC = b"conn"

# SHAPE — the canonical atom set; the only place atoms are chosen.
def ephemeral(eph_sk, eph_pk, t):
    return fact(TAG, ts_atom(t, SC),
                Atom(OFFER, b"ephsk", SC, Exact(eph_pk), eph_sk),  # keyed by its own pub
                Atom(NEED, b"closed", SC, SELF, effect=SUPPRESS))

# EXTRACT — content-pure durability. A handshake secret projects no sync marker.
def extract(f): return True

# CHECK — self-verification at the gate: the secret must derive the pub it keys.
def check(f, local):                     # local-only: an ephemeral secret is minted here, never off the wire
    v = {a.role: (a.target, a.value) for a in f.atoms}
    (tgt, sk) = v.get(b"ephsk", (None, None))
    return bool(sk) and tgt == Exact(x25519_pk(sk)) and local

# PROJECT — the only place this family's meaning lives.
def project(f, ctx):
    return Out(offers=tuple(a for a in f.atoms if a.role == b"ephsk"))

# COMMANDS — build a fact, admit it, stop; returns the fact id (the eph secret id).
def mint(node, eph_sk, eph_pk, t):
    return node.admit(encode(ephemeral(eph_sk, eph_pk, t)))

# QUERIES — none: ephemerals are read only as the offers other families Watch.

# CLI — no verbs: ephemerals are minted by the handshake commands, not by hand.
CLI = {}
