"""facts/connection/ephemeral_secret.py — one X25519 ephemeral keypair for a
single connection handshake (poc-10 tag 43). Durable and marker-free: kept so a
replayed request/connection can recompute the same handshake material, never
shared. It provides its secret keyed by its public key (the rendezvous the sealed
request and connection Gather to open envelopes) and dies with a connection.close
naming it, so severing a session purges the ephemeral that keyed it."""
from kernel import (Atom, Exact, PROVIDE, Out, SELF, SUPPRESS_IF, encode, fact,
                    now, remote_suppress, ts_atom, ts_of)
from crypto import x25519_pk

TAG = b"connection.ephemeral_secret"
SC = b"conn"

# SHAPE — the canonical atom set; the only place atoms are chosen.
def ephemeral(eph_sk, eph_pk, t):
    return fact(TAG, ts_atom(t, SC),
                remote_suppress,
                Atom(PROVIDE, b"ephsk", SC, Exact(eph_pk), eph_sk),  # keyed by its own pub
                Atom(SUPPRESS_IF, b"closed", SC, SELF))

# EXTRACT — content-pure durability. A handshake secret projects no sync marker.
def extract(f): return True

# CHECK — exact shape plus self-verification; provenance lives in SHAPE.
def check(f):
    try:
        row = next(a for a in f.atoms if a.name == b"ephsk")
        pk = x25519_pk(row.value)
        return bool(row.value) and row.target == Exact(pk) and f == ephemeral(row.value, pk, ts_of(f))
    except Exception:
        return False

# PROJECT — the only place this family's meaning lives.
def project(f, ctx):
    return Out(provides=tuple(a for a in f.atoms if a.name == b"ephsk"))

# COMMANDS — build a fact, admit it, stop; returns the fact id (the eph secret id).
def mint(node, eph_sk, eph_pk, t):
    return node.admit(encode(ephemeral(eph_sk, eph_pk, t)))

# QUERIES — none: ephemerals are read only as the Provides other families Gather.

# CLI — no verbs: ephemerals are minted by the handshake commands, not by hand.
CLI = {}
