"""facts/connection/hello.py — the handshake a peer sends the instant a socket
comes up: a volatile fact carrying its identity public key, its advertised listen
address, a coarse time bucket, and an Ed25519 signature over H(pk ‖ addr ‖
bucket). CHECK verifies that signature at the admission gate (pure of the fact's
own bytes), so a tampered hello is an inert miss — never a bad fact.

What it proves: the sender holds the private key for `pk`, and binds that key to
the address it advertises for the signed epoch. What it does NOT prove — stdlib
has no DH or encryption, so confidentiality and forward secrecy are out of scope,
stated plainly: freshness and session identity. A captured hello can be replayed;
the bucket records the epoch the key certified but the daemon does not gate on it
(a freshness window would be a one-line receiver check). The receiver records the
key trust-on-first-use; whether it is a workspace-authorized member/device key is
a separate value-compare, done query-side in connection.connection.peers."""
from kernel import Atom, H, OFFER, Out, SELF, encode, fact, frame
from ed25519 import sign, verify

TAG = b"connection.hello"
SC = b"conn"
BUCKET = 600                             # seconds; the epoch granularity the signature commits to
_transcript = lambda pk, addr, b: H(frame(pk, addr, b.to_bytes(8, "little")))

# SHAPE — the canonical atom set; the only place atoms are chosen.
def hello(pk, addr, bucket, sig):
    return fact(TAG, Atom(OFFER, b"hpk", SC, SELF, pk),
                Atom(OFFER, b"haddr", SC, SELF, addr),
                Atom(OFFER, b"hbucket", SC, SELF, bucket.to_bytes(8, "little")),
                Atom(OFFER, b"hsig", SC, SELF, sig))

# EXTRACT — content-pure: volatile + unshareable. A handshake is session state,
# shipped explicitly by the daemon, never stored and never in anyone's leaves.
def extract(f): return False, False

# CHECK — self-verification at the gate: a pure function of the fact's own bytes,
# run once and never on replay. Falsy math is an inert miss.
def check(f):
    v = {a.role: a.value for a in f.atoms}
    pk, addr, b, sig = v.get(b"hpk"), v.get(b"haddr"), v.get(b"hbucket"), v.get(b"hsig")
    if not (pk and addr is not None and b and sig): return False
    return verify(pk, _transcript(pk, addr, int.from_bytes(b, "little")), sig)

# PROJECT — publish the peer's proven key and advertised address.
def project(f, ctx, sl):
    return Out(offers=tuple(a for a in f.atoms if a.role in (b"hpk", b"haddr")))

# COMMANDS — the daemon builds a greeting from its identity and ships the bytes;
# a hello is authored onto the wire, not into the local db (hence no admit here).
def greeting(sk, pk, addr, t):
    bucket = t // BUCKET
    return encode(hello(pk, addr, bucket, sign(sk, _transcript(pk, addr, bucket))))

# QUERIES — the (key, addr) a verified hello proved, for the daemon to record.
def claim(node, hid):
    v = {a.role: a.value for a in node.facts[hid].atoms}
    return v[b"hpk"], v[b"haddr"]

# CLI — no human surface; the daemon greets on connect.
CLI = {}
