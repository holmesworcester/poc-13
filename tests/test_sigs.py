"""Signature tests: RFC 8032 vectors, the admission gate, and the promise that
replay never re-verifies. A detached signature is checked exactly once, when
it first enters; a user parks until its signature lands (either order)."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import ed25519 as e
from kernel import Node, encode, fact, fact_id, ts_atom
from facts import ROOT
from facts.auth import signature as sigmod, user as usermod, workspace as wsmod
from facts.auth.workspace import workspace
from facts.auth.founder import founder
from facts.auth.user import user
from facts.auth.signature import signature

# RFC 8032 section 7.1 test vectors: (secret seed, public key, message, signature).
VECTORS = [
    ("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
     "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "",
     "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555"
     "fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
    ("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
     "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "72",
     "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da0"
     "85ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"),
]

def test_rfc8032_vectors():
    for sk_h, pk_h, msg_h, sig_h in VECTORS:
        sk, pk, msg, sig = (bytes.fromhex(x) for x in (sk_h, pk_h, msg_h, sig_h))
        assert e.keygen(sk) == (sk, pk)               # deterministic public key
        assert e.sign(sk, msg) == sig                 # deterministic signature
        assert e.verify(pk, msg, sig)                 # and it verifies
        assert not e.verify(pk, msg + b"!", sig)      # over the wrong message: no
        assert not e.verify(pk, msg, bytes(64))       # garbage never raises, just False

def test_roundtrip_and_bad_inputs():
    sk, pk = e.keygen()                               # fresh random identity
    sig = e.sign(sk, b"hello")
    assert e.verify(pk, b"hello", sig)
    assert not e.verify(pk, b"hell0", sig)            # wrong message
    _, pk2 = e.keygen(); assert not e.verify(pk2, b"hello", sig)   # wrong key
    for bad in (b"", b"\x00" * 32, os.urandom(63), os.urandom(65)):
        assert e.verify(pk, b"hello", bad) is False   # malformed sig: never raises

WS = workspace(b"acme", 1)
WID = fact_id(WS)
SK, PK = e.keygen(bytes.fromhex(VECTORS[0][0]))      # PK is the founder root of WS in these tests

def _founder(t):                                     # the root fact + its self-signature
    fo = founder(WID, PK, t); fid = fact_id(fo)
    return fo, signature(WID, PK, fid, e.sign(SK, fid), t)

def _member(name, t):                                # founder-path user, its id, its signature by PK
    u = user(WID, name, PK, None, t); uid = fact_id(u)
    return u, uid, signature(WID, PK, uid, e.sign(SK, uid), t)

def test_tampered_signature_is_inert_at_gate():
    n = Node(ROOT); n.admit(encode(WS)); n.run()
    _, uid, s = _member(b"al", 3)
    bad = bytearray(encode(s)); bad[-1] ^= 1          # flip one byte of the signature
    n2 = Node(ROOT)
    assert n2.admit(bytes(bad)) is None               # falsy check -> inert miss
    assert n.admit(encode(s)) is not None             # the honest one admits

def test_malformed_signature_never_crashes_the_gate():
    from kernel import Atom, OFFER, SELF
    # A signature fact whose sig atom targets SELF (no concrete id): the check
    # must return falsy, not raise reading a target it cannot use.
    junk = fact(b"auth.signature", ts_atom(3, WID),
                Atom(OFFER, b"pk", WID, SELF, PK),
                Atom(OFFER, b"sig", WID, SELF, e.sign(SK, b"whatever")))
    assert Node(ROOT).admit(encode(junk)) is None

def test_user_parks_until_signature_lands_either_order():
    u, uid, s = _member(b"al", 3)
    fo, fs = _founder(2)                               # the root that blesses PK must be present
    def rooted(node):
        for b in (encode(WS), encode(fo), encode(fs)): node.admit(b)
        node.run()
    n = Node(ROOT); rooted(n)
    n.admit(encode(u)); n.run()
    assert n.memo[uid] == "Parked"                    # Require b"pk" (its signature) unmet
    n.admit(encode(s)); n.run()
    assert n.memo[uid] == "Valid"                     # signature wakes it; signer PK == root
    m = Node(ROOT); rooted(m)                          # reverse order: signature first
    m.admit(encode(s)); m.run(); m.admit(encode(u)); m.run()
    assert m.memo[uid] == "Valid"

def test_replay_never_reverifies():
    n = Node(ROOT)
    wid = wsmod.create(n, b"acme", 1); n.run()        # workspace + founder root + its signature
    uid = usermod.join(n, wid, b"al", 3); n.run()     # founder self-joins with the rooted local key
    assert n.memo[uid] == "Valid"
    calls, orig = [], sigmod.verify
    sigmod.verify = lambda *a: (calls.append(1), orig(*a))[1]
    try:
        assert sigmod.check(n.facts[[k for k, f in n.facts.items()
                                     if f.type_tag == b"auth.signature"][0]])
        assert calls, "a live check must call verify"   # gate really runs the crypto
        calls.clear()
        m = n.replay()                                  # rebuild from the durable file
        assert calls == [], "replay must not re-verify"
        assert m.memo[uid] == "Valid"                   # yet the member is still valid
    finally:
        sigmod.verify = orig

if __name__ == "__main__":
    for t in (test_rfc8032_vectors, test_roundtrip_and_bad_inputs,
              test_tampered_signature_is_inert_at_gate,
              test_malformed_signature_never_crashes_the_gate,
              test_user_parks_until_signature_lands_either_order,
              test_replay_never_reverifies):
        t(); print(f"ok  {t.__name__}")
    print("\nall signature tests passed")
