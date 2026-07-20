"""Signature tests: RFC 8032 vectors, the admission gate, and the promise that
a reboot never re-verifies: a signature is checked exactly once, when it
first enters — existence in the store is the persisted certificate, and the
re-hash on reconstruction transfers it. A user parks until its signature
lands (either order)."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import crypto as e
from harness import reboot
from kernel import Node, Atom, encode, fact, fact_id, ts_atom
from facts import ROOT
from facts.auth import signature as sigmod, user as usermod, workspace as wsmod
from facts.auth import user_invite as uimod
from facts.auth.workspace import workspace
from facts.auth.invite_accepted import invite_accepted
from facts.auth.user import user
from facts.auth.user_invite import user_invite
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
        assert e.ed25519_keygen(sk) == (sk, pk)               # deterministic public key
        assert e.ed25519_sign(sk, msg) == sig                 # deterministic signature
        assert e.ed25519_verify(pk, msg, sig)                 # and it verifies
        assert not e.ed25519_verify(pk, msg + b"!", sig)      # over the wrong message: no
        assert not e.ed25519_verify(pk, msg, bytes(64))       # garbage never raises, just False

def test_roundtrip_and_bad_inputs():
    sk, pk = e.ed25519_keygen()                               # fresh random identity
    sig = e.ed25519_sign(sk, b"hello")
    assert e.ed25519_verify(pk, b"hello", sig)
    assert not e.ed25519_verify(pk, b"hell0", sig)            # wrong message
    _, pk2 = e.ed25519_keygen(); assert not e.ed25519_verify(pk2, b"hello", sig)   # wrong key
    for bad in (b"", b"\x00" * 32, os.urandom(63), os.urandom(65)):
        assert e.ed25519_verify(pk, b"hello", bad) is False   # malformed sig: never raises

SK, PK = e.ed25519_keygen(bytes.fromhex(VECTORS[0][0]))      # PK is the workspace root in these tests
WS = workspace(b"acme", PK, 1)                        # the root pk is embedded in the workspace
WID = fact_id(WS)

def _sig(sk, pk, target, t, scope=WID):
    return signature(scope, pk, target, e.ed25519_sign(sk, target), t)

_ISK, _IPK = e.ed25519_keygen(bytes.fromhex(VECTORS[1][0]))  # a fixed invite key, so chains are reproducible

def _chain(name, t):                                 # (rooting facts, member fact, uid, member sig)
    inv = user_invite(WID, _IPK, 3); iid = fact_id(inv)
    roots = [WS, _sig(SK, PK, WID, 1, scope=b"auth"), invite_accepted(WID, iid, _ISK, b"", PK, 2),
             inv, _sig(SK, PK, iid, 3)]              # workspace + acceptance + invite chain
    u = user(WID, name, PK, iid, t); uid = fact_id(u)
    return roots, u, uid, _sig(_ISK, _IPK, uid, t)

def _member(node, name, t):                          # drain the rooting chain; return member + its sig
    roots, u, uid, s = _chain(name, t)
    for f in roots: node.admit(encode(f))
    node.run(); return u, uid, s

def test_tampered_signature_is_inert_at_gate():
    n = Node(ROOT); _, uid, s = _member(n, b"al", 4)
    atoms = [a if a.name != b"sig" else                   # corrupt the signature value itself,
             Atom(a.relationship, a.name, a.scope, a.target,       # not a byte at some position in the encoding
                  a.value[:-1] + bytes([a.value[-1] ^ 1]))
             for a in s.atoms]
    assert Node(ROOT).admit(encode(fact(s.type_tag, *atoms))) is None   # bad signature -> inert miss
    assert n.admit(encode(s)) is not None             # the honest one admits

def test_malformed_signature_never_crashes_the_gate():
    from kernel import Atom, PROVIDE, SELF
    # A signature fact whose sig atom targets SELF (no concrete id): the check
    # must return falsy, not raise reading a target it cannot use.
    junk = fact(b"auth.signature", ts_atom(3, WID),
                Atom(PROVIDE, b"pk", WID, SELF, PK),
                Atom(PROVIDE, b"sig", WID, SELF, e.ed25519_sign(SK, b"whatever")))
    assert Node(ROOT).admit(encode(junk)) is None

def test_signature_fact_cannot_smuggle_pk_for_another_target():
    from kernel import Exact, PROVIDE
    # A pk Provide is an authority claim. One fact, one verified claim: a second
    # pk atom at a foreign id must not ride the honest pair past the one check.
    ask, apk = e.ed25519_keygen(b"a" * 32)
    _, vpk = e.ed25519_keygen(b"v" * 32)
    x, y = b"x" * 32, b"y" * 32
    smuggled = fact(b"auth.signature", ts_atom(3, WID),
                    Atom(PROVIDE, b"pk", WID, Exact(x), vpk),      # the victim's key at a foreign id
                    Atom(PROVIDE, b"pk", WID, Exact(y), apk),
                    Atom(PROVIDE, b"sig", WID, Exact(y), e.ed25519_sign(ask, y)))
    assert Node(ROOT).admit(encode(smuggled)) is None            # gate: inert miss

    n = Node(ROOT)                                     # checked replay skips the gate:
    sid = n.admit(encode(smuggled), checked=True); n.run()       # the projector must also hold
    assert n.memo[sid] == "Invalid"
    assert not n.provided(b"pk", WID)

def test_tag_alias_is_not_a_signature():
    # Canonical form includes the type tag: the same honest atoms under a longer
    # tag route to this family but are a different fact id — refuse them.
    honest = _sig(SK, PK, b"y" * 32, 3)
    alias = fact(b"auth.signature.x", *honest.atoms)
    assert Node(ROOT).admit(encode(honest)) is not None
    assert Node(ROOT).admit(encode(alias)) is None

def test_content_projectors_reject_forged_authorship():
    # The signed-content wave's whole point: a projector gate binds each fact to a
    # member signature. A valid signature by a NON-member, or a member's fact
    # re-attributed to someone else, must be Invalid — not admitted on shape alone.
    from kernel import Exact
    from facts.auth import local_signer_secret
    from facts.content import (channel as channels, message, reaction,
                               message_deletion, retention_policy)
    n = Node(ROOT)
    wid = wsmod.create(n, b"acme", 1); n.run()          # founder: member + admin; #general exists
    _sk, pk = local_signer_secret.current(n)
    uid = next(k for k, f in n.facts.items() if f.type_tag == b"auth.user")
    cid = channels.resolve(n, wid, b"general")
    zsk, zpk = e.ed25519_keygen(b"z" * 32)              # a stranger: never enrolled
    def signed(f, sk, pk, t):                           # a fact + a real signature over its id by pk
        fid = fact_id(f)
        n.admit(encode(f)); n.admit(encode(signature(wid, pk, fid, e.ed25519_sign(sk, fid), t)))
        n.run(); return fid

    good = message.send(n, wid, cid, b"hi", 5); n.run()
    assert n.memo[good] == "Valid"                      # baseline: a real member message admits

    forged = signed(message.message(wid, cid, uid, b"forged", 6, bytes(32)), zsk, zpk, 6)
    assert n.memo[forged] == "Invalid"                  # author=founder but signed by a stranger key
    stranger = signed(message.message(wid, cid, b"x" * 32, b"nope", 7, bytes(32)), zsk, zpk, 7)
    assert n.memo[stranger] == "Invalid"                # stranger posting as their own non-member id

    react = signed(reaction.reaction(wid, good, uid, b":x:", 8), zsk, zpk, 8)
    assert n.memo[react] == "Invalid"                   # a reaction the reactor did not sign

    dead = signed(message_deletion.deletion(wid, good, 9), zsk, zpk, 9)
    assert n.memo[dead] == "Invalid"                    # a non-member cannot delete
    assert message.feed(n, wid, cid) == [b"hi"]         # ...and the message survives the forged deletion

    policy = signed(retention_policy.policy(wid, 1440, 10), zsk, zpk, 10)
    assert n.memo[policy] == "Invalid"                  # a non-admin (here a non-member) cannot set retention

def test_user_parks_until_signature_lands_either_order():
    n = Node(ROOT); u, uid, s = _member(n, b"al", 4)   # chain present, member's own sig withheld
    n.admit(encode(u)); n.run()
    assert n.memo[uid] == "Parked"                    # Require b"pk" (its signature) unmet
    n.admit(encode(s)); n.run()
    assert n.memo[uid] == "Valid"                     # signature wakes it; signer == the invite key
    m = Node(ROOT); _member(m, b"al", 4)               # reverse order on a fresh node: signature first
    m.admit(encode(s)); m.run(); m.admit(encode(u)); m.run()
    assert m.memo[uid] == "Valid"

def test_replay_never_reverifies():
    n = Node(ROOT)
    wid = wsmod.create(n, b"acme", 1); n.run()        # full bootstrap: workspace + first member + admin
    uid = next(k for k, f in n.facts.items() if f.type_tag == b"auth.user")
    assert n.memo[uid] == "Valid"                     # the founder's own membership
    calls, orig = [], sigmod.verify
    sigmod.verify = lambda *a: (calls.append(1), orig(*a))[1]
    try:
        assert sigmod.check(n.facts[[k for k, f in n.facts.items()
                                     if f.type_tag == b"auth.signature"][0]])
        assert calls, "a live check must call verify"   # gate really runs the crypto
        calls.clear()
        m = reboot(n)                                   # boot from the durable rows
        assert calls == [], "boot must not re-verify: existence is the certificate"
        assert m.memo[uid] == "Valid"                   # yet the member is still valid
    finally:
        sigmod.verify = orig

if __name__ == "__main__":
    for t in (test_rfc8032_vectors, test_roundtrip_and_bad_inputs,
              test_tampered_signature_is_inert_at_gate,
              test_malformed_signature_never_crashes_the_gate,
              test_signature_fact_cannot_smuggle_pk_for_another_target,
              test_tag_alias_is_not_a_signature,
              test_content_projectors_reject_forged_authorship,
              test_user_parks_until_signature_lands_either_order,
              test_replay_never_reverifies):
        t(); print(f"ok  {t.__name__}")
    print("\nall signature tests passed")
