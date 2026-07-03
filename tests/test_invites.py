"""Invite-chain tests: authority binding, not just a signature. The gate proves
SOME key signed a fact; these prove the signer key is the one the chain blessed.

In-process: the happy chain (founder -> invite -> member) validates; a member
signed by a RANDOM key is Invalid (a real refusal, not Parked, not Valid); the
whole chain converges to bit-identical state under every admission order. The
black-box leg (two daemons, B joins on the printed link, membership travels
both ways) lives in test_pair.py's invite-chain phase."""
import os, random, sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import crypto as e
from kernel import Node, encode, fact_id
from facts import ROOT
from facts.auth import user as usermod
from facts.auth.workspace import workspace
from facts.auth.invite_accepted import invite_accepted
from facts.auth.user_invite import user_invite
from facts.auth.user import user
from facts.auth.signature import signature

FSK, FPK = e.ed25519_keygen()                                 # the workspace root key
WS = workspace(b"acme", FPK, 1)                       # the root pk is embedded in the workspace
WID = fact_id(WS)

def _sig(sk, pk, target, t, scope=WID):
    return signature(scope, pk, target, e.ed25519_sign(sk, target), t)

def _chain(name, member_pk, member_sk):
    """Every fact in a member's authority chain, plus the id we expect Valid.
    The workspace is valid only with a root self-signature AND a local
    invite_accepted (the acceptance gate); the founder is enrolled the same way."""
    isk, ipk = e.ed25519_keygen()                             # the invite keypair; isk is the link secret
    inv = user_invite(WID, ipk, 3); iid = fact_id(inv)
    acc = invite_accepted(WID, iid, isk, b"", member_pk, 4)   # local acceptance -> workspace valid
    u = user(WID, name, member_pk, iid, 4); uid = fact_id(u)
    facts = [WS, _sig(FSK, FPK, WID, 1, scope=b"auth"),   # root signs the workspace (global scope)
             acc,                                          # this node accepted an invite to WID
             inv, _sig(FSK, FPK, iid, 3),                 # root blesses the invite key
             u, _sig(isk, ipk, uid, 4)]                   # member fact signed BY the invite key
    return facts, uid, (isk, ipk)

def _drain(facts):
    n = Node(ROOT)
    for f in facts: n.admit(encode(f))
    return n.run()

def test_happy_chain_validates():
    msk, mpk = e.ed25519_keygen()
    facts, uid, _ = _chain(b"bo", mpk, msk)
    n = _drain(facts)
    assert n.memo[uid] == "Valid"
    assert usermod.roster(n, WID) == [b"bo"]

def test_random_key_is_invalid_not_parked():
    msk, mpk = e.ed25519_keygen()
    facts, uid, (isk, ipk) = _chain(b"bo", mpk, msk)
    rsk, rpk = e.ed25519_keygen()                             # a key the invite never blessed
    forged = user(WID, b"mallory", rpk, fact_id(facts[3]), 5); fuid = fact_id(forged)
    facts = facts[:-2] + [forged, _sig(rsk, rpk, fuid, 5)]   # same invite, wrong signer
    n = _drain(facts)
    assert n.memo[fuid] == "Invalid"                 # the signature landed (not Parked) but is not blessed
    assert usermod.roster(n, WID) == []

def test_converges_under_every_order():
    msk, mpk = e.ed25519_keygen()
    facts, uid, _ = _chain(b"bo", mpk, msk)
    baseline = _drain(facts).derived()
    for _ in range(40):                               # sample admission orders; all must agree
        order = facts[:]; random.shuffle(order)
        n = _drain(order)
        assert n.memo[uid] == "Valid"
        assert n.derived() == baseline                # bit-identical derived state, order-independent

if __name__ == "__main__":
    for t in (test_happy_chain_validates, test_random_key_is_invalid_not_parked,
              test_converges_under_every_order):
        t(); print(f"ok  {t.__name__}")
    print("\nall invite-chain tests passed")
