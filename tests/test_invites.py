"""Invite-chain tests: authority binding, not just a signature. The gate proves
SOME key signed a fact; these prove the signer key is the one the chain blessed.

In-process: the happy chain (founder -> invite -> member) validates; a member
signed by a RANDOM key is Invalid (a real refusal, not Parked, not Valid); the
whole chain converges to bit-identical state under every admission order. The
black-box leg (two daemons, B joins on the printed link, membership travels
both ways) lives in test_pair.py's invite-chain phase."""
import os, random, sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import ed25519 as e
from kernel import Node, encode, fact_id
from facts import ROOT
from facts.auth import user as usermod
from facts.auth.founder import founder
from facts.auth.workspace import workspace
from facts.auth.user_invite import user_invite
from facts.auth.user import user
from facts.auth.signature import signature

WS = workspace(b"acme", 1)
WID = fact_id(WS)
FSK, FPK = e.keygen()                                 # the founder's key: root of WID

def _sig(sk, pk, target, t): return signature(WID, pk, target, e.sign(sk, target), t)

def _chain(name, member_pk, member_sk):
    """Every fact in a member's authority chain, plus the id we expect Valid."""
    fo = founder(WID, FPK, 2); fid = fact_id(fo)
    isk, ipk = e.keygen()                             # the invite keypair; isk is the link secret
    inv = user_invite(WID, ipk, 3); iid = fact_id(inv)
    u = user(WID, name, member_pk, iid, 4); uid = fact_id(u)
    facts = [WS, fo, _sig(FSK, FPK, fid, 2),          # founder roots FPK
             inv, _sig(FSK, FPK, iid, 3),             # founder blesses the invite key
             u, _sig(isk, ipk, uid, 4)]               # member fact signed BY the invite key
    return facts, uid, (isk, ipk)

def _drain(facts):
    n = Node(ROOT)
    for f in facts: n.admit(encode(f))
    return n.run()

def test_happy_chain_validates():
    msk, mpk = e.keygen()
    facts, uid, _ = _chain(b"bo", mpk, msk)
    n = _drain(facts)
    assert n.memo[uid] == "Valid"
    assert usermod.roster(n, WID) == [b"bo"]

def test_random_key_is_invalid_not_parked():
    msk, mpk = e.keygen()
    facts, uid, (isk, ipk) = _chain(b"bo", mpk, msk)
    rsk, rpk = e.keygen()                             # a key the invite never blessed
    forged = user(WID, b"mallory", rpk, fact_id(facts[3]), 5); fuid = fact_id(forged)
    facts = facts[:-2] + [forged, _sig(rsk, rpk, fuid, 5)]   # same invite, wrong signer
    n = _drain(facts)
    assert n.memo[fuid] == "Invalid"                 # the signature landed (not Parked) but is not blessed
    assert usermod.roster(n, WID) == []

def test_converges_under_every_order():
    msk, mpk = e.keygen()
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
