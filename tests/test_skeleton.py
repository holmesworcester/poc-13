"""High-level tests: the design's headline claims, end to end."""
import os, random, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from kernel import (Node, Out, Router, decode, encode, fact, fact_id, ts_atom,
                    ts_of, Atom, Exact, OFFER)
import crypto as _c
from facts import ROOT
from facts.auth.workspace import workspace
from facts.auth.invite_accepted import invite_accepted
from facts.auth.signature import signature
from facts.content.message import message
from facts.content.message_deletion import deletion
from facts.outbox.send import send

RK, RPK = _c.ed25519_keygen(bytes(32))                  # a fixed workspace root key
WS = workspace(b"acme", RPK, 1)
WID, CH = fact_id(WS), b"general"
# The facts that make WS Valid: its root self-signature + a local acceptance.
WS_CHAIN = [WS, signature(b"auth", RPK, WID, _c.ed25519_sign(RK, WID), 1),
            invite_accepted(WID, bytes(32), bytes(32), b"", RPK, 1)]

def test_identity_and_admission():
    a1 = Atom(OFFER, b"msg", WID, Exact(CH), b"hi")
    a2 = ts_atom(1, WID)
    # Canonical form is a function of the atom multiset: order- and dup-free.
    assert fact_id(fact(b"content.message", a1, a2)) == fact_id(fact(b"content.message", a2, a1, a2))
    n, b = Node(ROOT), encode(message(WID, CH, b"al", b"hi", 1))
    fid = n.admit(b)
    assert fid and decode(b) == message(WID, CH, b"al", b"hi", 1)
    assert n.admit(b) == fid and len(n.facts) == 1            # idempotent admission
    assert n.admit(b[:-1]) is None and n.admit(b + b"\x00") is None   # strict decode
    assert n.admit(encode(message(WID, CH, b"al", b"other", 1)), expect=fid) is None  # checked load: miss
    n.run()
    assert n.admit(encode(fact(b"no.such", ts_atom(1)))) is not None
    n.run()
    assert n.memo[fact_id(fact(b"no.such", ts_atom(1)))] == "Parked"  # unknown tag parks

def test_requires_suppression_and_wakes():
    n = Node(ROOT)
    m1, m2 = message(WID, CH, b"al", b"keep", 2), message(WID, CH, b"al", b"delete me", 3)
    d2 = deletion(WID, fact_id(m2), 4)
    n.admit(encode(d2)); n.run()                              # deletion arrives FIRST
    for f in (m1, m2): n.admit(encode(f))
    n.run()
    assert n.memo[fact_id(m1)] == "Parked"                    # no workspace yet: Require gates
    for f in WS_CHAIN: n.admit(encode(f))                     # authority root + acceptance land
    n.run()                                                   # wakes both messages
    assert n.memo[fact_id(m1)] == "Valid"
    assert n.memo[fact_id(m2)] == "Suppressed"                # cross-time match held
    assert [a.value for _, _, a in n.watched(b"msg", WID)] == [b"keep"]

def test_admission_check_hook():
    class SigLike:                       # throwaway family: a self-check at the gate
        extract = staticmethod(lambda f: (True, True))
        project = staticmethod(lambda f, ctx, sl: Out())
        check = staticmethod(lambda f: ts_of(f) != 13)
    n = Node(Router({b"sig": Router({b"x": SigLike}, depth=1)}))
    ok, bad = encode(fact(b"sig.x", ts_atom(7))), encode(fact(b"sig.x", ts_atom(13)))
    assert n.admit(ok) is not None
    assert n.admit(bad) is None                       # falsy check: inert miss
    assert n.admit(bad, checked=True) is not None     # replay path never re-runs the check

def test_outbox_reap_and_replay():
    n = Node(ROOT)
    fid = n.admit(encode(send(b"peer1", b"hello", 1))); n.run()
    assert [a.value for _, _, a in n.watched(b"send", b"outbox")] == [b"hello"]
    assert n.memo[fid] == "Valid"                             # watch never gated validity
    n.turn(shipped=[fid]); n.run()                            # the daemon reports the flush
    assert n.watched(b"send", b"outbox") == []                # reaped: the offer is gone
    assert fid not in n.facts and fid not in n.memo           # the body left no residue
    assert not n.durable                                      # a volatile send persists nothing
    for f in WS_CHAIN + [message(WID, CH, b"al", b"hi", 5)]: n.admit(encode(f))
    n.run()
    ids, states = list(n.durable), []
    for seed in range(3):                                     # shuffled admission orders
        random.Random(seed).shuffle(ids)
        states.append(n.replay(ids).derived())
    assert states[0] == states[1] == states[2] == n.derived() # replay is bit-identical

if __name__ == "__main__":
    for t in (test_identity_and_admission, test_requires_suppression_and_wakes,
              test_admission_check_hook, test_outbox_reap_and_replay):
        t(); print(f"ok  {t.__name__}")
    print("\nall tests passed")
