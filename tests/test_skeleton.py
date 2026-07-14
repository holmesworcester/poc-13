"""High-level tests: the design's headline claims, end to end."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from kernel import (Node, Out, Router, decode, encode, fact, fact_id, ts_atom,
                    ts_of, Atom, Exact, PROVIDE)
import crypto as _c
from facts import ROOT
from facts.store import hydrate
from harness import reboot
from facts.auth.workspace import workspace
from facts.auth.invite_accepted import invite_accepted
from facts.auth.signature import signature
from facts.content.message import message
from facts.outbox.send import send
from content_fixtures import member_context, signed_channel, signed_deletion, signed_message

RK, RPK = _c.ed25519_keygen(bytes(32))                  # a fixed workspace root key
WS = workspace(b"acme", RPK, 1)
WID = fact_id(WS)
# The facts that make WS Valid: its root self-signature + a local acceptance.
WS_CHAIN = [WS, signature(b"auth", RPK, WID, _c.ed25519_sign(RK, WID), 1),
            invite_accepted(WID, bytes(32), bytes(32), b"", RPK, 1)]
MEMBER = member_context(WID, RK, RPK, t=2)
CHANNEL, CHANNEL_SIG = signed_channel(MEMBER, WID, b"general", 3)
CH = fact_id(CHANNEL)
AUTH_CHAIN = WS_CHAIN + list(MEMBER.facts) + [CHANNEL, CHANNEL_SIG]

def test_identity_and_admission():
    a1 = Atom(PROVIDE, b"msg", WID, Exact(CH), b"hi")
    a2 = ts_atom(1, WID)
    # Canonical form is a function of the atom multiset: order- and dup-free.
    assert fact_id(fact(b"content.message", a1, a2)) == fact_id(fact(b"content.message", a2, a1, a2))
    n, b = Node(ROOT), encode(message(WID, CH, MEMBER.uid, b"hi", 1))
    fid = n.admit(b)
    assert fid and decode(b) == message(WID, CH, MEMBER.uid, b"hi", 1)
    assert n.admit(b) == fid and len(n.facts) == 1            # idempotent admission
    assert n.admit(b[:-1]) is None and n.admit(b + b"\x00") is None   # strict decode
    assert n.admit(encode(message(WID, CH, MEMBER.uid, b"other", 1)), expect=fid) is None  # checked load: miss
    n.run()
    assert n.admit(encode(fact(b"no.such", ts_atom(1)))) is not None
    n.run()
    assert n.memo[fact_id(fact(b"no.such", ts_atom(1)))] == "Parked"  # unknown tag parks

def test_requires_suppression_and_wakes():
    n = Node(ROOT)
    m1, s1 = signed_message(MEMBER, WID, CH, b"keep", 5)
    m2, s2 = signed_message(MEMBER, WID, CH, b"delete me", 6)
    d2, ds2 = signed_deletion(MEMBER, WID, fact_id(m2), 7)
    for f in (d2, ds2): n.admit(encode(f))                    # deletion arrives FIRST
    n.run()
    for f in (m1, s1, m2, s2): n.admit(encode(f))
    n.run()
    assert n.memo[fact_id(m1)] == "Parked"                    # no channel/workspace yet: Require gates
    for f in AUTH_CHAIN: n.admit(encode(f))                   # authority root + membership lands
    n.run()                                                   # wakes both messages
    assert n.memo[fact_id(m1)] == "Valid"
    assert fact_id(m2) not in n.facts                         # cross-time match held: purged whole
    assert fact_id(m2) not in n.durable
    assert [a.value for _, _, a in n.provided(b"msg", WID)] == [b"keep"]

def test_admission_check_hook():
    def _check(f):
        if ts_of(f) == 99: raise ValueError("malformed")
        return ts_of(f) != 13
    class SigLike:                       # throwaway family: an intrinsic gate
        extract = staticmethod(lambda f: True)
        project = staticmethod(lambda f, ctx: Out())
        check = staticmethod(_check)
    root = Router({b"sig": Router({b"x": SigLike}, depth=1)})
    n = Node(root)
    ok, bad = encode(fact(b"sig.x", ts_atom(7))), encode(fact(b"sig.x", ts_atom(13)))
    assert n.admit(ok) is not None
    assert n.admit(bad) is None                       # falsy check: inert miss
    assert n.admit(encode(fact(b"sig.x", ts_atom(99)))) is None  # a raised check is the same inert miss
    assert n.admit(bad, checked=True) is not None     # replay path never re-runs the check

def test_outbox_reap_and_reboot():
    n = Node(ROOT)
    fid = n.admit(encode(send(b"peer1", b"hello", 1))); n.run()
    assert [a.value for _, _, a in n.provided(b"send", b"outbox")] == [b"hello"]
    assert n.memo[fid] == "Valid"                             # Gather never gated validity
    n.turn(shipped=[fid]); n.run()                            # the daemon reports the flush
    assert n.provided(b"send", b"outbox") == []                # reaped: the Provide is gone
    assert fid not in n.facts and fid not in n.memo           # the body left no residue
    assert not n.durable                                      # a volatile send persists nothing
    m, s = signed_message(MEMBER, WID, CH, b"hi", 5)          # a message travels with its signature
    for f in AUTH_CHAIN + [m, s]: n.admit(encode(f))
    n.run()
    hydrate.demand(n)                    # the seed is itself a fact: give the original the
    states = []                          # same one, so derived() compares like for like
    for seed in range(3):                                     # shuffled db row orders
        states.append(reboot(n, seed).derived())
    assert states[0] == states[1] == states[2] == n.derived() # boot is bit-identical

if __name__ == "__main__":
    for t in (test_identity_and_admission, test_requires_suppression_and_wakes,
              test_admission_check_hook, test_outbox_reap_and_reboot):
        t(); print(f"ok  {t.__name__}")
    print("\nall tests passed")
