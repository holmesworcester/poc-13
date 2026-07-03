"""High-level tests: the design's headline claims, end to end."""
import os, random, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from kernel import Node, decode, encode, fact, fact_id, ts_atom, Atom, Exact, OFFER
from facts import ROOT
from facts.chat.note import note
from facts.chat.tombstone import tombstone
from facts.outbox.intent import intent
from facts.outbox.performed import performed

CH = b"general"

def test_identity_and_admission():
    a1 = Atom(OFFER, b"msg", CH, Exact(b"feed"), b"hi")
    a2 = ts_atom(1, CH)
    # Canonical form is a function of the atom multiset: order- and dup-free.
    assert fact_id(fact(b"chat.note", a1, a2)) == fact_id(fact(b"chat.note", a2, a1, a2))
    n, b = Node(ROOT), encode(note(CH, b"hi", 1))
    fid = n.admit(b)
    assert fid and decode(b) == note(CH, b"hi", 1)
    assert n.admit(b) == fid and len(n.facts) == 1            # idempotent admission
    assert n.admit(b[:-1]) is None and n.admit(b + b"\x00") is None   # strict decode
    assert n.admit(encode(note(CH, b"other", 1)), expect=fid) is None # checked load: miss
    n.run()
    assert n.admit(encode(fact(b"no.such", ts_atom(1)))) is not None
    n.run()
    assert n.memo[fact_id(fact(b"no.such", ts_atom(1)))] == "Parked"  # unknown tag parks

def test_suppression_and_wakes():
    n = Node(ROOT)
    n1, n2 = note(CH, b"keep", 1), note(CH, b"delete me", 2)
    t2 = tombstone(CH, fact_id(n2), 3)
    n.admit(encode(t2)); n.run()                              # tombstone arrives FIRST
    for f in (n1, n2): n.admit(encode(f))
    n.run()
    assert n.memo[fact_id(n1)] == "Valid"
    assert n.memo[fact_id(n2)] == "Suppressed"                # cross-time match held
    assert [a.value for _, _, a in n.watched(b"msg", CH)] == [b"keep"]

def test_outbox_and_replay():
    n, i1 = Node(ROOT), intent(b"peer1", b"hello", 1)
    n.admit(encode(i1)); n.run()
    assert [a.value for _, _, a in n.watched(b"send", b"outbox")] == [b"hello"]
    n.admit(encode(performed(fact_id(i1), 2))); n.run()       # host reports the effect
    assert n.watched(b"send", b"outbox") == []                # watch reprojected the intent
    assert n.memo[fact_id(i1)] == "Valid"                     # watch never gated validity
    ids, states = list(n.durable), []
    for seed in range(3):                                     # shuffled admission orders
        random.Random(seed).shuffle(ids)
        states.append(n.replay(ids).derived())
    assert states[0] == states[1] == states[2] == n.derived() # replay is bit-identical

if __name__ == "__main__":
    for t in (test_identity_and_admission, test_suppression_and_wakes, test_outbox_and_replay):
        t(); print(f"ok  {t.__name__}")
    print("\nall tests passed")
