"""Sync family tests: the negentropy algorithm in-process (two Nodes reconciled
over a simulated single-type wire) plus one black-box bidirectional daemon run.
Mirrors the poc-12 proof quantifiers — shuffled admission orders converge to
bit-identical derived state; a one-fact diff ships exactly that fact's closure."""
import os, random, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import crypto as _c
from kernel import Node, decode, encode, fact_id
from facts import ROOT
from facts.sync import compare as sync
from facts.auth.workspace import workspace
from facts.auth.invite_accepted import invite_accepted
from facts.auth.signature import signature
from facts.content.message import message, feed
from facts.content.message_deletion import deletion

RK, RPK = _c.ed25519_keygen(bytes(32))                  # a fixed workspace root key
WS = workspace(b"acme", RPK, 1); WID = fact_id(WS)
# WS is Valid only with a root self-signature (shareable) AND local acceptance
# (local-only). The signature rides sync in the closure; acceptance is authored
# out-of-band on each node (the invite link), exactly as the real model requires.
WS_SIG = signature(b"auth", RPK, WID, _c.ed25519_sign(RK, WID), 1)
_ACCEPT = invite_accepted(WID, bytes(32), bytes(32), b"", RPK, 1)

def node(*facts):
    n = Node(ROOT)
    n.admit(encode(_ACCEPT))                          # this node accepted the workspace
    for f in facts: n.admit(encode(f))
    n.run(); return n

def reconcile(a, b, maxr=1000):
    """Drive a full round-trip between two nodes over the daemon's exact wire
    discipline: each side opens a round on leaf-fp change, each answers an
    admitted peer compare. Returns the count of compare frames that crossed."""
    pend, fp, rounds = {a: [], b: []}, {a: None, b: None}, 0
    def half(me, other):
        nonlocal rounds
        mf = sync.myfp(me); opened = fp[me] != mf
        if opened: pend[other] += sync.initiate(me); fp[me] = mf
        box, pend[me] = pend[me], []
        for fb in box:
            new = fact_id(decode(fb)) not in me.facts
            fid = me.admit(fb)
            if fid and new and me.facts[fid].type_tag == sync.TAG:
                rounds += 1; pend[other] += sync.respond(me, fid)
        me.run()
        return opened or bool(box)
    while (half(a, b) | half(b, a)) and rounds < maxr: pass
    return rounds

# --- The algorithm, in-process --------------------------------------------------
def test_equal_sets_zero_ships():
    a, b = node(WS, WS_SIG), node(WS, WS_SIG)
    before = set(b.durable)
    reconcile(a, b)
    assert set(b.durable) == before               # nothing to send
    assert sync.leaves(a) == sync.leaves(b)

def test_one_fact_diff_ships_exactly_that_closure():
    msgs = [message(WID, b"g", b"al", b"m%d" % i, i + 2) for i in range(20)]
    a, b = node(WS, WS_SIG, *msgs), node(WS, WS_SIG, *msgs[:-1])   # b lacks the last message; deps present
    before, missing = set(b.durable), fact_id(msgs[-1])
    reconcile(a, b)
    assert set(b.durable) - before == {missing}    # exactly the one missing leaf
    assert sync.leaves(a) == sync.leaves(b)

def test_fresh_peer_gets_dependency_closure():
    a, b = node(WS, WS_SIG, message(WID, b"g", b"al", b"hi", 2)), node()
    reconcile(a, b)
    assert set(a.durable) == set(b.durable)        # workspace rode along as the message's closure
    assert feed(b, WID, b"g") == [b"hi"]

def test_tombstone_travels_and_suppresses():
    m = message(WID, b"g", b"al", b"doomed", 2)
    a, b = node(WS, WS_SIG, m, deletion(WID, fact_id(m), 3)), node()
    reconcile(a, b)
    assert b.memo[fact_id(m)] == "Suppressed"      # arrived already dead: no resurrection window
    assert feed(b, WID, b"g") == []
    assert sync.leaves(a) == sync.leaves(b)         # the suppressed leaf still reconciles

def test_sync_facts_volatile_and_excluded():
    a, b = node(WS, WS_SIG, message(WID, b"g", b"al", b"hi", 2)), node()
    reconcile(a, b)
    for n in (a, b):
        syn = [fid for fid, f in n.facts.items() if f.type_tag == sync.TAG]
        assert syn                                  # compare frames were admitted as facts
        assert not any(fid in n.durable for fid in syn)                   # volatile: never flushed
        assert not any(fid in {k[1] for k in sync.leaves(n)} for fid in syn)  # excluded from leaves

def test_shuffled_orders_converge():
    msgs = [message(WID, b"g", b"al", b"m%d" % i, i + 2) for i in range(10)]
    facts = [WS, WS_SIG] + msgs + [deletion(WID, fact_id(msgs[3]), 100)]
    outs = []
    for seed in range(3):
        order = facts[:]; random.Random(seed).shuffle(order)
        a, b = node(*order), node()
        reconcile(a, b)
        outs.append(b.derived())
    assert outs[0] == outs[1] == outs[2]            # order-independent derived state

def test_reply_offers_stand_until_sent_receipt():
    from facts.sync import reply as sreply
    from facts.outbox import sent
    a, b = node(WS, WS_SIG, message(WID, b"g", b"al", b"hi", 2)), node(WS, WS_SIG)
    cid = b.admit(sync.initiate(a)[0]); b.run()      # a's root compare lands on b
    rid = sreply.answer(b, cid, b"dest", 5); b.run() # b's answer: offers at the outbox keys
    rows = [a for _, _, a in b.watched(b"send", b"outbox") + b.watched(b"ship", b"outbox")]
    assert rows and all(r.target == (0, b"dest") for r in rows)   # staged toward the peer
    sent.report(b, rid, 6); b.run()                  # the receipt retires the queue rows
    assert not b.watched(b"send", b"outbox") and not b.watched(b"ship", b"outbox")

def test_round_count_one_fact_in_hundred():
    msgs = [message(WID, b"g", b"al", b"m%d" % i, i + 2) for i in range(100)]
    a, b = node(WS, WS_SIG, *msgs), node(WS, WS_SIG, *msgs[:-1])
    rounds = reconcile(a, b)
    assert sync.leaves(a) == sync.leaves(b)
    assert rounds <= 30                             # ~logarithmic split, not a push-all scan
    print("\ncompare frames, 1-fact diff over 100-fact set:", rounds)

if __name__ == "__main__":
    for t in (test_equal_sets_zero_ships, test_one_fact_diff_ships_exactly_that_closure,
              test_fresh_peer_gets_dependency_closure, test_tombstone_travels_and_suppresses,
              test_sync_facts_volatile_and_excluded, test_shuffled_orders_converge,
              test_reply_offers_stand_until_sent_receipt,
              test_round_count_one_fact_in_hundred):
        t(); print(f"ok  {t.__name__}")
