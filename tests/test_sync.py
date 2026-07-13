"""Decomposed dependency-aware sync: the negentropy descent expressed as three
tiny volatile families — compare (one-range fingerprint descent), have (advertise
a held id), need (pull one id) — reconciled over a manual daemon loop that mirrors
bin/cond.py's cycle (admit inbox + present shipped) and pump (deliver send/ship
offers, fire owners). No round state: convergence is fingerprint agreement,
re-checked on leaf change. Mirrors the poc-12 quantifiers — shuffled admission
orders converge to bit-identical derived state; a one-fact diff ships exactly that
fact's closure; a below-window dependency rides in as a closure id, pulled by id."""
import os, random, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import crypto as _c
from kernel import Node, decode, encode, fact_id, summary_need, unframe
from facts import ROOT
from facts.sync import compare as cmp, need as _need
from facts.sync.compare import HI
from facts.auth.workspace import workspace
from facts.auth.invite_accepted import invite_accepted
from facts.auth.signature import signature
from facts.content.message import message, feed
from facts.content.message_deletion import deletion

RK, RPK = _c.ed25519_keygen(bytes(32))                  # a fixed workspace root key
DAY, HOUR, MIN = 86_400, 3_600, 60
T0 = 1_700_000_000                                      # 2023-11-14: the workspace is founded here
WS = workspace(b"acme", RPK, T0); WID = fact_id(WS)
WS_SIG = signature(b"auth", RPK, WID, _c.ed25519_sign(RK, WID), T0)
_ACCEPT = invite_accepted(WID, bytes(32), bytes(32), b"", RPK, T0)
CID = b"\x11" * 32                                      # a fixed connection id for the in-process pair
SYNC = {cmp.TAG, _need.TAG}

def node(*facts):
    n = Node(ROOT)
    n.admit(encode(_ACCEPT))                          # this node locally accepted the workspace
    for f in facts: n.admit(encode(f))
    n.run(); return n


def reconcile(a, b, maxr=6000, lo=0):
    """Drive two nodes to convergence over the decomposed wire. Each side opens a
    bare-root compare when its leaf set changes (the daemon's leaf_ver guard),
    every send/ship offer is delivered to the peer and its owner fired, and fired
    owners are presented as `shipped` next cycle so the volatile couriers reap.
    Returns the count of wire frames (compares + haves + needs) that crossed."""
    floor = b"" if lo <= 0 else lo.to_bytes(8, "big") + b"\x00" * 32
    inbox = {a: [], b: []}; ver = {a: None, b: None}; fired = {a: [], b: []}; frames = [0]
    t = [0]
    def step(me, other):
        t[0] += 50                                              # a clock: confirm pulses reap on their
        me.turn(now=t[0], shipped=tuple(fired[me])); fired[me] = []   # next tick, as under the daemon
        got, inbox[me] = inbox[me], []
        for blob in got: me.admit(blob)                         # admit what the peer sent
        me.run()
        if me.leaf_ver != ver[me]:                              # leaf set moved: open a fresh round
            cmp.open_round(me, CID, floor); ver[me] = me.leaf_ver; me.run()
        did = False                                             # pump: deliver offers, fire owners
        for role in (b"send", b"ship"):
            for o, _, at in me.watched(role, b"outbox"):
                if role == b"send": inbox[other].append(at.value); frames[0] += 1
                else: inbox[other] += [me.durable[x] for x in unframe(at.value) if x in me.durable]
                if o not in fired[me]: fired[me].append(o)
                did = True
        return did or bool(got)
    while (step(a, b) | step(b, a)) and frames[0] < maxr: pass
    for n in (a, b):                                            # final flushes + ticks so the last
        for _ in range(2):                                      # couriers (and confirm pulses) reap
            t[0] += 50; n.turn(now=t[0], shipped=tuple(fired[n])); n.run()
    return frames[0]

def leaves(n): return {(int.from_bytes(k[:8], "big"), k[8:]) for k in n.tree.keys}  # (ts, fid) per leaf

def cidsunframe(n, lo, hi, floor):      # the fact ids a summary advertises as cids over [lo,hi) at this floor
    out = set()
    for _, _, a in n._summary_rows(summary_need(lo, hi, floor)):
        if a.role != b"cids": continue
        out.update(unframe(a.value))
    return out

# --- The algorithm, in-process --------------------------------------------------
def test_equal_sets_zero_ships():
    a, b = node(WS, WS_SIG), node(WS, WS_SIG)
    before = set(b.durable)
    reconcile(a, b)
    assert set(b.durable) == before                # nothing to send
    assert leaves(a) == leaves(b)

def test_one_fact_diff_ships_exactly_that_fact():
    msgs = [message(WID, b"g", b"al", b"m%d" % i, T0 + HOUR + i * MIN) for i in range(20)]
    a, b = node(WS, WS_SIG, *msgs), node(WS, WS_SIG, *msgs[:-1])   # b lacks the last; its deps present
    before, missing = set(b.durable), fact_id(msgs[-1])
    reconcile(a, b)
    assert set(b.durable) - before == {missing}    # exactly the one missing leaf
    assert leaves(a) == leaves(b)

def test_fresh_peer_gets_dependency_closure():
    a, b = node(WS, WS_SIG, message(WID, b"g", b"al", b"hi", T0 + HOUR)), node()
    reconcile(a, b)                                # full range (floor 0): the spine are in-range leaves of their
    assert set(a.durable) == set(b.durable)        # own, enumerated and pulled directly — no closure ride needed
    assert feed(b, WID, b"g") == [b"hi"]

def test_tombstone_travels_and_suppresses():
    m = message(WID, b"g", b"al", b"doomed", T0 + HOUR)
    a, b = node(WS, WS_SIG, m, deletion(WID, fact_id(m), T0 + HOUR + MIN)), node()
    reconcile(a, b)
    assert b.memo[fact_id(m)] == "Suppressed"      # arrived already dead: no resurrection window
    assert feed(b, WID, b"g") == []
    assert leaves(a) == leaves(b)                  # the suppressed leaf still reconciles

def test_sync_facts_volatile_and_excluded():
    a, b = node(WS, WS_SIG, message(WID, b"g", b"al", b"hi", T0 + HOUR)), node()
    reconcile(a, b)
    for n in (a, b):
        syn = [fid for fid, f in n.facts.items() if f.type_tag in SYNC]
        assert not any(fid in n.durable for fid in syn)                    # volatile: never flushed
        assert not any(fid in {k[1] for k in leaves(n)} for fid in syn)    # excluded from the leaves
    assert not any(f.type_tag in SYNC for f in a.facts.values())           # pruned/shipped couriers reaped
    assert not any(f.type_tag in SYNC for f in b.facts.values())           # no volatile residue after quiescence

def test_shuffled_orders_converge():
    msgs = [message(WID, b"g", b"al", b"m%d" % i, T0 + HOUR + i * MIN) for i in range(10)]
    facts = [WS, WS_SIG] + msgs + [deletion(WID, fact_id(msgs[3]), T0 + DAY)]
    outs = []
    for seed in range(3):
        order = facts[:]; random.Random(seed).shuffle(order)
        a, b = node(*order), node()
        reconcile(a, b)
        outs.append(b.derived())
    assert outs[0] == outs[1] == outs[2]           # order-independent derived state

def test_reconcile_is_idempotent():
    msgs = [message(WID, b"g", b"al", b"m%d" % i, T0 + HOUR + i * MIN) for i in range(10)]
    a, b = node(WS, WS_SIG, *msgs), node(WS, WS_SIG, *msgs)
    reconcile(a, b)
    before = set(b.durable)
    reconcile(a, b)                                # re-run on a converged pair
    assert set(b.durable) == before                # content-addressed: no rounds, no double-ship

def test_full_range_advertises_leaves_only_windowed_carries_the_spine():
    """The floor alone decides whether deps ride in cids — no separate flag. Over the
    SAME range, a full round (floor=b"") advertises only the in-range leaf: every dep
    is itself an in-range leaf, enumerated on its own, so repeating it is waste. A
    windowed round (floor>0) additionally carries that leaf's below-floor SHAREABLE
    spine as closure ids (the window won't enumerate it) — but never a local-only fact
    like invite_accepted, which must not travel."""
    recent = message(WID, b"g", b"al", b"recent", T0 + 30 * DAY)
    a = node(WS, WS_SIG, recent)                                 # node() also holds a local invite_accepted (_ACCEPT)
    lo = (T0 + 29 * DAY).to_bytes(8, "big") + b"\x00" * 32       # a range starting after the T0-founded spine
    rid = fact_id(recent)
    assert cidsunframe(a, lo, HI, b"") == {rid}                     # full: just the in-range leaf, no deps repeated
    assert cidsunframe(a, lo, HI, lo) == {rid, WID, fact_id(WS_SIG)}   # windowed: + shareable below-floor spine
    assert fact_id(_ACCEPT) not in cidsunframe(a, lo, HI, lo)       # local-only invite_accepted never rides

def test_windowed_in_range_facts_and_their_deps_reconcile():
    """In range: a fact at/after the window floor reconciles, and its below-floor
    dependencies ride in as closure ids attached to its leaf — the auth spine,
    founded a month before the floor, is advertised as `have`s at the recent leaf
    and pulled by id (poc-12 dep-aware sync), in one descent, not a dep-chain of
    round trips."""
    recent = message(WID, b"g", b"al", b"recent", T0 + 30 * DAY)
    a = node(WS, WS_SIG, recent)
    b = node()
    reconcile(a, b, lo=T0 + 29 * DAY)                             # window ~ the last day
    assert fact_id(recent) in set(b.durable), "the in-range fact reconciled"
    assert {WID, fact_id(WS_SIG)} <= set(b.durable), \
        "its below-floor spine deps arrived as closure ids, though founded at T0"
    assert feed(b, WID, b"g") == [b"recent"]

def test_windowed_out_of_range_content_is_not_reconciled():
    """Out of range: old content that nothing recent depends on sits below the
    floor and does not travel. A floor of 0 (no window) syncs the very same fact,
    proving the window is what withholds it."""
    stale  = message(WID, b"g", b"al", b"stale",  T0 + HOUR)
    recent = message(WID, b"g", b"al", b"recent", T0 + 30 * DAY)
    a = node(WS, WS_SIG, stale, recent)
    b = node()
    reconcile(a, b, lo=T0 + 29 * DAY)
    assert fact_id(stale) not in b.durable, "the window never shipped the stale message"
    assert feed(b, WID, b"g") == [b"recent"]
    c = node()                                                   # no window: the stale fact reconciles
    reconcile(a, c, lo=0)
    assert fact_id(stale) in c.durable and feed(c, WID, b"g") == [b"stale", b"recent"]

def test_windowed_bulk_converges_and_withholds():
    """A window carrying many facts over a shared below-floor spine: every in-range
    fact reconciles and its spine arrives via closure ids, while old content nothing
    recent depends on stays put — order-independently."""
    stale  = [message(WID, b"g", b"al", b"s%d" % i, T0 + HOUR + i * MIN) for i in range(60)]
    recent = [message(WID, b"g", b"al", b"r%d" % i, T0 + 30 * DAY + i * MIN) for i in range(40)]
    for seed in range(3):
        order = [WS, WS_SIG] + stale + recent; random.Random(seed).shuffle(order)
        a, b = node(*order), node()
        reconcile(a, b, lo=T0 + 29 * DAY)
        assert all(fact_id(m) in b.durable for m in recent), "every in-range fact reconciled"
        assert not any(fact_id(m) in b.durable for m in stale), "below-floor content withheld"
        assert {WID, fact_id(WS_SIG)} <= set(b.durable), "the shared spine rode in via closure ids"
        assert feed(b, WID, b"g") == [b"r%d" % i for i in range(40)]

def test_frame_count_is_sublinear():
    """A one-fact diff over a 100-fact set costs O(depth) wire frames, not O(n): the
    descent prunes matching prefixes by fingerprint and only the differing path (plus
    the one leaf's have/need/ship) crosses the wire — nowhere near a push-all scan."""
    msgs = [message(WID, b"g", b"al", b"m%d" % i, T0 + HOUR + i * MIN) for i in range(100)]
    a, b = node(WS, WS_SIG, *msgs), node(WS, WS_SIG, *msgs[:-1])
    before = set(b.durable)
    frames = reconcile(a, b)
    assert leaves(a) == leaves(b)
    assert set(b.durable) - before == {fact_id(msgs[-1])}   # exactly one fact shipped
    assert frames <= 100, frames                            # sublinear: prune-by-fingerprint, not push-all
    print("\nwire frames, 1-fact diff over 100-fact set:", frames)

if __name__ == "__main__":
    for t in (test_equal_sets_zero_ships, test_one_fact_diff_ships_exactly_that_fact,
              test_fresh_peer_gets_dependency_closure, test_tombstone_travels_and_suppresses,
              test_sync_facts_volatile_and_excluded, test_shuffled_orders_converge,
              test_reconcile_is_idempotent,
              test_full_range_advertises_leaves_only_windowed_carries_the_spine,
              test_windowed_in_range_facts_and_their_deps_reconcile,
              test_windowed_out_of_range_content_is_not_reconciled,
              test_windowed_bulk_converges_and_withholds, test_frame_count_is_sublinear):
        t(); print(f"ok  {t.__name__}")
