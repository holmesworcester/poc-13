"""Hydration tests: demand-driven replay agrees with full replay on every
resident fact; Require closure, suppression, and Watch units hold across the
cold boundary; budget is an amortization knob with no semantic residue."""
import os, random, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from kernel import (Atom, Exact, NEED, OFFER, Node, RANGE, REQUIRE, Store,
                    WATCH, covers, decode, encode, fact, fact_id, ts_atom, window)
from facts import ROOT
from facts.auth import admin, local_signer_secret, user, workspace
from facts.content import message, message_deletion
from facts.content.message import feed
from facts.store import hydrate

CH = b"general"

def _build():                            # the corpus is a REAL signed workspace
    n = Node(ROOT)
    local_signer_secret.keygen(n, 0)
    wid = workspace.create(n, b"acme", 1); n.run()   # founder is auto member + bootstrap admin
    uid = next(k for k, f in n.facts.items() if f.type_tag == b"auth.user")
    mids = [message.send(n, wid, CH, b"al", b"m%d" % i, 10 + i) for i in range(5)]
    message_deletion.delete(n, wid, mids[2], 99)
    return n.run(), wid, uid, mids

FULL, WID, UID, MIDS = _build()
CORPUS = list(FULL.durable.values())     # exactly what a db would hold

def store_of(bs, seed=0):
    s, bs = Store(), list(bs)
    random.Random(seed).shuffle(bs)      # file order must not matter
    for b in bs: s.add(b)
    return s

def full(): return FULL

def test_demand_agrees_with_full_replay():
    f = full()
    for seed in range(3):
        n = Node(ROOT, store_of(CORPUS, seed))
        assert feed(n, WID, CH) == [b"m0", b"m1", b"m3", b"m4"]     # m2 deleted, cold tombstone
        for fid in n.facts:              # every resident fact judged as full replay judged it
            if fid in f.memo: assert n.memo[fid] == f.memo[fid], fid.hex()

def test_gating_needs_pull_their_closure():
    n = Node(ROOT, store_of(CORPUS))
    got = admin.admins(n, WID)           # admin Requires member Requires workspace
    assert got == [UID]
    assert WID in n.facts and n.memo[UID] == "Valid"

def test_suppression_across_the_cold_boundary():
    n = Node(ROOT, store_of(CORPUS))
    feed(n, WID, CH)
    assert n.memo[MIDS[2]] == "Suppressed"                   # tombstone was pulled
    assert n.memo[MIDS[3]] == "Valid"

def test_unrelated_facts_stay_cold():
    n = Node(ROOT, store_of(CORPUS))
    feed(n, WID, CH)
    assert UID not in n.facts            # a channel feed pulls message closure, not membership

def test_budget_is_amortization_only():
    f = full()
    n = Node(ROOT, store_of(CORPUS))
    lo, got = 0, 0
    for _ in range(9):                   # page to exhaustion: cursor = last ts, inclusive;
        hydrate.demand(node=n, role=b"msg", scope=WID,               # pop-as-dedup makes
                       win=window(lo=lo, budget=2)); n.run()         # re-scan safe
        rows = n.watched(b"msg", WID)
        if len(rows) == got: break
        got, lo = len(rows), max(t for _, t, _ in rows)
    assert feed(n, WID, CH) == feed(Node(ROOT, store_of(CORPUS)), WID, CH)
    for fid in n.facts:
        if fid in f.memo: assert n.memo[fid] == f.memo[fid]

def test_sql_pull_mirrors_covers():
    """Exhaustive mirror: Store.pull == the kernel-covers reference, for every
    target-shape pair on a small alphabet and every window arm — coverage,
    ts filter, asc/desc order, budget, and blob-ts ordering across the byte
    boundary (all ts > 255, where a wrong-endian encoding would missort)."""
    ks = [bytes([b]) for b in range(4)]
    shapes = ([Exact(k) for k in ks] +
              [(RANGE, a, b) for a in ks for b in ks if a <= b])
    offers = [(250 + 7 * i, t) for i, t in enumerate(shapes)]
    for nt in shapes:
        for w in (None, (0, 2**64 - 1, 3, 0), (260, 320, 2, 1)):
            need = Atom(NEED, b"r", b"s", nt, w and window(*w),
                        effect=REQUIRE if w is None else WATCH)
            s = Store()                  # fresh store: hot-set dedup stays out of frame
            fids = {}
            for ts, ot in offers:
                f = fact(b"no.such", ts_atom(ts), Atom(OFFER, b"r", b"s", ot))
                s.add(encode(f)); fids[fact_id(f)] = (ts, ot)
            got = [fact_id(decode(fb)) for fb in s.pull(need)]
            want = sorted((ts, fid) for fid, (ts, ot) in fids.items() if covers(ot, nt))
            if w:
                lo, hi, budget, order = w
                want = sorted((r for r in want if lo <= r[0] <= hi),
                              reverse=bool(order))[:budget]
            assert got == [fid for _, fid in want], (nt, w)

if __name__ == "__main__":
    for t in (test_demand_agrees_with_full_replay, test_gating_needs_pull_their_closure,
              test_suppression_across_the_cold_boundary,
              test_unrelated_facts_stay_cold, test_budget_is_amortization_only,
              test_sql_pull_mirrors_covers):
        t(); print(f"ok  {t.__name__}")
    print("\nall tests passed")
