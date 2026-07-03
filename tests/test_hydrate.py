"""Hydration tests: demand-driven replay agrees with full replay on every
resident fact; Require closure, suppression, and Watch units hold across the
cold boundary; budget is an amortization knob with no semantic residue."""
import os, random, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from kernel import (Atom, Exact, NEED, OFFER, Node, RANGE, REQUIRE, Store,
                    covers, decode, encode, fact, fact_id, ts_atom, window)
from facts import ROOT
from facts.auth.admin import admin, admins
from facts.auth.user import user
from facts.auth.workspace import workspace
from facts.content.message import feed, message
from facts.content.message_deletion import deletion
from facts.outbox.intent import intent, pending
from facts.outbox.performed import performed
from facts.store import hydrate

WS = workspace(b"acme", 1)
WID, CH = fact_id(WS), b"general"
MS = [message(WID, CH, b"al", b"m%d" % i, 10 + i) for i in range(5)]
U = user(WID, b"al", b"pk", 2)
CORPUS = [WS, U, admin(WID, fact_id(U), 3), *MS, deletion(WID, fact_id(MS[2]), 99),
          intent(b"peer", b"hello", 5), performed(fact_id(intent(b"peer", b"hello", 5)), 6)]

def store_of(fs, seed=0):
    s, fs = Store(), list(fs)
    random.Random(seed).shuffle(fs)      # file order must not matter
    for f in fs: s.add(encode(f))
    return s

def full():
    n = Node(ROOT)
    for f in CORPUS: n.admit(encode(f))
    return n.run()

def test_demand_agrees_with_full_replay():
    f = full()
    for seed in range(3):
        n = Node(ROOT, store_of(CORPUS, seed))
        assert feed(n, WID, CH) == [b"m0", b"m1", b"m3", b"m4"]     # m2 deleted, cold tombstone
        for fid in n.facts:              # every resident fact judged as full replay judged it
            if fid in f.memo: assert n.memo[fid] == f.memo[fid], fid.hex()

def test_gating_needs_pull_their_closure():
    n = Node(ROOT, store_of(CORPUS))
    got = admins(n, WID)                 # admin Requires member Requires workspace
    assert got == [fact_id(U)]
    assert fact_id(WS) in n.facts and n.memo[fact_id(U)] == "Valid"

def test_suppression_across_the_cold_boundary():
    n = Node(ROOT, store_of(CORPUS))
    feed(n, WID, CH)
    assert n.memo[fact_id(MS[2])] == "Suppressed"                   # tombstone was pulled
    assert n.memo[fact_id(MS[3])] == "Valid"

def test_watch_pulls_the_performed_unit():
    n = Node(ROOT, store_of(CORPUS))
    assert pending(n) == []              # intent hydrated WITH its performed fact
    assert n.memo[fact_id(intent(b"peer", b"hello", 5))] == "Valid" # watch never gated

def test_unrelated_facts_stay_cold():
    n = Node(ROOT, store_of(CORPUS))
    feed(n, WID, CH)
    assert all(f.type_tag != b"outbox.intent" for f in n.facts.values())

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

def test_sql_clause_mirrors_covers():
    rnd = random.Random(7)
    ks = [bytes([b]) for b in range(5)]
    def tgt():
        if rnd.random() < .5: return Exact(rnd.choice(ks))
        lo, hi = sorted((rnd.choice(ks), rnd.choice(ks)))
        return (RANGE, lo, hi)
    offers = [(i, tgt()) for i in range(40)]
    for _ in range(60):                  # pull's WHERE clause == kernel covers, always
        need = Atom(NEED, b"r", b"s", tgt(), effect=REQUIRE)
        s = Store()                      # fresh store: hot-set dedup stays out of frame
        fids = {}
        for i, ot in offers:
            f = fact(b"no.such", ts_atom(i), Atom(OFFER, b"r", b"s", ot))
            s.add(encode(f)); fids[fact_id(f)] = ot
        got = {fact_id(decode(fb)) for fb in s.pull(need)}
        want = {fid for fid, ot in fids.items() if covers(ot, need.target)}
        assert got == want, (need.target, sorted(ot for _, ot in offers))

if __name__ == "__main__":
    for t in (test_demand_agrees_with_full_replay, test_gating_needs_pull_their_closure,
              test_suppression_across_the_cold_boundary, test_watch_pulls_the_performed_unit,
              test_unrelated_facts_stay_cold, test_budget_is_amortization_only,
              test_sql_clause_mirrors_covers):
        t(); print(f"ok  {t.__name__}")
    print("\nall tests passed")
