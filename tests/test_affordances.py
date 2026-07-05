"""Engine-answered reserved needs (kernel §2.2-2.4): the `summary@prefix` and
`resident@id` affordances the decomposed sync families read from ctx, plus the
`deps`/`closure` edge memo they descend. Unit-level — we call the engine's answer
methods directly on a populated Node, the way _step injects them into ctx. Mirrors
test_sync's auth spine so admitted facts actually become shareable Merkle leaves.

The shape being pinned: a summary of the ROOT of a multi-leaf tree hands back
child fingerprints (descent handles), not closures; closure ids ride the summary
at the prefix that RESOLVES to a leaf. That is how a leaf and its below-window
dependency spine travel together, by id, deduped."""
import os, sys
from collections import Counter
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import crypto as _c
from kernel import (Node, SUM_ROLE, RES_ROLE, RESERVED, summary_need,
                    resident_need, encode, fact_id, ts_of)
from facts import ROOT
from facts.auth.workspace import workspace
from facts.auth.invite_accepted import invite_accepted
from facts.auth.signature import signature
from facts.content.message import message

RK, RPK = _c.ed25519_keygen(bytes(32))
HOUR, MIN = 3_600, 60
T0 = 1_700_000_000
WS = workspace(b"acme", RPK, T0); WID = fact_id(WS)
WS_SIG = signature(b"auth", RPK, WID, _c.ed25519_sign(RK, WID), T0)
ACCEPT = invite_accepted(WID, bytes(32), bytes(32), b"", RPK, T0)

def node(*fs):
    n = Node(ROOT); n.admit(encode(ACCEPT))               # locally accepted the workspace (gates validity)
    for f in fs: n.admit(encode(f))
    n.run(); return n

def _has_fids(rows):                                       # fids advertised by a summary answer (40-byte key)
    return {a.target[1][8:] for _, _, a in rows if a.role == b"has"}

def test_closure_includes_self_and_spine():
    m = message(WID, b"g", b"al", b"hi", T0 + HOUR); mid = fact_id(m)
    c = node(WS, WS_SIG, m).closure(mid)
    assert mid in c and WID in c and fact_id(WS_SIG) in c  # self + its Require/suppress spine, transitively

def test_deps_structural_and_compat_alias():
    m = message(WID, b"g", b"al", b"hi", T0 + HOUR); n = node(WS, WS_SIG, m)
    assert WID in n.deps(fact_id(m))                       # a direct edge owner (asserted, not validity-gated)
    assert n.validated_deps(fact_id(m)) == n.deps(fact_id(m))   # the compat alias the old compare still calls

def test_summary_at_root_hands_back_descent_handles():
    msgs = [message(WID, b"g", b"al", b"m%d" % i, T0 + HOUR + i * MIN) for i in range(5)]
    rows = node(WS, WS_SIG, *msgs)._answer(summary_need(b""))
    fps = [a.target[1] for _, _, a in rows if a.role == b"fp"]
    assert b"" in fps                                      # my label for the whole range
    assert any(t for t in fps)                             # child fingerprints to descend into
    assert not _has_fids(rows)                             # closures ride at resolved leaves, never the root

def test_summary_at_a_leaf_advertises_its_closure():
    m = message(WID, b"g", b"al", b"hi", T0 + HOUR); mid = fact_id(m)
    n = node(WS, WS_SIG, m)
    key = ts_of(m).to_bytes(8, "big") + mid               # the leaf's 40-byte radix key
    rows = n._answer(summary_need(key))
    adv = _has_fids(rows)
    assert {mid, WID, fact_id(WS_SIG)} <= adv             # the leaf and its below-window spine, by id
    cnt = Counter(a.target[1][8:] for _, _, a in rows if a.role == b"has")
    assert cnt[WID] == 1 and cnt[fact_id(WS_SIG)] == 1     # deduped: each closure id advertised exactly once

def test_resident_present_and_absent():
    m = message(WID, b"g", b"al", b"hi", T0 + HOUR); n = node(WS, WS_SIG, m)
    assert n._answer(resident_need(fact_id(m)))            # I hold it
    assert not n._answer(resident_need(bytes(32)))         # I do not hold this one
    assert SUM_ROLE in RESERVED and RES_ROLE in RESERVED   # reserved: WATCH-only, never a gate

if __name__ == "__main__":
    for t in (test_closure_includes_self_and_spine, test_deps_structural_and_compat_alias,
              test_summary_at_root_hands_back_descent_handles,
              test_summary_at_a_leaf_advertises_its_closure, test_resident_present_and_absent):
        t(); print("ok ", t.__name__)
