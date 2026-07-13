"""Engine-answered reserved needs (kernel §2.2-2.4), RBSR shape: a `summary@range`
need is answered with my fingerprint for the range plus my reconciliation claims —
either a B-way equal-count split (a fingerprint per part) or, for a small range, the
range's id list expanded to its dependency closure. `resident@id` answers whether I
hold a fact. Plus the `deps`/`closure` edge memo the summary walks. Unit-level: we
call the engine's answer methods directly, the way _step injects them into ctx."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import crypto as _c
from kernel import (Node, SUM_ROLE, RES_ROLE, RESERVED, summary_need, unframe,
                    resident_need, encode, fact_id, Atom, Exact,
                    dec_atom, enc_atom, NEED, OFFER, WATCH, REQUIRE)
from facts import ROOT
from facts.auth.workspace import workspace
from facts.auth.invite_accepted import invite_accepted
from facts.auth.signature import signature
from facts.content.message import message

RK, RPK = _c.ed25519_keygen(bytes(32))
HOUR, MIN = 3_600, 60
T0 = 1_700_000_000
HI = b"\xff" * 41                                          # above every 40-byte key: the half-open domain end
WS = workspace(b"acme", RPK, T0); WID = fact_id(WS)
WS_SIG = signature(b"auth", RPK, WID, _c.ed25519_sign(RK, WID), T0)
ACCEPT = invite_accepted(WID, bytes(32), bytes(32), b"", RPK, T0)

def node(*fs):
    n = Node(ROOT); n.admit(encode(ACCEPT))               # locally accepted the workspace (gates validity)
    for f in fs: n.admit(encode(f))
    n.run(); return n

def _role(rows, r): return [a for _, _, a in rows if a.role == r]

def test_closure_includes_self_and_spine():
    m = message(WID, b"g", b"al", b"hi", T0 + HOUR); mid = fact_id(m)
    c = node(WS, WS_SIG, m).closure(mid)
    assert mid in c and WID in c and fact_id(WS_SIG) in c  # self + its Require/suppress spine, transitively

def test_deps_structural():
    m = message(WID, b"g", b"al", b"hi", T0 + HOUR); n = node(WS, WS_SIG, m)
    assert WID in n.deps(fact_id(m))                       # a direct edge owner (asserted, not validity-gated)

def test_summary_small_range_is_one_id_list_with_closure():
    m = message(WID, b"g", b"al", b"hi", T0 + HOUR); mid = fact_id(m)
    n = node(WS, WS_SIG, m)                                # 3 shareable leaves (<= T): the whole domain is "small"
    rows = n._answer(summary_need(b"", HI))
    assert len(_role(rows, b"fp")) == 1                    # one prune-check fingerprint for the range
    cids = _role(rows, b"cids")
    assert len(cids) == 1 and not _role(rows, b"cfp")      # small: a single id list, no split
    ids = set(unframe(cids[0].value))
    assert {mid, WID, fact_id(WS_SIG)} <= ids              # leaves + below-window spine, by id, deduped

def test_summary_large_range_splits_by_equal_count():
    msgs = [message(WID, b"g", b"al", b"m%d" % i, T0 + HOUR + i * MIN) for i in range(40)]
    n = node(WS, WS_SIG, *msgs)                            # > T leaves: the domain must be split, not listed
    rows = n._answer(summary_need(b"", HI))
    claims = _role(rows, b"cfp") + _role(rows, b"cids")
    assert 1 < len(claims) <= 16                           # a B-way (<= 16) partition, not one giant blob
    rngs = sorted(a.target for a in claims)
    assert all(rngs[i][1] <= rngs[i + 1][0] for i in range(len(rngs) - 1))   # disjoint, ordered: a partition

def test_resident_present_and_absent():
    m = message(WID, b"g", b"al", b"hi", T0 + HOUR); n = node(WS, WS_SIG, m)
    assert n._answer(resident_need(fact_id(m)))            # I hold it
    assert not n._answer(resident_need(bytes(32)))         # I do not hold this one
    assert SUM_ROLE in RESERVED and RES_ROLE in RESERVED   # reserved: WATCH-only, never a gate

def test_reserved_role_must_be_a_watch_need():
    ok = Atom(NEED, SUM_ROLE, b"sync", Exact(b"x"), effect=WATCH)
    assert dec_atom(enc_atom(ok)).effect == WATCH          # a reserved WATCH need round-trips
    for bad in (Atom(NEED, SUM_ROLE, b"sync", Exact(b"x"), effect=REQUIRE),  # reserved role that would gate
                Atom(OFFER, RES_ROLE, b"sync", Exact(b"x"))):                # a NUL-role offer
        try: dec_atom(enc_atom(bad)); assert False, "reserved role accepted"
        except ValueError: pass

if __name__ == "__main__":
    for t in (test_closure_includes_self_and_spine, test_deps_structural,
              test_summary_small_range_is_one_id_list_with_closure,
              test_summary_large_range_splits_by_equal_count, test_resident_present_and_absent,
              test_reserved_role_must_be_a_watch_need):
        t(); print("ok ", t.__name__)
