"""Engine-answered reserved needs (kernel §2.2-2.4), RBSR shape: a `summary@range`
need is answered with my fingerprint for the range plus my reconciliation claims —
either a B-way equal-count split (a fingerprint per part) or, for a small range, the
range's id list expanded to its dependency closure. `resident@id` answers whether I
hold a fact. Plus the `deps`/`closure` edge memo the summary walks. Unit-level: we
call the engine's answer methods directly, the way _step injects them into ctx."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import crypto as _c
from kernel import (Node, RES_ROLE, RESERVED, Row, unframe,
                    resident_need, encode, fact, fact_id, Atom, Exact,
                    dec_atom, enc_atom, now_need, NEED, OFFER, WATCH, REQUIRE)
from facts.sync.index import SUM_ROLE, summary_need
from facts import ROOT
from facts.auth.workspace import workspace
from facts.auth.invite_accepted import invite_accepted
from facts.auth.signature import signature
from facts.content.message import message
from content_fixtures import flat, member_context, signed_channel, signed_message

RK, RPK = _c.ed25519_keygen(bytes(32))
HOUR, MIN = 3_600, 60
T0 = 1_700_000_000
HI = b"\xff" * 41                                          # above every 40-byte key: the half-open domain end
WS = workspace(b"acme", RPK, T0); WID = fact_id(WS)
WS_SIG = signature(b"auth", RPK, WID, _c.ed25519_sign(RK, WID), T0)
ACCEPT = invite_accepted(WID, bytes(32), bytes(32), b"", RPK, T0)
MEMBER = member_context(WID, RK, RPK, t=T0 + 1)
CHANNEL, CHANNEL_SIG = signed_channel(MEMBER, WID, b"g", T0 + 2)
CHANNEL_ID = fact_id(CHANNEL)

def node(*fs):
    n = Node(ROOT); n.admit(encode(ACCEPT))               # locally accepted the workspace (gates validity)
    for f in fs: n.admit(encode(f))
    n.run(); return n

def _role(rows, r): return [a for _, _, a in rows if a.role == r]
def msg(body, t): return signed_message(MEMBER, WID, CHANNEL_ID, body, t)

def test_closure_includes_self_and_spine():
    m, s = msg(b"hi", T0 + HOUR); mid = fact_id(m)
    c = node(WS, WS_SIG, *MEMBER.facts, CHANNEL, CHANNEL_SIG, m, s).closure(mid)
    assert {mid, fact_id(s), CHANNEL_ID, fact_id(CHANNEL_SIG), WID,
            fact_id(WS_SIG)} <= c                           # signed message -> signed channel -> authority spine

def test_deps_structural():
    m, s = msg(b"hi", T0 + HOUR)
    n = node(WS, WS_SIG, *MEMBER.facts, CHANNEL, CHANNEL_SIG, m, s)
    assert CHANNEL_ID in n.deps(fact_id(m))                # direct structural edge; workspace is transitive

def test_summary_small_range_is_one_id_list_with_closure():
    n = node(WS, WS_SIG, *MEMBER.facts, CHANNEL, CHANNEL_SIG)  # exactly T shareable leaves
    rows = n._answer(summary_need(b"", HI))
    assert len(_role(rows, b"fp")) == 1                    # one prune-check fingerprint for the range
    cids = _role(rows, b"cids")
    assert len(cids) == 1 and not _role(rows, b"cfp")      # small: a single id list, no split
    ids = set(unframe(cids[0].value))
    assert {CHANNEL_ID, fact_id(CHANNEL_SIG), WID,
            fact_id(WS_SIG)} <= ids                         # signed channel is a real closure edge

def test_summary_large_range_splits_by_equal_count():
    bundles = [msg(b"m%d" % i, T0 + HOUR + i * MIN) for i in range(40)]
    n = node(WS, WS_SIG, *MEMBER.facts, CHANNEL, CHANNEL_SIG, *flat(bundles))
    rows = n._answer(summary_need(b"", HI))
    claims = _role(rows, b"cfp") + _role(rows, b"cids")
    assert 1 < len(claims) <= 16                           # a B-way (<= 16) partition, not one giant blob
    rngs = sorted(a.target for a in claims)
    assert all(rngs[i][1] <= rngs[i + 1][0] for i in range(len(rngs) - 1))   # disjoint, ordered: a partition

def test_resident_present_and_absent():
    m, s = msg(b"hi", T0 + HOUR)
    n = node(WS, WS_SIG, *MEMBER.facts, CHANNEL, CHANNEL_SIG, m, s)
    assert n._answer(resident_need(fact_id(m)))            # I hold it
    assert not n._answer(resident_need(bytes(32)))         # I do not hold this one
    assert SUM_ROLE in RESERVED and RES_ROLE in RESERVED   # reserved: WATCH-only, never a gate

def test_every_match_path_returns_the_named_row_shape():
    """Asserted, validated, host, and reserved answers share one safe API."""
    m = message(WID, b"g", b"al", b"hi", T0 + HOUR); mid = fact_id(m)
    n = node(WS, WS_SIG, m)
    probe_offer = Atom(OFFER, b"row", b"contract", Exact(b"k"))
    probe_need = Atom(NEED, b"row", b"contract", Exact(b"k"), effect=WATCH)
    n.admit(encode(fact(b"no.such.row-offer", probe_offer)))
    n.admit(encode(fact(b"no.such.row-need", probe_need)))
    clean = n.watched(b"workspace", b"auth")[0].atom
    clean_need = Atom(NEED, clean.role, clean.scope, clean.target, effect=WATCH)
    n.turn(now=500)
    paths = {
        "asserted offers": n.offers_for(probe_need),
        "asserted needs": n.needs_for(probe_offer),
        "validated answers": n._answer(clean_need),
        "resident answers": n._answer(resident_need(mid)),
        "host signals": n._answer(now_need(0)),
        "family answers": n._answer(summary_need(b"", HI)),
    }
    assert all(paths.values())
    for name, rows in paths.items():
        assert all(type(r) is Row for r in rows), name
        assert all(isinstance(r.ts, int) and isinstance(r.atom, Atom) for r in rows), name

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
              test_every_match_path_returns_the_named_row_shape,
              test_reserved_role_must_be_a_watch_need):
        t(); print("ok ", t.__name__)
