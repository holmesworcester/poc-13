"""Engine-answered reserved Gathers (kernel §2.2-2.4), RBSR shape: a
`summary@range` Gather is answered with my fingerprint plus reconciliation claims —
either a B-way equal-count split (a fingerprint per part) or, for a small range, the
range's id list expanded to its dependency closure. `resident@id` answers whether I
hold a fact. Plus the `deps`/`closure` edge memo the summary walks. Unit-level: we
call the engine's answer methods directly, the way _step injects them into ctx."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import crypto as _c
from kernel import (Node, ORIGIN_SCOPE, REMOTE_NAME, RES_NAME, RESERVED_NAMES,
                    Row, unframe, resident_gather, encode, fact, fact_id, Atom,
                    Exact, dec_atom, enc_atom, now_gather, PROVIDE, GATHER,
                    REQUIRE, SUPPRESS_IF, SELF)
from facts.sync.index import SUM_NAME, summary_gather
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

def _name(rows, r): return [a for _, _, a in rows if a.name == r]
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
    n = node(WS, WS_SIG, *MEMBER.facts, CHANNEL, CHANNEL_SIG)  # exactly T marker-owning leaves
    rows = n._answer(summary_gather(b"", HI))
    assert len(_name(rows, b"fp")) == 1                    # one prune-check fingerprint for the range
    cids = _name(rows, b"cids")
    assert len(cids) == 1 and not _name(rows, b"cfp")      # small: a single id list, no split
    ids = set(unframe(cids[0].value))
    assert {CHANNEL_ID, fact_id(CHANNEL_SIG), WID,
            fact_id(WS_SIG)} <= ids                         # signed channel is a real closure edge

def test_summary_large_range_splits_by_equal_count():
    bundles = [msg(b"m%d" % i, T0 + HOUR + i * MIN) for i in range(40)]
    n = node(WS, WS_SIG, *MEMBER.facts, CHANNEL, CHANNEL_SIG, *flat(bundles))
    rows = n._answer(summary_gather(b"", HI))
    claims = _name(rows, b"cfp") + _name(rows, b"cids")
    assert 1 < len(claims) <= 16                           # a B-way (<= 16) partition, not one giant blob
    rngs = sorted(a.target for a in claims)
    assert all(rngs[i][1] <= rngs[i + 1][0] for i in range(len(rngs) - 1))   # disjoint, ordered: a partition

def test_resident_present_and_absent():
    m, s = msg(b"hi", T0 + HOUR)
    n = node(WS, WS_SIG, *MEMBER.facts, CHANNEL, CHANNEL_SIG, m, s)
    assert n._answer(resident_gather(fact_id(m)))            # I hold it
    assert not n._answer(resident_gather(bytes(32)))         # I do not hold this one
    assert SUM_NAME in RESERVED_NAMES and RES_NAME in RESERVED_NAMES   # reserved names are engine/family-owned

def test_every_match_path_returns_the_named_row_shape():
    """Asserted, validated, host, and reserved answers share one safe API."""
    m = message(WID, b"g", b"al", b"hi", T0 + HOUR); mid = fact_id(m)
    n = node(WS, WS_SIG, m)
    probe_provide = Atom(PROVIDE, b"row", b"contract", Exact(b"k"))
    probe_gather = Atom(GATHER, b"row", b"contract", Exact(b"k"))
    n.admit(encode(fact(b"no.such.row-provide", probe_provide)))
    n.admit(encode(fact(b"no.such.row-gather", probe_gather)))
    clean = n.provided(b"workspace", b"auth")[0].atom
    clean_need = Atom(GATHER, clean.name, clean.scope, clean.target)
    n.turn(now=500)
    paths = {
        "asserted provides": n.provides_for(probe_gather),
        "asserted consumers": n.consumers_for(probe_provide),
        "validated answers": n._answer(clean_need),
        "resident answers": n._answer(resident_gather(mid)),
        "host signals": n._answer(now_gather(0)),
        "family answers": n._answer(summary_gather(b"", HI)),
    }
    assert all(paths.values())
    for name, rows in paths.items():
        assert all(type(r) is Row for r in rows), name
        assert all(isinstance(r.ts, int) and isinstance(r.atom, Atom) for r in rows), name

def test_reserved_name_relationships_are_narrow():
    ok = Atom(GATHER, SUM_NAME, b"sync", Exact(b"x"))
    assert dec_atom(enc_atom(ok)).relationship == GATHER          # a reserved Gather round-trips
    provenance = Atom(SUPPRESS_IF, REMOTE_NAME, ORIGIN_SCOPE, SELF)
    assert dec_atom(enc_atom(provenance)).relationship == SUPPRESS_IF
    for bad in (Atom(REQUIRE, SUM_NAME, b"sync", Exact(b"x")),  # reserved name that would gate
                Atom(SUPPRESS_IF, SUM_NAME, b"sync", Exact(b"x")),
                Atom(SUPPRESS_IF, REMOTE_NAME, ORIGIN_SCOPE, Exact(b"x")),
                Atom(SUPPRESS_IF, REMOTE_NAME, ORIGIN_SCOPE, SELF, b"x"),
                Atom(PROVIDE, RES_NAME, b"sync", Exact(b"x"))):       # a NUL-name Provide
        try: dec_atom(enc_atom(bad)); assert False, "reserved name accepted"
        except ValueError: pass

if __name__ == "__main__":
    for t in (test_closure_includes_self_and_spine, test_deps_structural,
              test_summary_small_range_is_one_id_list_with_closure,
              test_summary_large_range_splits_by_equal_count, test_resident_present_and_absent,
              test_every_match_path_returns_the_named_row_shape,
              test_reserved_name_relationships_are_narrow):
        t(); print("ok ", t.__name__)
