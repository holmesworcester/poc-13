"""The two generic seams a family owns an index through — observe() folds
validated Provide deltas into a rebuildable register and answer() exposes the
index through a reserved Gather — plus sync's use of them: a projector-emitted
leaf marker as the sole replication decision, terminal and Invalid retraction,
replay rebuilding the treap, closure memo invalidation, and marker-authorized
by-id shipment."""
import os, sys, types
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from kernel import (Atom, Exact, PROVIDE, Out, Router, SELF, REQUIRE,
                    SUPPRESS_IF, GATHER, encode, fact, fact_id, ts_atom, Node)
from facts.sync import index as sidx
from facts.sync import need as sync_need
from facts.sync.index import summary_gather, summary
import kernel

HI = b"\xff" * 41

def fam(**kw):                           # a toy family module
    return types.SimpleNamespace(**kw)

def toy(tag, ts, *atoms):
    return fact(tag, ts_atom(ts), *atoms)

def node(*fams):
    return Node(Router({b"toy": Router(dict(fams), depth=1)}))

def sync_node(*fams):
    return Node(Router({b"toy": Router(dict(fams), depth=1),
                        b"sync": Router({b"need": sync_need}, depth=1)}))

def leafkeys(n): return set(sidx.tree(n).keys)


def test_projected_leaf_offer_is_the_replication_decision():
    quiet = fam(project=lambda f, ctx: Out(), extract=lambda f: True)
    loud = fam(project=lambda f, ctx: Out(provides=(sidx.sync_leaf(),)), extract=lambda f: True)
    n = node((b"q", quiet), (b"l", loud))
    qid = n.admit(encode(toy(b"toy.q", 1)))
    lid = n.admit(encode(toy(b"toy.l", 2)))
    # An asserted marker is still dirty input: only projector output is indexed.
    forged = n.admit(encode(toy(b"toy.q", 3, sidx.sync_leaf())))
    n.run()
    ks = leafkeys(n)
    assert ks == {(2).to_bytes(8, "big") + lid}
    assert sidx.contains(n, lid) and not sidx.contains(n, qid) and not sidx.contains(n, forged)
    assert n.matches(sidx.sync_leaf_gather(lid))
    assert not n.matches(sidx.sync_leaf_gather(qid))


def test_suppression_purges_and_a_rearrival_dies_on_arrival():
    # Suppressed is terminal: clean replacement retracts the projected marker
    # even though project() never runs, and the observer drops the leaf before
    # the kernel purges the husk whole. Convergence keeps
    # the RELATIONSHIP — the killer's Provide stays — so a laggard peer
    # re-shipping the purged bytes buys one admission that dies on arrival.
    def project(f, ctx):
        return Out("Invalid") if by_name(ctx, b"poison") else Out(provides=(sidx.sync_leaf(),))
    def by_name(ctx, name):
        return [r for nn, rs in ctx.items() if nn.name == name for r in rs]
    f1 = toy(b"toy.l", 5, Atom(SUPPRESS_IF, b"kill", b"t", SELF),
             Atom(GATHER, b"poison", b"t", SELF))
    loud = fam(project=project, extract=lambda f: True)
    killer = fam(project=lambda f, ctx: Out(provides=tuple(
                     a for a in f.atoms if a.relationship == PROVIDE and a.name != b"ts")),
                 extract=lambda f: False)
    n = node((b"l", loud), (b"k", killer))
    fid = n.admit(encode(f1)); n.run()
    assert leafkeys(n) and n.memo[fid] == "Valid"
    n.admit(encode(toy(b"toy.k", 6, Atom(PROVIDE, b"kill", b"t", Exact(fid))))); n.run()
    assert fid not in n.facts and fid not in n.durable   # purged whole, not a husk
    assert not leafkeys(n) and n.purged == [fid]         # leaf gone; the host learns what left disk
    v1 = sidx.ver(n)
    assert n.admit(encode(f1)) == fid; n.run()           # the laggard re-ship
    assert fid not in n.facts and not leafkeys(n)        # died on arrival
    assert sidx.ver(n) == v1                             # and never touched the tree
    # Invalid is NOT terminal: a poison Provide flips project's own verdict — the
    # leaf leaves the set but the fact stays, because its cause may withdraw.
    f2 = toy(b"toy.l", 7, Atom(GATHER, b"poison", b"t", SELF))
    fid2 = n.admit(encode(f2)); n.run()
    assert len(leafkeys(n)) == 1
    n.admit(encode(toy(b"toy.k", 8, Atom(PROVIDE, b"poison", b"t", Exact(fid2))))); n.run()
    assert n.memo[fid2] == "Invalid" and not leafkeys(n) and fid2 in n.facts


def test_replay_rebuilds_the_treap_from_projected_markers():
    loud = fam(project=lambda f, ctx: Out(provides=(sidx.sync_leaf(),)), extract=lambda f: True)
    n = node((b"l", loud))
    for i in range(20): n.admit(encode(toy(b"toy.l", 100 + i)))
    n.run()
    m = node((b"l", loud))                            # a fresh engine over the same bytes:
    for b in n.durable.values(): m.admit(b, checked=True)   # hydration's admission path
    m.run()
    assert leafkeys(m) == leafkeys(n)                 # same set
    assert sidx.tree(m).fp(b"", HI) == sidx.tree(n).fp(b"", HI)   # same canonical fingerprint


def test_floored_memo_invalidates_when_a_marker_leaf_grows_the_closure():
    # m requires a name that p provides; p sits below the floor, so it rides the
    # floored answer only as a closure id. Every transferable dependency is a
    # leaf, so a second provider grows the set and invalidates the memo through
    # the same marker observer; no separate durable-count guard is needed.
    prov = fam(project=lambda f, ctx: Out(provides=tuple(
                   a for a in f.atoms if a.relationship == PROVIDE and a.name == b"base")
                   + (sidx.sync_leaf(),)),
               extract=lambda f: True)
    dep = fam(project=lambda f, ctx: Out(provides=(sidx.sync_leaf(),)), extract=lambda f: True)
    n = node((b"p", prov), (b"d", dep))
    p1 = toy(b"toy.p", 10, Atom(PROVIDE, b"base", b"t", Exact(b"x")))
    m1 = toy(b"toy.d", 1000, Atom(REQUIRE, b"base", b"t", Exact(b"x")))
    n.admit(encode(p1)); n.admit(encode(m1)); n.run()
    floor = (500).to_bytes(8, "big") + bytes(32)
    rows = summary(n, summary_gather(floor, HI, floor))
    cids = next(a.value for _, _, a in rows if a.name == b"cids")
    assert fact_id(p1) in set(kernel.unframe(cids))   # the below-floor dep rides
    assert summary(n, summary_gather(floor, HI, floor)) is rows   # memoised while nothing moves
    p2 = toy(b"toy.p", 11, Atom(PROVIDE, b"base", b"t", Exact(b"x")))
    n.admit(encode(p2)); n.run()                      # a second provider joins m1's closure
    rows2 = summary(n, summary_gather(floor, HI, floor))
    assert rows2 is not rows
    assert fact_id(p2) in set(kernel.unframe(
        next(a.value for _, _, a in rows2 if a.name == b"cids")))


def test_sync_need_ships_only_validated_marker_owners():
    quiet = fam(project=lambda f, ctx: Out(), extract=lambda f: True)
    loud = fam(project=lambda f, ctx: Out(provides=(sidx.sync_leaf(),)), extract=lambda f: True)
    n = sync_node((b"q", quiet), (b"l", loud))
    local_id = n.admit(encode(toy(b"toy.q", 1)))
    shared_id = n.admit(encode(toy(b"toy.l", 2)))
    n.run()

    cid = bytes([7]) * 32
    n.admit(encode(sync_need.need(cid, [local_id, shared_id])))
    n.run()
    shipped = [kernel.unframe(a.value) for _, _, a in n.provided(b"ship", b"outbox")]
    assert shipped == [[shared_id]]
