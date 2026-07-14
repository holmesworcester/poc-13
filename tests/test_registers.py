"""The two generic seams a family owns an index through — the settle() hook (a
family sees every verdict its facts settle to and folds it into its shared
register) and answer() (a family claims a reserved role) — plus sync's use of
them: the one-line replication opt-in, the terminal purge with its
die-on-arrival reconvergence, the Invalid minus, replay rebuilding the treap
through the very same hook, and the floored summary memo's durable-count guard
(which replaced the kernel's clear-on-every-admit)."""
import os, sys, types
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from kernel import (Atom, Exact, NEED, OFFER, Out, Router, SELF, REQUIRE,
                    SUPPRESS, WATCH, encode, fact, fact_id, ts_atom, Node)
from facts.sync import index as sidx
from facts.sync.index import summary_need, summary
import kernel

HI = b"\xff" * 41

def fam(**kw):                           # a toy family module
    return types.SimpleNamespace(**kw)

def toy(tag, ts, *atoms):
    return fact(tag, ts_atom(ts), *atoms)

def node(*fams):
    return Node(Router({b"toy": Router(dict(fams), depth=1)}))

def leafkeys(n): return set(sidx.tree(n).keys)


def test_replication_is_the_one_line_opt_in():
    quiet = fam(project=lambda f, ctx: Out(), extract=lambda f: (True, True))
    loud = fam(project=lambda f, ctx: Out(), extract=lambda f: (True, True),
               settle=sidx.settle)
    n = node((b"q", quiet), (b"l", loud))
    n.admit(encode(toy(b"toy.q", 1))); n.admit(encode(toy(b"toy.l", 2))); n.run()
    ks = leafkeys(n)
    assert len(ks) == 1                               # shareable is not enough: no hook, no leaf
    assert next(iter(ks))[:8] == (2).to_bytes(8, "big")   # the opted-in fact, at its ts


def test_suppression_purges_and_a_rearrival_dies_on_arrival():
    # Suppressed is terminal: the hook sees the verdict (project() never runs)
    # and drops the leaf; the kernel purges the husk whole. Convergence keeps
    # the RELATIONSHIP — the killer's offer stays — so a laggard peer
    # re-shipping the purged bytes buys one admission that dies on arrival.
    def project(f, ctx):
        return Out("Invalid") if by_role(ctx, b"poison") else Out()
    def by_role(ctx, role):
        return [r for nn, rs in ctx.items() if nn.role == role for r in rs]
    f1 = toy(b"toy.l", 5, Atom(NEED, b"kill", b"t", SELF, effect=SUPPRESS),
             Atom(NEED, b"poison", b"t", SELF, effect=WATCH))
    loud = fam(project=project, extract=lambda f: (True, True), settle=sidx.settle)
    killer = fam(project=lambda f, ctx: Out(offers=tuple(
                     a for a in f.atoms if a.kind == OFFER and a.role != b"ts")),
                 extract=lambda f: (False, False))
    n = node((b"l", loud), (b"k", killer))
    fid = n.admit(encode(f1)); n.run()
    assert leafkeys(n) and n.memo[fid] == "Valid"
    n.admit(encode(toy(b"toy.k", 6, Atom(OFFER, b"kill", b"t", Exact(fid))))); n.run()
    assert fid not in n.facts and fid not in n.durable   # purged whole, not a husk
    assert not leafkeys(n) and n.purged == [fid]         # leaf gone; the host learns what left disk
    v1 = sidx.ver(n)
    assert n.admit(encode(f1)) == fid; n.run()           # the laggard re-ship
    assert fid not in n.facts and not leafkeys(n)        # died on arrival
    assert sidx.ver(n) == v1                             # and never touched the tree
    # Invalid is NOT terminal: a poison offer flips project's own verdict — the
    # leaf leaves the set but the fact stays, because its cause may withdraw.
    f2 = toy(b"toy.l", 7, Atom(NEED, b"poison", b"t", SELF, effect=WATCH))
    fid2 = n.admit(encode(f2)); n.run()
    assert len(leafkeys(n)) == 1
    n.admit(encode(toy(b"toy.k", 8, Atom(OFFER, b"poison", b"t", Exact(fid2))))); n.run()
    assert n.memo[fid2] == "Invalid" and not leafkeys(n) and fid2 in n.facts


def test_replay_rebuilds_the_treap_through_the_same_hook():
    loud = fam(project=lambda f, ctx: Out(), extract=lambda f: (True, True),
               settle=sidx.settle)
    n = node((b"l", loud))
    for i in range(20): n.admit(encode(toy(b"toy.l", 100 + i)))
    n.run()
    m = node((b"l", loud))                            # a fresh engine over the same bytes:
    for b in n.durable.values(): m.admit(b, checked=True)   # hydration's admission path
    m.run()
    assert leafkeys(m) == leafkeys(n)                 # same set
    assert sidx.tree(m).fp(b"", HI) == sidx.tree(n).fp(b"", HI)   # same canonical fingerprint


def test_floored_memo_repins_on_closure_growth():
    # m requires a role that p offers; p sits below the floor, so it rides the
    # floored answer only as a closure id. The provider family is shareable but
    # NOT opted in (it rides closures, it is not a leaf), so a second provider
    # grows the closure WITHOUT moving the leaf set — only the durable-count
    # guard can notice: this pins the guard that replaced clear-on-every-admit.
    prov = fam(project=lambda f, ctx: Out(offers=tuple(
                   a for a in f.atoms if a.kind == OFFER and a.role == b"base")),
               extract=lambda f: (True, True))
    dep = fam(project=lambda f, ctx: Out(), extract=lambda f: (True, True),
              settle=sidx.settle)
    n = node((b"p", prov), (b"d", dep))
    p1 = toy(b"toy.p", 10, Atom(OFFER, b"base", b"t", Exact(b"x")))
    m1 = toy(b"toy.d", 1000, Atom(NEED, b"base", b"t", Exact(b"x"), effect=REQUIRE))
    n.admit(encode(p1)); n.admit(encode(m1)); n.run()
    floor = (500).to_bytes(8, "big") + bytes(32)
    rows = summary(n, summary_need(floor, HI, floor))
    cids = next(a.value for _, _, a in rows if a.role == b"cids")
    assert fact_id(p1) in set(kernel.unframe(cids))   # the below-floor dep rides
    assert summary(n, summary_need(floor, HI, floor)) is rows   # memoised while nothing moves
    p2 = toy(b"toy.p", 11, Atom(OFFER, b"base", b"t", Exact(b"x")))
    n.admit(encode(p2)); n.run()                      # a second provider joins m1's closure
    rows2 = summary(n, summary_need(floor, HI, floor))
    assert fact_id(p2) in set(kernel.unframe(
        next(a.value for _, _, a in rows2 if a.role == b"cids")))
