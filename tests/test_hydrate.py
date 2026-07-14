"""Hydration tests: matching looks to the persisted relation. A stepped
fact's needs fault their cold matches resident — transitively, over RECORDED
rows rather than family code — so a demand-driven session agrees with the
fully resident node on every fact it holds, across renamed roles and
reshaped facts. Boot is the degenerate demand: ONE total hydrate fact
replaces load and replay entirely, and this file pins their absence.
Existence is the certificate: reads reconstruct, re-encode, and re-hash, so
damage is a miss (never a wrong fact) that a repair fully reverses."""
import os, random, sys
from types import SimpleNamespace
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from kernel import (Atom, Exact, NEED, OFFER, Node, Out, REQUIRE, Range,
                    Router, SELF, SUPPRESS, Store, WATCH, all_need, covers,
                    decode, encode, fact, fact_id, mat, needs_of, ts_atom)
from facts import ROOT
from facts.auth import admin, local_signer_secret, user, workspace
from facts.content import channel, message, message_deletion
from facts.content.message import feed
from facts.store import hydrate

def _build():                            # the corpus is a REAL signed workspace
    n = Node(ROOT)
    local_signer_secret.keygen(n, 0)
    wid = workspace.create(n, b"acme", 1); n.run()   # founder is auto member + bootstrap admin
    uid = next(k for k, f in n.facts.items() if f.type_tag == b"auth.user")
    channel_id = channel.resolve(n, wid, "general")
    mids = [message.send(n, wid, channel_id, b"m%d" % i, 10 + i) for i in range(5)]
    message_deletion.delete(n, wid, mids[2], 99)
    return n.run(), wid, uid, mids, channel_id

FULL, WID, UID, MIDS, CH = _build()
CORPUS = list(FULL.durable.values())     # exactly what a db would hold

def store_of(bs, seed=0):
    s, bs = Store(), list(bs)
    random.Random(seed).shuffle(bs)      # row order must not matter
    for b in bs: s.add(b)
    return s

def full(): return FULL

# --- the working-set story: queries demand, needs fault, verdicts agree ---------
def test_demand_agrees_with_the_fully_resident_node():
    f = full()
    for seed in range(3):
        n = Node(ROOT, store_of(CORPUS, seed))
        assert feed(n, WID, CH) == [b"m0", b"m1", b"m3", b"m4"]     # m2 deleted, cold tombstone
        for fid in n.facts:              # every resident fact judged as the resident node judged it
            if fid in f.memo: assert n.memo[fid] == f.memo[fid], fid.hex()

def test_gating_needs_pull_their_closure():
    n = Node(ROOT, store_of(CORPUS))
    got = admin.admins(n, WID)           # admin Requires member Requires workspace
    assert got == [UID]
    assert WID in n.facts and n.memo[UID] == "Valid"

def test_suppression_across_the_cold_boundary():
    n = Node(ROOT, store_of(CORPUS))
    feed(n, WID, CH)
    assert MIDS[2] not in n.facts                            # the deletion was faulted in and bit: purged
    assert n.memo[MIDS[3]] == "Valid"

def test_signed_content_pulls_authority_closure():
    # The locality trade of signed content, pinned: a message Requires its
    # author's blessed key, so a channel feed faults membership resident too.
    n = Node(ROOT, store_of(CORPUS))
    feed(n, WID, CH)
    assert UID in n.facts                # the author's membership rode the Require closure

def test_hydration_is_only_ever_a_fact():
    """The demand IS the mechanism: content-addressed (the same demand twice
    is one fact, one check), volatile (never durable, never flushed), and
    nothing becomes resident until a fact carries a need into a step."""
    n = Node(ROOT, store_of(CORPUS))
    assert not n.facts                                 # cold until something demands
    a = hydrate.demand(n, b"msg", WID)
    b = hydrate.demand(n, b"msg", WID)
    assert a == b and a not in n.durable               # one volatile fact

# --- the boot story: one total demand, no load, no replay -----------------------
def test_boot_is_one_fact():
    n = Node(ROOT, store_of(CORPUS))
    seed = hydrate.demand(n)                           # the whole boot
    assert set(n.durable) == set(FULL.durable)
    assert all(n.durable[fid] == FULL.durable[fid] for fid in FULL.durable)
    assert all(n.memo[fid] == FULL.memo[fid] for fid in FULL.durable)
    assert set(n.memo) == set(FULL.durable) | {seed}   # residency = the durable set + the seed
    assert n.derived()[0] == FULL.derived()[0]         # the clean twin, bit-identical
    assert feed(n, WID, CH) == [b"m0", b"m1", b"m3", b"m4"]

def test_the_seed_is_the_only_boot():
    """The elimination, pinned: no load, no replay, no bulk read — the only
    way from rows to residency is a fact's need meeting the fault leg."""
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "bin"))
    import runtime, kernel
    assert not hasattr(runtime, "load")
    assert not hasattr(Store, "all") and not hasattr(Store, "pull")
    assert not hasattr(Node, "replay") and not hasattr(Node, "missing_needs")
    assert not hasattr(kernel, "window") and not hasattr(kernel, "WINDOW_LEN")

def test_a_checked_total_ends_faulting():
    """After the total demand everything is resident and every future step
    skips the store: existence is monotone (rows enter only via residency),
    so a checked total covers every key for the rest of the session."""
    s = store_of(CORPUS)
    n = Node(ROOT, s)
    hydrate.demand(n)
    calls = []
    s.owners = lambda *a: (calls.append(a), [])[1]     # any further call would land here
    assert feed(n, WID, CH) == [b"m0", b"m1", b"m3", b"m4"]
    assert calls == []

def test_a_flushed_key_is_already_resident():
    """Monotonicity of the fault memo: rows enter the store only through
    resident facts (flush), so a key checked while cold never goes stale."""
    s = Store()
    n = Node(ROOT, s)
    hydrate.demand(n, b"msg", WID)                     # checked while the db is empty
    for b in CORPUS: n.admit(b, checked=True)          # the workspace arrives live...
    n.run()
    for b in CORPUS: s.add(b)                          # ...and is flushed (runtime.flush)
    assert feed(n, WID, CH) == [b"m0", b"m1", b"m3", b"m4"]   # the memoized key lost nothing

# --- the relation is version-neutral: closures cross vocabulary eras ------------
S = b"s"
_epoch = SimpleNamespace(extract=lambda f: (True, False),   # a minimal always-valid family:
                         project=lambda f, ctx:             # promote every offer, gate on needs
                             Out(offers=tuple(a for a in f.atoms if a.kind == OFFER)))
EPOCHS = Router({b"v1": _epoch, b"v2": _epoch, b"v3": _epoch})

def _chain():
    """Three vocabulary eras, one dependency chain. v1 speaks role b"doc";
    v2 renamed it b"document" and grew a b"meta" field; v3 is the live head.
    Nothing current-era — no family code, no demand key — names the old
    vocabulary; only the recorded rows relate the eras. R is a RANGE offer
    covering the exact b"doc" needs, so the fault walk crosses a range edge
    at depth >= 1 deterministically."""
    A = fact(b"v1.doc", ts_atom(10), Atom(OFFER, b"doc", S, SELF))
    B = fact(b"v1.doc", ts_atom(20), Atom(NEED, b"doc", S, Exact(fact_id(A)), effect=REQUIRE),
             Atom(NEED, b"gone", S, SELF, effect=SUPPRESS), Atom(OFFER, b"doc", S, SELF))
    T = fact(b"v2.doc", ts_atom(50), Atom(NEED, b"doc", S, Exact(fact_id(B)), effect=REQUIRE),
             Atom(OFFER, b"document", S, SELF), Atom(OFFER, b"meta", S, SELF, b"lang=en"))
    C = fact(b"v3.item", ts_atom(100), Atom(NEED, b"document", S, Exact(fact_id(T)), effect=REQUIRE),
             Atom(OFFER, b"item", S, Exact(b"k")))
    R = fact(b"v1.idx", ts_atom(15), Atom(OFFER, b"doc", S, Range(b"\x00" * 32, b"\xff" * 32)))
    return [A, B, T, C, R]

def test_a_keyed_demand_pulls_related_facts_transitively():
    """A demand at the newest era's key hydrates the whole related web: the
    fault walk crosses a role rename and a field addition because it walks
    recorded rows, never family vocabulary."""
    chain = _chain()
    s = Store()
    for f in chain: s.add(encode(f))
    n = Node(EPOCHS, s)
    hydrate.demand(n, b"item", S)                      # the era-3 key only
    ids = [fact_id(f) for f in chain]
    assert all(i in n.facts for i in ids)     # A, B, R arrived via a role nothing current names
    assert all(n.memo[i] == "Valid" for i in ids)
    m = Node(EPOCHS)
    for f in chain: m.admit(encode(f), checked=True)
    m.run()
    assert {i: n.memo[i] for i in ids} == {i: m.memo[i] for i in ids}

def test_a_tombstone_rides_the_closure_across_eras():
    """A suppressor is one recorded Suppress edge from its target, so it
    arrives with it: a cold old-era tombstone is never outrun by the
    new-era facts that depend on its target."""
    chain = _chain()
    D = fact(b"v1.tomb", ts_atom(25), Atom(OFFER, b"gone", S, Exact(fact_id(chain[1]))))
    s = Store()
    for f in chain + [D]: s.add(encode(f))
    n = Node(EPOCHS, s)
    hydrate.demand(n, b"item", S)
    assert fact_id(D) in n.facts                       # faulted via B's suppress key
    assert fact_id(chain[1]) not in n.facts            # ...and bit: B purged whole
    m = Node(EPOCHS)
    for f in chain + [D]: m.admit(encode(f), checked=True)
    m.run()
    ids = [fact_id(f) for f in chain + [D]]            # purged ids compare as absent on both paths
    assert {i: n.memo.get(i) for i in ids} == {i: m.memo.get(i) for i in ids}

def test_needs_fault_their_own_deps():
    """No demand needed: a resident fact's own step checks its keys against
    the relation, so a head whose spine is cold validates as it lands."""
    chain = _chain()
    s = Store()
    for f in chain[:3] + chain[4:]: s.add(encode(f))   # A, B, T, R cold in the db
    n = Node(EPOCHS, s)
    cid = n.admit(encode(chain[3])); n.run()           # the head arrives...
    assert n.memo[cid] == "Valid"                      # ...and faults its whole spine
    assert all(fact_id(f) in n.facts for f in chain[:3])

def test_a_cold_suppressor_bites_without_a_demand():
    """The suppress flavor: a live-authored fact's own step checks its
    suppress key, so a tombstone cold in the db flips it immediately —
    never a lasting wrong Valid waiting for the right demand."""
    chain = _chain()
    D = fact(b"v1.tomb", ts_atom(25), Atom(OFFER, b"gone", S, Exact(fact_id(chain[1]))))
    s = Store()
    s.add(encode(chain[0])); s.add(encode(D))          # A and B's tombstone, cold
    n = Node(EPOCHS, s)
    bid = n.admit(encode(chain[1])); n.run()           # B authored live
    assert fact_id(D) in n.facts and bid not in n.facts   # the cold tombstone bit: B purged on arrival

# --- existence is the certificate: reconstruction, damage, repair ---------------
class _Flaky:
    """A connection proxy whose next executemany raises — a transient write
    fault (or a signal handler's SystemExit) landing between the two inserts."""
    def __init__(self, db, exc): self._db, self._exc = db, exc
    def __getattr__(self, k): return getattr(self._db, k)
    def executemany(self, *a):
        if self._exc: e, self._exc = self._exc, None; raise e
        return self._db.executemany(*a)

def test_a_failed_write_propagates_and_tears_nothing():
    """Bad bytes are a miss, but a failed WRITE propagates whole: the caller
    keeps the fact unflushed (never a silent +ok over nothing) and no torn
    half-fact blocks the retry — SystemExit (tinyd's signal handler) included."""
    import sqlite3
    for exc in (sqlite3.OperationalError("disk I/O error"), SystemExit(0)):
        s = Store()
        b = CORPUS[0]; fid = fact_id(decode(b))
        s.db = _Flaky(s.db, exc)
        try:
            s.add(b); assert False, "the write error must propagate"
        except type(exc): pass
        assert s.db.execute("SELECT count(*) FROM facts WHERE fid=?", (fid,)).fetchone() == (0,)
        s.add(b)                                       # the retry heals completely
        assert s.fact_bytes(fid) == b

def test_adds_are_durable_only_at_commit():
    """One transaction per host turn: a second connection sees nothing until
    commit() — durable before the reply, never before."""
    import sqlite3, tempfile
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "t.facts")
        s = Store(path); s.add(CORPUS[0])
        other = sqlite3.connect(path)
        assert other.execute("SELECT count(*) FROM facts").fetchone() == (0,)
        s.commit()
        assert other.execute("SELECT count(*) FROM facts").fetchone() == (1,)
        other.close(); s.db.close()

def test_a_zero_atom_fact_survives_the_reboot():
    """A canonical fact with no atoms at all (legal: decode round-trips it,
    unknown tags extract durable) reconstructs from its spine row alone."""
    f = fact(b"no.such")
    s = Store(); s.add(encode(f))
    assert s.fact_bytes(fact_id(f)) == encode(f)
    n = Node(Router({}), s)
    n.admit(encode(hydrate.hydrate())); n.run()        # the total demand faults it resident
    assert fact_id(f) in n.durable

def test_rows_rebuild_the_exact_bytes():
    """The relation is the store: reconstruction re-derives byte-identical
    canonical facts — every target shape, and the None vs b"" value
    distinction, included."""
    s = store_of(CORPUS)
    for b in CORPUS: assert s.fact_bytes(fact_id(decode(b))) == b
    f = fact(b"no.such", ts_atom(7), Atom(OFFER, b"a", b"s", SELF),
             Atom(OFFER, b"b", b"s", Exact(b"k"), b""),
             Atom(NEED, b"c", b"s", Range(b"a", b"z"), effect=WATCH),
             Atom(NEED, b"d", b"s", Exact(b"k"), effect=SUPPRESS))
    s2 = Store(); s2.add(encode(f))
    assert s2.fact_bytes(fact_id(f)) == encode(f)

def test_a_damaged_row_is_a_miss_never_a_wrong_fact():
    s = store_of(CORPUS)
    victim = fact_id(decode(CORPUS[0]))
    s.db.execute("UPDATE atoms SET value=x'ff' WHERE fid=? AND value IS NOT NULL", (victim,))
    assert s.fact_bytes(victim) is None                # no longer re-hashes to its fid
    n = Node(ROOT, s)
    hydrate.demand(n)                                  # boot over the damaged db
    assert victim not in n.facts                       # a miss...
    for fid, b in n.durable.items():
        assert b == FULL.durable[fid]                  # ...and everything held is exact

def test_repair_after_damage_redelivers():
    """Damage leaves no residue: delete + the true bytes + refault (the
    close.purge discipline) redeliver without any new demand — the parked
    dependent's own key re-checks and heals."""
    chain = _chain()
    s = Store()
    for f in chain[:2]: s.add(encode(f))
    s.db.execute("UPDATE atoms SET value=x'ff' WHERE fid=? AND value IS NOT NULL",
                 (fact_id(chain[0]),))                 # damage A (its ts row)
    n = Node(EPOCHS, s)
    hydrate.demand(n, b"doc", S)                       # B delivered; A missed
    assert n.memo[fact_id(chain[1])] == "Parked"
    s.delete(fact_id(chain[0])); s.add(encode(chain[0]))
    n.refault(); n.run()                               # the relation changed underneath
    assert n.memo[fact_id(chain[1])] == "Valid"

# --- mirrors: the SQL coverage relation and the fault fixpoint ------------------
def test_fault_fixpoint_mirrors_kernel_covers():
    """Property mirror: the resident set a demand faults in equals a
    pure-Python fixpoint (needs_of x covers over materialized atoms) on
    random fact graphs mixing every target shape and effect."""
    rng = random.Random(7)
    ks = [bytes([k]) for k in range(4)]
    tshapes = [Exact(k) for k in ks] + [Range(a, b) for a in ks for b in ks if a <= b] + [SELF]
    roles = [b"p", b"q", b"r"]
    for trial in range(25):
        fs = {}
        for i in range(12):
            atoms = [ts_atom(50 + i)]
            for _ in range(rng.randrange(1, 4)):
                if rng.random() < 0.5:
                    atoms.append(Atom(OFFER, rng.choice(roles), S, rng.choice(tshapes)))
                else:
                    atoms.append(Atom(NEED, rng.choice(roles), S, rng.choice(tshapes),
                                      effect=rng.choice((REQUIRE, WATCH, SUPPRESS))))
            f = fact(b"no.such", *atoms)
            fs[fact_id(f)] = f
        def covering(n):                 # owners of offers covering one materialized need
            return {i for i, f in fs.items()
                    if any(a.kind == OFFER and (a.role, a.scope) == (n.role, n.scope)
                           and covers(mat(a, i).target, n.target) for a in f.atoms)}
        seed = Atom(NEED, b"p", S, Range(b"", b"\xff"), effect=WATCH)
        want, queue = set(), sorted(covering(seed))
        while queue:
            i = queue.pop()
            if i in want: continue
            want.add(i)
            for n in needs_of(fs[i], i): queue += sorted(covering(n))
        st = Store()
        for f in fs.values(): st.add(encode(f))
        nd = Node(Router({}), st)
        sid = nd.admit(encode(fact(b"x.demand", seed))); nd.run()
        assert set(nd.facts) - {sid} == want, trial

def test_sql_owners_mirrors_covers():
    """Exhaustive mirror: Store.owners == the kernel-covers reference for
    every target-shape pair on a small alphabet, plus the total key."""
    ks = [bytes([b]) for b in range(4)]
    shapes = [Exact(k) for k in ks] + [Range(a, b) for a in ks for b in ks if a <= b]
    s, fids = Store(), {}
    for i, ot in enumerate(shapes):
        f = fact(b"no.such", ts_atom(250 + 7 * i), Atom(OFFER, b"r", b"s", ot))
        s.add(encode(f)); fids[fact_id(f)] = ot
    for nt in shapes:
        need = Atom(NEED, b"r", b"s", nt, effect=REQUIRE)
        assert set(s.owners(need)) == {fid for fid, ot in fids.items() if covers(ot, nt)}, nt
    assert set(s.owners(all_need)) == set(fids)        # the total demand: every stored fact
    dup = fact(b"no.such", ts_atom(999), Atom(OFFER, b"r", b"s", Exact(ks[0])),
               Atom(OFFER, b"r", b"s", Range(ks[0], ks[1])))
    s.add(encode(dup))                                 # two rows cover the same point...
    got = s.owners(Atom(NEED, b"r", b"s", Exact(ks[0]), effect=REQUIRE))
    assert got.count(fact_id(dup)) == 1                # ...but an owner faults once

if __name__ == "__main__":
    for t in (test_demand_agrees_with_the_fully_resident_node,
              test_gating_needs_pull_their_closure,
              test_suppression_across_the_cold_boundary, test_signed_content_pulls_authority_closure,
              test_hydration_is_only_ever_a_fact, test_boot_is_one_fact,
              test_the_seed_is_the_only_boot, test_a_checked_total_ends_faulting,
              test_a_flushed_key_is_already_resident,
              test_a_keyed_demand_pulls_related_facts_transitively,
              test_a_tombstone_rides_the_closure_across_eras,
              test_needs_fault_their_own_deps, test_a_cold_suppressor_bites_without_a_demand,
              test_rows_rebuild_the_exact_bytes, test_a_damaged_row_is_a_miss_never_a_wrong_fact,
              test_repair_after_damage_redelivers, test_a_failed_write_propagates_and_tears_nothing,
              test_adds_are_durable_only_at_commit, test_a_zero_atom_fact_survives_the_reboot,
              test_fault_fixpoint_mirrors_kernel_covers, test_sql_owners_mirrors_covers):
        t(); print(f"ok  {t.__name__}")
    print("\nall tests passed")
