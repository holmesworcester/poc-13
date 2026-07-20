"""Hydration tests: matching looks to the persisted relation. A stepped
fact's consumer relationships fault their cold matches resident — transitively, over RECORDED
rows rather than family code — so a demand-driven session agrees with the
fully resident node on every fact it holds, across renamed names and
reshaped facts. Boot is the degenerate demand: ONE total hydrate fact
replaces load and replay entirely, and this file pins their absence.
Existence is the certificate: reads reconstruct, re-encode, and re-hash, so
damage is a miss (never a wrong fact) that a repair fully reverses."""
import os, random, sys
from types import SimpleNamespace
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from kernel import (Atom, Exact, PROVIDE, Node, Out, REQUIRE, Range,
                    Router, SELF, SUPPRESS_IF, Store, GATHER, all_gather, covers,
                    decode, encode, fact, fact_id, mat, consumers_of, ts_atom)
from facts import ROOT
from facts.auth import admin, local_signer_secret, user, workspace
from facts.content import channel, file, file_slice, message, message_deletion, reaction
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

# --- the working-set story: queries demand, consumers fault, verdicts agree -----
def test_demand_agrees_with_the_fully_resident_node():
    f = full()
    for seed in range(3):
        n = Node(ROOT, store_of(CORPUS, seed))
        assert feed(n, WID, CH) == [b"m0", b"m1", b"m3", b"m4"]     # m2 deleted, cold tombstone
        for fid in n.facts:              # every resident fact judged as the resident node judged it
            if fid in f.memo: assert n.memo[fid] == f.memo[fid], fid.hex()

def test_require_relationships_pull_their_closure():
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
    nothing becomes resident until a fact carries a consumer into a step."""
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
    way from rows to residency is a consumer relationship meeting the fault leg."""
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
    s.providers = lambda *a: (calls.append(a), [])[1]  # any further call would land here
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
_epoch = SimpleNamespace(extract=lambda f: True,            # a minimal always-valid family:
                         project=lambda f, ctx:             # publish every Provide; engine settles consumers
                             Out(provides=tuple(a for a in f.atoms if a.relationship == PROVIDE)))
EPOCHS = Router({b"v1": _epoch, b"v2": _epoch, b"v3": _epoch})

def _chain():
    """Three vocabulary eras, one dependency chain. v1 speaks name b"doc";
    v2 renamed it b"document" and grew a b"meta" field; v3 is the live head.
    Nothing current-era — no family code, no demand key — names the old
    vocabulary; only the recorded rows relate the eras. R is a RANGE Provide
    covering the exact b"doc" consumers, so the fault walk crosses a range edge
    at depth >= 1 deterministically."""
    A = fact(b"v1.doc", ts_atom(10), Atom(PROVIDE, b"doc", S, SELF))
    B = fact(b"v1.doc", ts_atom(20), Atom(REQUIRE, b"doc", S, Exact(fact_id(A))),
             Atom(SUPPRESS_IF, b"gone", S, SELF), Atom(PROVIDE, b"doc", S, SELF))
    T = fact(b"v2.doc", ts_atom(50), Atom(GATHER, b"doc", S, Exact(fact_id(B))),
             Atom(PROVIDE, b"document", S, SELF), Atom(PROVIDE, b"meta", S, SELF, b"lang=en"))
    C = fact(b"v3.item", ts_atom(100), Atom(REQUIRE, b"document", S, Exact(fact_id(T))),
             Atom(PROVIDE, b"item", S, Exact(b"k")))
    R = fact(b"v1.idx", ts_atom(15), Atom(PROVIDE, b"doc", S, Range(b"\x00" * 32, b"\xff" * 32)))
    return [A, B, T, C, R]

def test_a_keyed_demand_pulls_related_facts_transitively():
    """A demand at the newest era's key hydrates the whole related web: the
    fault walk crosses a name rename and a field addition because it walks
    recorded rows, never family vocabulary."""
    chain = _chain()
    s = Store()
    for f in chain: s.add(encode(f))
    n = Node(EPOCHS, s)
    hydrate.demand(n, b"item", S)                      # the era-3 key only
    ids = [fact_id(f) for f in chain]
    assert all(i in n.facts for i in ids)     # A, B, R arrived via a name nothing current names
    assert all(n.memo[i] == "Valid" for i in ids)
    m = Node(EPOCHS)
    for f in chain: m.admit(encode(f), checked=True)
    m.run()
    assert {i: n.memo[i] for i in ids} == {i: m.memo[i] for i in ids}

def test_a_tombstone_rides_the_closure_across_eras():
    """A suppressor is one recorded SuppressIf edge from its target, so it
    arrives with it: a cold old-era tombstone is never outrun by the
    new-era facts that depend on its target."""
    chain = _chain()
    D = fact(b"v1.tomb", ts_atom(25), Atom(PROVIDE, b"gone", S, Exact(fact_id(chain[1]))))
    s = Store()
    for f in chain + [D]: s.add(encode(f))
    n = Node(EPOCHS, s)
    hydrate.demand(n, b"item", S)
    assert fact_id(D) in n.facts                       # faulted via B's SuppressIf key
    assert fact_id(chain[1]) not in n.facts            # ...and bit: B purged whole
    m = Node(EPOCHS)
    for f in chain + [D]: m.admit(encode(f), checked=True)
    m.run()
    ids = [fact_id(f) for f in chain + [D]]            # purged ids compare as absent on both paths
    assert {i: n.memo.get(i) for i in ids} == {i: m.memo.get(i) for i in ids}

def test_consumers_fault_their_own_dependencies():
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
    """The SuppressIf relationship: a live-authored fact's own step checks its
    key, so a tombstone cold in the db flips it immediately —
    never a lasting wrong Valid waiting for the right demand."""
    chain = _chain()
    D = fact(b"v1.tomb", ts_atom(25), Atom(PROVIDE, b"gone", S, Exact(fact_id(chain[1]))))
    s = Store()
    s.add(encode(chain[0])); s.add(encode(D))          # A and B's tombstone, cold
    n = Node(EPOCHS, s)
    bid = n.admit(encode(chain[1])); n.run()           # B authored live
    assert fact_id(D) in n.facts and bid not in n.facts   # the cold tombstone bit: B purged on arrival

# --- the forward suppression leg: a deletion reaches a durable-but-cold target --
def _live_and_dead(mid_index=2):
    """A peer's disk holding a message AND its deletion. The target's bytes come
    from the pre-delete durable set (the fully-resident builder purges the target,
    so its post-delete set can never exhibit the cold-target case); the deletion
    AND its signature closure come from the post-delete set. Their union is the
    disk a peer would hold: every message, plus a deletion that can validate."""
    n = Node(ROOT)
    local_signer_secret.keygen(n, 0)
    wid = workspace.create(n, b"acme", 1); n.run()
    cid = channel.resolve(n, wid, "general")
    mids = [message.send(n, wid, cid, b"m%d" % i, 10 + i) for i in range(5)]; n.run()
    pre = dict(n.durable)                              # all five messages durable, none deleted yet
    message_deletion.delete(n, wid, mids[mid_index], 99); n.run()
    corpus = {**pre, **n.durable}                      # pre keeps the target; post adds deletion+signature
    return list(corpus.values()), wid, mids[mid_index]

def test_a_cold_target_is_purged_when_only_the_deletion_hydrates():
    """The forward dual of test_a_cold_suppressor_bites_without_a_demand: there
    the live target pulls its own death; here only the DELETION hydrates and it
    must still reach a durable-but-cold target it never demanded. A peer holds a
    message and its deletion on disk and demands only the suppressor address
    b"dead" — never b"msg". Without the forward leg the deletion validates but
    the message sits untouched on disk: a false 'I have it' the sync layer would
    advertise. With it, the target is faulted in, bites, and is purged."""
    corpus, wid, mid = _live_and_dead()
    s = store_of(corpus)
    assert s.fact_bytes(mid) is not None               # the target is on the peer's disk
    n = Node(ROOT, s)
    hydrate.demand(n, b"dead", wid)                     # the suppressor address only, never b"msg"
    assert mid not in n.facts                           # faulted in, bit, and evicted whole...
    assert s.fact_bytes(mid) is None                    # ...its bytes gone from disk, not merely cold

def test_the_forward_leg_is_inert_under_total_demand():
    """The safety property that lets it land before eviction exists: under the
    total boot demand _ALL_KEY guards the leg off entirely, so residency and
    every verdict are bit-identical to a node without it — the leg changes
    nothing until a demand is selective enough to leave a target cold."""
    corpus, wid, mid = _live_and_dead()
    n = Node(ROOT, store_of(corpus))
    hydrate.demand(n)                                   # the whole boot: _ALL_KEY ∈ checked
    assert not any(k[0] == SUPPRESS_IF and len(k) == 4 for k in n.checked)   # leg never fired
    assert mid not in n.facts and mid not in n.durable  # yet deleted the ordinary (backward) way,
    assert mid not in n.memo                            # evicted whole — no residue, exactly as before

def test_deletion_closure_is_flat():
    """F4, the flatness the forward leg depends on: every family that must die
    with a message names the MESSAGE directly in its `dead` SuppressIf — never a
    derived fid it merely Requires (a slice names the message, not the
    descriptor root it authenticates). Static: each SHAPE's death key is SELF
    (the message itself) or Exact(message_id). Dynamic: a deletion purges the
    message and a reaction on it from memory AND disk in one flat closure."""
    wid, mid, fid, root = (bytes([i]) * 32 for i in range(4))
    shapes = {                                         # every dead-key-bearing family
        b"message":    message.message(wid, bytes([9]) * 32, bytes([8]) * 32, b"b", 1),
        b"reaction":   reaction.reaction(wid, mid, bytes([8]) * 32, b":x:", 2),
        b"file":       file.file(wid, mid, fid, root, 0, 0, b"n", b"m", 3),
        b"file_slice": file_slice.file_slice(wid, mid, fid, root, 0, b"\x00" * 8, 4)}
    for name, shape in shapes.items():
        dead = [a for a in shape.atoms if a.relationship == SUPPRESS_IF and a.name == b"dead"]
        assert len(dead) == 1, name
        assert dead[0].target in (SELF, Exact(mid)), (name, dead[0].target)   # never a derived fid

    n = Node(ROOT)                                      # dynamic: author message + reaction, delete
    local_signer_secret.keygen(n, 0)
    w = workspace.create(n, b"acme", 1); n.run()
    ch = channel.resolve(n, w, "general")
    m = message.send(n, w, ch, b"hi", 10)
    r = reaction.react(n, w, m, b":+1:", 11); n.run()
    assert n.memo[m] == "Valid" and n.memo[r] == "Valid"
    message_deletion.delete(n, w, m, 99); n.run()
    assert m not in n.facts and r not in n.facts        # the reaction died with the message...
    assert m not in n.durable and r not in n.durable    # ...from memory and disk, one flat closure

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
    f = fact(b"no.such", ts_atom(7), Atom(PROVIDE, b"a", b"s", SELF),
             Atom(PROVIDE, b"b", b"s", Exact(b"k"), b""),
             Atom(REQUIRE, b"c", b"s", Range(b"a", b"z")),
             Atom(SUPPRESS_IF, b"d", b"s", Exact(b"k")))
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
    pure-Python fixpoint (consumers_of x covers over materialized atoms) on
    random fact graphs mixing every target shape and relationship."""
    rng = random.Random(7)
    ks = [bytes([k]) for k in range(4)]
    tshapes = [Exact(k) for k in ks] + [Range(a, b) for a in ks for b in ks if a <= b] + [SELF]
    names = [b"p", b"q", b"r"]
    for trial in range(25):
        fs = {}
        for i in range(12):
            atoms = [ts_atom(50 + i)]
            for _ in range(rng.randrange(1, 4)):
                if rng.random() < 0.5:
                    atoms.append(Atom(PROVIDE, rng.choice(names), S, rng.choice(tshapes)))
                else:
                    atoms.append(Atom(rng.choice((REQUIRE, GATHER, SUPPRESS_IF)),
                                      rng.choice(names), S, rng.choice(tshapes)))
            f = fact(b"no.such", *atoms)
            fs[fact_id(f)] = f
        def covering(n):                 # owners of Provides covering one materialized consumer
            return {i for i, f in fs.items()
                    if any(a.relationship == PROVIDE and (a.name, a.scope) == (n.name, n.scope)
                           and covers(mat(a, i).target, n.target) for a in f.atoms)}
        seed = Atom(GATHER, b"p", S, Range(b"", b"\xff"))
        want, queue = set(), sorted(covering(seed))
        while queue:
            i = queue.pop()
            if i in want: continue
            want.add(i)
            for n in consumers_of(fs[i], i): queue += sorted(covering(n))
        st = Store()
        for f in fs.values(): st.add(encode(f))
        nd = Node(Router({}), st)
        sid = nd.admit(encode(fact(b"x.demand", seed))); nd.run()
        assert set(nd.facts) - {sid} == want, trial

def test_sql_providers_mirrors_covers():
    """Exhaustive mirror: Store.providers == the kernel-covers reference for
    every target-shape pair on a small alphabet, plus the total key."""
    ks = [bytes([b]) for b in range(4)]
    shapes = [Exact(k) for k in ks] + [Range(a, b) for a in ks for b in ks if a <= b]
    s, fids = Store(), {}
    for i, ot in enumerate(shapes):
        f = fact(b"no.such", ts_atom(250 + 7 * i), Atom(PROVIDE, b"r", b"s", ot))
        s.add(encode(f)); fids[fact_id(f)] = ot
    for nt in shapes:
        consumer = Atom(REQUIRE, b"r", b"s", nt)
        assert set(s.providers(consumer)) == {fid for fid, ot in fids.items() if covers(ot, nt)}, nt
    assert set(s.providers(all_gather)) == set(fids)     # the total demand: every stored fact
    dup = fact(b"no.such", ts_atom(999), Atom(PROVIDE, b"r", b"s", Exact(ks[0])),
               Atom(PROVIDE, b"r", b"s", Range(ks[0], ks[1])))
    s.add(encode(dup))                                 # two rows cover the same point...
    got = s.providers(Atom(REQUIRE, b"r", b"s", Exact(ks[0])))
    assert got.count(fact_id(dup)) == 1                # ...but an owner faults once

def test_sql_suppressors_mirrors_covers():
    """Exhaustive mirror, dual of test_sql_providers_mirrors_covers: for every
    target-shape pair, Store.suppressors(P) == the durable SuppressIf rows whose
    target covers-matches P. It is the reversed argument order of the same
    coverage relation — covers(provide, suppressif) here vs. covers(provide,
    consumer) there — which is exactly why the one _COV clause serves both."""
    ks = [bytes([b]) for b in range(4)]
    shapes = [Exact(k) for k in ks] + [Range(a, b) for a in ks for b in ks if a <= b]
    s, fids = Store(), {}
    for i, st in enumerate(shapes):
        f = fact(b"no.such", ts_atom(300 + 7 * i), Atom(SUPPRESS_IF, b"r", b"s", st))
        s.add(encode(f)); fids[fact_id(f)] = st
    for pt in shapes:
        provide = Atom(PROVIDE, b"r", b"s", pt)
        assert set(s.suppressors(provide)) == {fid for fid, st in fids.items() if covers(pt, st)}, pt
    dup = fact(b"no.such", ts_atom(998), Atom(SUPPRESS_IF, b"r", b"s", Exact(ks[0])),
               Atom(SUPPRESS_IF, b"r", b"s", Range(ks[0], ks[1])))
    s.add(encode(dup))                                 # two SuppressIf rows cover the same point...
    got = s.suppressors(Atom(PROVIDE, b"r", b"s", Exact(ks[0])))
    assert got.count(fact_id(dup)) == 1                # ...but an owner faults once

if __name__ == "__main__":
    for t in (test_demand_agrees_with_the_fully_resident_node,
              test_require_relationships_pull_their_closure,
              test_suppression_across_the_cold_boundary, test_signed_content_pulls_authority_closure,
              test_hydration_is_only_ever_a_fact, test_boot_is_one_fact,
              test_the_seed_is_the_only_boot, test_a_checked_total_ends_faulting,
              test_a_flushed_key_is_already_resident,
              test_a_keyed_demand_pulls_related_facts_transitively,
              test_a_tombstone_rides_the_closure_across_eras,
              test_consumers_fault_their_own_dependencies, test_a_cold_suppressor_bites_without_a_demand,
              test_a_cold_target_is_purged_when_only_the_deletion_hydrates,
              test_the_forward_leg_is_inert_under_total_demand, test_deletion_closure_is_flat,
              test_rows_rebuild_the_exact_bytes, test_a_damaged_row_is_a_miss_never_a_wrong_fact,
              test_repair_after_damage_redelivers, test_a_failed_write_propagates_and_tears_nothing,
              test_adds_are_durable_only_at_commit, test_a_zero_atom_fact_survives_the_reboot,
              test_fault_fixpoint_mirrors_kernel_covers, test_sql_providers_mirrors_covers,
              test_sql_suppressors_mirrors_covers):
        t(); print(f"ok  {t.__name__}")
    print("\nall tests passed")
