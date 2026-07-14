"""TinyP2P kernel: the atom model engine, one file (design: DESIGN.md).

Facts are the unit of identity, atoms the unit of matching, and needs/offers
are the whole fact language. The kernel owns exactly four things: canonical
identity, admission, matching, and the turn loop (which the host feeds `now`).
Everything else — sync, queues, effects, content, retention — is a fact family
under facts/; time alone is a turn primitive, not a family (see turn/now_need).
Two generic seams let a family own an index the kernel never reads: the
settle() hook (a family sees every verdict its facts settle to and folds it
into its register under regs — volatile, rebuilt by replay through the same
hook) and answer() (a family claims a reserved role and serves it itself).

Projectors ARE the routers: the kernel runs one root projector, and a Router
is just a projector that dispatches on the next type-tag segment. Extraction
routes through the same tree.

Derived state (validity memo, clean twin, frontier) is rebuildable
from the durable fact set alone. There is no replay: a stepped fact's needs
fault their cold matches resident from the Store (the persisted atom
relation), so boot is one total demand and a session pays for what it asks
about. The store answers existence, never standing.

Hash: BLAKE3-256 (the `blake3` package; stdlib has none).
"""
from collections import deque
from dataclasses import dataclass, replace
import sqlite3, time

try:
    from blake3 import blake3 as _b3
except ImportError as e:                 # the repo's one non-crypto-suite dependency
    raise ImportError("TinyP2P needs blake3 (pip install blake3)") from e

H = lambda b: _b3(b).digest()
now = lambda: int(time.time())           # host convenience; never engine input

def frame(*ps):                          # ‖ : length-framed concat (injective)
    assert all(len(p) < 2**32 for p in ps)
    return b"".join(len(p).to_bytes(4, "little") + p for p in ps)

def _rd(b, i):                           # read one frame, strict
    n = int.from_bytes(b[i:i + 4], "little"); j = i + 4 + n
    if j > len(b): raise ValueError("truncated")
    return b[i + 4:j], j

def unframe(b):                          # the dual of frame: every length-framed part in order
    out, i = [], 0
    while i < len(b): x, i = _rd(b, i); out.append(x)
    return out

# --- Canonical data -----------------------------------------------------------
NEED, OFFER = 0, 1
NONE, REQUIRE, WATCH, SUPPRESS = 0, 1, 2, 3
EXACT, SELF_T, RANGE = 0, 1, 2           # wire tags only; in memory a target is (lo, hi) or SELF
SELF = ()                                # "this fact's eventual FactId"
Exact = lambda b: (b, b)                 # a point is the degenerate range
Range = lambda lo, hi: (lo, hi)

@dataclass(frozen=True)
class Atom:
    kind: int; role: bytes; scope: bytes; target: tuple
    value: bytes = None; effect: int = NONE   # effect: needs only

def enc_atom(a):                         # the atom as one frame sequence: header ‖ role ‖ scope ‖ target-tail ‖ value?
    tt, tail = ((SELF_T, ()) if a.target == SELF else            # a point keeps the compact EXACT wire form
                (EXACT, a.target[:1]) if a.target[0] == a.target[1] else (RANGE, a.target))
    return frame(bytes([a.kind, a.effect, tt]), a.role, a.scope,
                 *tail, *(() if a.value is None else (a.value,)))

def dec_atom(b):                         # strict: parse leniently, then the re-encode must match byte-for-byte
    hdr, role, scope, *rest = unframe(b)
    kind, eff, tt = hdr                   # header is exactly (kind, effect, target-tag)
    if kind not in (NEED, OFFER) or eff > SUPPRESS or tt > RANGE: raise ValueError("bad tag")
    if kind == OFFER and eff != NONE: raise ValueError("effect on offer")
    if role[:1] == b"\x00" and (kind, eff) != (NEED, WATCH): raise ValueError("reserved role")
    n = (1, 0, 2)[tt]                     # target parts after the tag: EXACT 1, SELF 0, RANGE 2
    if len(rest) < n: raise ValueError("short target")
    a = Atom(kind, role, scope, SELF if not n else (rest[0], rest[n - 1]),
             rest[n] if len(rest) > n else None, eff)
    if enc_atom(a) != b: raise ValueError("non-canonical atom")   # extra/misplaced frames re-encode differently
    return a                              # (RANGE-form (v,v) re-encodes EXACT: rejected as non-canonical)

@dataclass(frozen=True)
class Fact:
    type_tag: bytes; atoms: tuple        # strictly increasing by encoding

def fact(tag, *atoms):                   # canonicalize: sort + dedup + validate
    return Fact(tag, tuple(dec_atom(e) for e in sorted({enc_atom(a) for a in atoms})))

DOMAIN = b"tinyp2p.fact.v1"                # the only dialect marker, forever
_blob = lambda f: b"".join(frame(enc_atom(a)) for a in f.atoms)
fact_id = lambda f: H(frame(DOMAIN, f.type_tag, _blob(f)))
encode = lambda f: frame(f.type_tag) + _blob(f)

def decode(b):                           # strict: reject anything non-canonical
    tag, *encs = unframe(b)              # ValueError on empty/truncated, as the hand-rolled loop did
    if any(x >= y for x, y in zip(encs, encs[1:])): raise ValueError("unsorted/dup")
    return Fact(tag, tuple(dec_atom(e) for e in encs))

# Canonical timestamp atom: 8-byte LE u64; a fact without one promotes at ts=0.
ts_atom = lambda t, scope=b"": Atom(OFFER, b"ts", scope, SELF, t.to_bytes(8, "little"))
ts_of = lambda f: next((int.from_bytes(a.value, "little")
                        for a in f.atoms if a.kind == OFFER and a.role == b"ts"), 0)

# --- Matching -------------------------------------------------------------------
def covers(off_t, need_t):               # one side is a point lying inside the other; SELF and span↔span never match
    if SELF in (off_t, need_t): return False
    return (need_t[0] == need_t[1] and off_t[0] <= need_t[0] <= off_t[1] or
            off_t[0] == off_t[1] and need_t[0] <= off_t[0] <= need_t[1])

# Materialization rule: every derived row rewrites SELF to the owner id.
mat = lambda a, fid: replace(a, target=Exact(fid)) if a.target == SELF else a
needs_of = lambda f, fid: [mat(a, fid) for a in f.atoms if a.kind == NEED]

# --- The projector contract ------------------------------------------------------
@dataclass
class Out:                               # project() -> verdict + all it may emit
    verdict: str = "Valid"               # Valid | Invalid
    offers: tuple = ()                   # engine restamps provenance regardless

by = lambda ctx, role: [r for n, rs in ctx.items() if n.role == role for r in rs]

# Time is a turn primitive: the host reads the clock from the OS and hands it to
# `turn(now)`, which presents it as a single transient offer at the NOW key. A
# time-waiting fact carries a Watch need over [deadline, ∞); when now reaches the
# deadline the offer falls in range and wakes it. Time is never stored, so nothing
# accumulates, and durable derived state never depends on now — a reboot at any
# now rebuilds it identically.
NOW_ROLE, NOW_SCOPE, _NOW = b"now", b"clock", b"\x00now"   # sentinel owner, not a fid
now_need = lambda deadline_ms: Atom(NEED, NOW_ROLE, NOW_SCOPE,
                                    Range(deadline_ms.to_bytes(8, "big"), b"\xff" * 8), effect=WATCH)
now_of = lambda ctx: next((int.from_bytes(r[2].target[1], "big") for r in by(ctx, NOW_ROLE)), None)

# The wire's flush report is the host's other transient signal, presented like
# `now`: the daemon presents shipped@Exact(fid) for each host-watched offer it
# flushed, and a sender Watching shipped@SELF wakes and decides its own
# retirement — Reap (a one-shot vanishes with no receipt) or re-arm a retry.
# Re-presented until the sender acts, so a bounded drain never drops it.
SHIPPED_ROLE, SHIPPED_SCOPE, _SHIP = b"shipped", b"wire", b"\x00ship"
shipped_need = Atom(NEED, SHIPPED_ROLE, SHIPPED_SCOPE, SELF, effect=WATCH)

# Reserved needs are answered the same transient way, but from indexes rather
# than the OS clock. The kernel itself answers two: `resident` (a fact id I
# already hold — the have/need pull seam) and the boot total below. A FAMILY
# claims any further reserved role via answer() — e.g. sync's `summary`
# (facts/sync/index.py) — so a family-owned index is read through the same seam
# without the kernel knowing its semantics. Reserved roles: the leading NUL
# cannot occur in a family role, so no family can author or collide with them;
# a reserved need is always WATCH and never gates. _answer (in _step) injects
# the rows into ctx exactly as valid_offers would, so `by(ctx, role)` reads
# them uniformly.
RES_ROLE, _RES = b"\x00resident", b"\x00res"

# The total demand is the whole boot story: one reserved Watch need whose key
# the fault leg reads as "every stored fact". Once checked, faulting is over —
# facts enter the store only via admission, so nothing cold appears behind it.
ALL_ROLE = b"\x00all"
FULL = Range(b"", b"\xff" * 64)         # the full-domain range Watch: covers any exact key
all_need = Atom(NEED, ALL_ROLE, b"store", FULL, effect=WATCH)
_ALL_KEY = (ALL_ROLE, b"store", all_need.target)

RESERVED = {RES_ROLE, ALL_ROLE}          # grows via answer(): registration is the census
ANSWERERS = {}                           # reserved role -> fn(node, need) -> ctx rows

def answer(role, fn):                    # a family claims a reserved role at import time
    assert role[:1] == b"\x00" and role not in (RES_ROLE, ALL_ROLE)
    ANSWERERS[role] = fn; RESERVED.add(role)

resident_need = lambda fid: Atom(NEED, RES_ROLE, b"sync", Exact(fid), effect=WATCH)

class Router:
    """A projector that dispatches on one type-tag segment and delegates whole.
    Routers narrow inputs and cannot widen a delegate's context; delegation
    must equal the delegate run alone (routing neutrality). Extraction —
    content-pure, decided at admission — routes through the same tree.
    Unknown tags are Durable + LocalOnly + Parked."""

    def __init__(self, routes, depth=0): self.routes, self.depth = routes, depth

    def _child(self, f):
        seg = f.type_tag.split(b".")
        return self.routes.get(seg[self.depth]) if len(seg) > self.depth else None

    def resolve(self, segs):             # dotted api/CLI path -> fact module
        c = self.routes.get(segs[self.depth]) if len(segs) > self.depth else None
        return c.resolve(segs) if isinstance(c, Router) else c

    def extract(self, f):                # -> (durable, shareable)
        c = self._child(f)
        return c.extract(f) if c else (True, False)

    def project(self, f, ctx):           # -> Out | None (None: no family, park)
        c = self._child(f)
        return c.project(f, ctx) if c else None

# --- The durable store --------------------------------------------------------------
class Store:
    """The persisted atom relation: one row per atom of every durable fact —
    canonical columns plus materialized match columns (SELF rewritten to the
    owner id). Facts are a derived view: a read regroups a fid's rows,
    rebuilds, re-encodes, and re-hashes, so rows that no longer add up to
    their fid are a miss, never a wrong fact. One write door — add(),
    downstream of admission — makes existence the persisted certificate:
    intrinsic checks ran once, and the re-hash transfers them, so a faulted
    fact re-enters checked. The store answers existence (owners, fact_bytes)
    and never standing: verdicts live in the engine alone. The coverage
    WHERE clause mirrors kernel `covers` (mirror-tested)."""

    _COV = (" AND ((ex=1 AND lo BETWEEN ? AND ?)"    # ex=const per arm: both index-narrowed
            " OR (ex=0 AND ? AND ? BETWEEN lo AND hi))")

    def __init__(self, path=":memory:"):
        self.db = sqlite3.connect(path)
        self.db.execute("PRAGMA busy_timeout=5000")  # tolerate brief lock contention
        self.db.execute("PRAGMA journal_mode=WAL")   # commit per turn without a full fsync
        self.db.execute("PRAGMA synchronous=NORMAL") # fsync at checkpoints, not every commit
        self.db.executescript("""
          CREATE TABLE IF NOT EXISTS facts(fid BLOB PRIMARY KEY, tag BLOB) WITHOUT ROWID;
          CREATE TABLE IF NOT EXISTS atoms(fid BLOB, kind INT, effect INT, role BLOB, scope BLOB,
                                           value BLOB, ex INT, lo BLOB, hi BLOB);
          CREATE INDEX IF NOT EXISTS match_ix ON atoms(kind, role, scope, ex, lo);
          CREATE INDEX IF NOT EXISTS owner_ix ON atoms(fid);""")

    def add(self, fb):                   # checked write: decode + derive EVERY row before the
        try:                             # first insert — bad BYTES are a miss...
            f = decode(fb); fid = fact_id(f)
            rows = [(fid, a.kind, a.effect, a.role, a.scope, a.value,
                     t[0] == t[1], t[0], t[1])
                    for a in f.atoms for t in (mat(a, fid).target,)]
        except Exception: return
        if not self.db.in_transaction: self.db.execute("BEGIN")   # one transaction per host
        self.db.execute("SAVEPOINT a")                            # turn: commit() ends it
        try:
            if self.db.execute("INSERT OR IGNORE INTO facts VALUES(?,?)", (fid, f.type_tag)).rowcount:
                self.db.executemany("INSERT INTO atoms VALUES(?,?,?,?,?,?,?,?,?)", rows)
            self.db.execute("RELEASE a")
        except BaseException:            # ...but a failed WRITE (SystemExit included) tears
            try: self.db.execute("ROLLBACK TO a"); self.db.execute("RELEASE a")
            except sqlite3.Error: pass   # (the tx may have auto-rolled-back beneath us)
            raise                        # propagate whole: the caller keeps it unflushed, retries

    def _mk(self, fid, tag, rows):       # regroup -> rebuild -> re-hash: the certificate check.
        try:                             # A fact never targets its own id (a hash fixpoint), so a
            f = fact(tag, *(Atom(k, r, s, SELF if lo == fid else (lo, hi), v, e)   # row at the owner id
                            for k, e, r, s, lo, hi, v in rows))                    # can only be SELF —
            return encode(f) if fact_id(f) == fid else None                        # and the re-hash certifies it
        except Exception: return None

    def fact_bytes(self, fid):           # the derived view: canonical bytes, or a miss
        t = self.db.execute("SELECT tag FROM facts WHERE fid=?", (fid,)).fetchone()
        rows = self.db.execute("SELECT kind, effect, role, scope, lo, hi, value"
                               " FROM atoms WHERE fid=?", (fid,)).fetchall()
        return self._mk(fid, t[0], rows) if t else None    # zero atom rows is legal: hash decides

    def owners(self, n):                 # existence: who offers at this (materialized) need's
        if n.role == ALL_ROLE:           # key — never standing. Total demand: every stored fact.
            return [r[0] for r in self.db.execute("SELECT fid FROM facts")]
        return [r[0] for r in self.db.execute(
            "SELECT DISTINCT fid FROM atoms WHERE kind=1 AND role=? AND scope=?" + self._COV,
            (n.role, n.scope, *n.target, n.target[0] == n.target[1], n.target[0]))]

    def delete(self, fid):               # cold-path purge: forget a fact's rows. The caller
        self.db.execute("DELETE FROM facts WHERE fid=?", (fid,))     # owns the node-side
        self.db.execute("DELETE FROM atoms WHERE fid=?", (fid,))     # discipline: refault().

    def commit(self): self.db.commit()   # host calls it: durable before the reply

# --- The match index ---------------------------------------------------------------
class Bucket:
    """One match bucket over rows whose LAST element is the atom: (owner, atom)
    in the asserted index (keyed by kind, role, scope), (owner, ts, atom) in the
    clean twin (keyed by role, scope). Point-target rows live in a dict keyed by
    the point (the common case: an O(1) lookup, not a scan of every same-key
    atom); the few span-target rows sit in a short list. covers() reduces, in
    BOTH match directions, to the same function of the query target — a point
    hits its bin plus any span over it; a span hits the points inside it — so
    one `match` serves offers_for, needs_for, and valid_offers alike. Iterable —
    `for o,t,a in bucket` — so watched() and derived() read it unchanged."""
    __slots__ = ("exact", "ranges")
    def __init__(self): self.exact, self.ranges = {}, []      # point -> [row] ; [row]

    def add(self, r):
        t = r[-1].target
        (self.exact.setdefault(t[0], []) if t[0] == t[1] else self.ranges).append(r)
    def remove(self, r):
        t = r[-1].target
        if t[0] == t[1]:
            lst = self.exact.get(t[0])
            if lst and r in lst:
                lst.remove(r)
                if not lst: del self.exact[t[0]]
        elif r in self.ranges: self.ranges.remove(r)

    def match(self, t):                  # the rows a query target `t` covers-matches (either direction)
        lo, hi = t                       # (query targets are materialized: never SELF)
        if lo == hi:                     # a point: its bin, plus every span that covers it
            return (list(self.exact.get(lo, ()))
                    + [r for r in self.ranges if r[-1].target[0] <= lo <= r[-1].target[1]])
        return [r for v, rs in self.exact.items() if lo <= v <= hi for r in rs]
    def __iter__(self):                  # every row, in no particular order — for watched() and derived()
        return iter([r for rs in self.exact.values() for r in rs] + self.ranges)
    def __len__(self):
        return sum(len(rs) for rs in self.exact.values()) + len(self.ranges)
    def __bool__(self):                  # truthiness is presence, O(1) — `b.match(t) if b else []`
        return bool(self.exact) or bool(self.ranges)   # must never pay the linear count

# --- The engine --------------------------------------------------------------------
class Node:
    """One engine over one root projector. Durable authority = self.durable
    (canonical bytes, 'the disk'); memo/clean/frontier are derived.
    With a store, residency is demand-driven: a stepped fact's needs fault
    their cold matches resident through ordinary admission — residency is
    the fixpoint of demand, and boot is the degenerate case (one total
    need). The store answers existence, never standing: verdicts are
    computed here, over the resident set, and only here."""

    def __init__(self, root, store=None):
        self.root, self.store = root, store
        self.checked = set()                 # need keys already faulted: existence is monotone
                                             # (rows enter the store only via resident facts)
        self.facts, self.durable = {}, {}    # id -> Fact ; id -> canonical bytes
        # Match index bucketed by (kind, role, scope): a need only ever matches
        # offers sharing its role+scope, so one bucket is the whole candidate
        # set. Each bucket then indexes exact targets by value, so a point query
        # is an O(1) lookup, never a scan of every same-role atom.
        self.rows = {}                       # (kind,role,scope) -> Bucket: the asserted match index
        self.memo, self.clean = {}, {}       # id -> verdict ; (role,scope) -> [(owner, ts, atom)]
        self.owned = {}                      # id -> its clean rows, for owner-scoped replacement
        self.regs = {}                       # scope -> one shared mutable register per family group, written
                                             # by settle() hooks; volatile derived state, rebuilt by replay
        self.frontier = deque()              # FIFO of fids to (re)step
        self._queued = set()                 # membership mirror of the frontier: O(1) dedup ('in' on a deque is O(n))
        self.purged = []                     # durable fids a terminal verdict evicted, for the host's
                                             # flush bookkeeping (a purged fid is no longer "on disk")

    # Host in — admission gates; a failed gate is inert. checked=True (replay
    # from own durable file) skips the family self-check: those bytes passed once.
    def admit(self, b, expect=None, checked=False):
        try: f = decode(b)
        except Exception: return None
        fid = fact_id(f)
        if expect not in (None, fid): return None
        if fid in self.facts: return fid     # idempotent admission
        chk = None if checked else getattr(self.root.resolve(f.type_tag.split(b".")), "check", None)
        if chk and not chk(f): return None   # per-family self-check: falsy = inert miss
        durable, _shareable = self.root.extract(f)
        self.facts[fid], self.memo[fid] = f, "Unknown"
        if durable: self.durable[fid] = b
        for a in f.atoms:
            self.rows.setdefault((a.kind, a.role, a.scope), Bucket()).add((fid, mat(a, fid)))
        self._enqueue(fid)
        return fid

    # A shared role+scope is the whole precondition for a match, so it keys the
    # bucket; the bucket's own index decides the rest over just the candidates a
    # point/range can touch — the same covers() relation, without the linear scan.
    def offers_for(self, need):          # asserted, dirty: discovery only
        b = self.rows.get((OFFER, need.role, need.scope)); return b.match(need.target) if b else []
    def needs_for(self, offer):          # wake fanout direction
        b = self.rows.get((NEED, offer.role, offer.scope)); return b.match(offer.target) if b else []
    def valid_offers(self, need):        # the clean twin: the only justifier — a point/range lookup, not a scan
        b = self.clean.get((need.role, need.scope)); return b.match(need.target) if b else []

    def _enqueue(self, fid):             # add to the frontier iff not already pending (mirror keeps 'in' O(1))
        if fid not in self._queued: self.frontier.append(fid); self._queued.add(fid)

    def _wake(self, offer, skip=None):   # re-enqueue every need this offer covers (never its own owner)
        for o, _ in self.needs_for(offer):
            if o != skip: self._enqueue(o)

    def deps(self, fid):                 # fid's direct Require/suppress edge owners: its dependency spine.
        f = self.facts.get(fid)          # STRUCTURAL/asserted (from offers_for), NOT validity-gated — decided in _step
        return frozenset() if f is None else frozenset(
            o for n in needs_of(f, fid) if n.effect in (REQUIRE, SUPPRESS)
            for o, _ in self.offers_for(n))

    def closure(self, fid, out=None):    # transitive deps (requires + suppressors), incl fid — the sync spine.
        out = set() if out is None else out          # a shared visited-set across leaves dedups the union closure
        if fid in out: return out
        out.add(fid)
        for d in self.deps(fid): self.closure(d, out)
        return out

    def refault(self):                   # the relation changed underneath (delete + re-add):
        self.checked.clear()             # forget the fault memos and re-step every resident
        for fid in self.facts: self._enqueue(fid)     # fact, so their keys re-check the store

    # Engine-answered needs: a reserved index need is answered from an index and
    # injected into ctx as clean-twin-shaped (owner, ts, atom) rows, exactly the
    # way valid_offers answers an ordinary need, so `by(ctx, role)` reads them
    # uniformly. The kernel answers its own (resident); a registered family
    # answerer serves the rest. Everything else falls through to the clean twin.
    def _answer(self, n):
        if n.role == RES_ROLE: return self._resident_rows(n)
        if (fn := ANSWERERS.get(n.role)): return fn(self, n)
        return self.valid_offers(n)

    def _resident_rows(self, n):         # answered iff I already hold the fact — the have/need pull seam
        fid = n.target[1]
        return [(_RES, 0, Atom(OFFER, b"resident", b"sync", Exact(fid)))] if fid in self.durable else []

    # A host signal is one transient clean-twin slot, replaced each turn (nothing
    # accumulates), waking every need the offers now cover: `now` is the OS clock
    # at the NOW key, waking a time-waiting need whose deadline it reaches;
    # `shipped` is the daemon's flush reports at the SHIPPED key, waking a sender
    # Watching shipped@SELF to decide its own retirement.
    def _present(self, role, scope, rows):
        b = Bucket()
        for r in rows: b.add(r)
        self.clean[(role, scope)] = b
        for _, _, off in rows: self._wake(off)

    # Engine drain — bounded; overflow parks on the frontier, never drops.
    def turn(self, now=None, shipped=(), bound=64):
        if now is not None:                          # the host hands time to the turn
            self._present(NOW_ROLE, NOW_SCOPE, [(_NOW, now,
                          Atom(OFFER, NOW_ROLE, NOW_SCOPE, Exact(now.to_bytes(8, "big"))))])
        self._present(SHIPPED_ROLE, SHIPPED_SCOPE,   # and the wire hands back its flush reports
                      [(_SHIP, 0, Atom(OFFER, SHIPPED_ROLE, SHIPPED_SCOPE, Exact(fid))) for fid in shipped])
        for _ in range(min(bound, len(self.frontier))):
            fid = self.frontier.popleft(); self._queued.discard(fid)
            self._step(fid)

    def run(self):
        for _ in range(100_000):
            if not self.frontier: return self
            self.turn()
        raise RuntimeError("no quiescence")

    def _step(self, fid):
        if fid not in self.facts: return
        f = self.facts[fid]; ns = needs_of(f, fid)
        if self.store and _ALL_KEY not in self.checked:   # a checked total covers every key
            for n in ns:                                  # the fault leg: each need key is
                k = (n.role, n.scope, n.target)           # checked once; cold owners re-enter
                if k in self.checked: continue            # through admission, and their own
                self.checked.add(k)                       # needs fault in turn — the step
                for o in self.store.owners(n):            # loop IS the closure walk.
                    if o not in self.facts and (b := self.store.fact_bytes(o)):
                        self.admit(b, checked=True)
        # Precedence (ratified): Suppress > Require(Park) > Resolve. Reserved
        # index needs never reach here — decode pins a NUL role to a WATCH need.
        fam = self.root.resolve(f.type_tag.split(b"."))
        if any(self.valid_offers(n) for n in ns if n.effect == SUPPRESS):
            out = Out("Suppressed")
        elif any(not self.valid_offers(n) for n in ns if n.effect == REQUIRE):
            out = Out("Parked")
        else:                            # Context<Validated>; Watch never gates. Reserved index needs are
            ctx = {n: self._answer(n) for n in ns if n.effect in (REQUIRE, WATCH)}   # answered from the engine
            out = self.root.project(f, ctx) or Out("Parked")
        self._promote(fid, f, out, fam)

    def _promote(self, fid, f, out, fam=None):
        self.memo[fid] = out.verdict
        # The family lifecycle hook: a family that declares settle() sees every
        # verdict its fact settles to — including Suppressed and Parked, which
        # never reach project() — and maintains derived group state from it
        # (e.g. sync's leaf membership, whose minus side needs the verdict).
        if fam is not None and (hook := getattr(fam, "settle", None)):
            hook(self, fid, f, out.verdict)
        # Owner-scoped replacement: pull this fact's current rows from their
        # buckets, add the new ones — old and new output are never both visible.
        old = self.owned.pop(fid, [])
        for r in old: self.clean[(r[2].role, r[2].scope)].remove(r)
        new = ([(fid, ts_of(f), mat(a, fid)) for a in out.offers]
               if out.verdict == "Valid" else [])
        for r in new: self.clean.setdefault((r[2].role, r[2].scope), Bucket()).add(r)
        if new: self.owned[fid] = new
        for _, _, a in set(old) ^ set(new):   # wake fanout on every changed offer (never re-wake self)
            self._wake(a, fid)
        # Terminal verdicts evict the whole body — resident fact, memo, asserted
        # rows, durable bytes — leaving no residue. Suppression keeps the
        # RELATIONSHIP, never the husk: the suppressor and the death keys it
        # matches are durable facts, so a purged fact that re-arrives (a laggard
        # peer re-ships it) re-derives Suppressed and dies on arrival. Deletion
        # is immediate and real; what remains of a deleted fact is only the edge
        # that deleted it. (No guard for Suppressed: withdrawing offers others
        # gate on is the point — dependents park, or die by their own death key.)
        if out.verdict == "Reap":            # guard: never reap an offer another fact gates on
            for r in old:
                for o, na in self.needs_for(r[2]):
                    assert o == fid or na.effect not in (REQUIRE, SUPPRESS), "reap of a gating offer"
        if out.verdict in ("Reap", "Suppressed"):
            self.facts.pop(fid, None); self.memo.pop(fid, None)
            for a in f.atoms:                # drop its asserted rows so nothing re-wakes it
                if bk := self.rows.get((a.kind, a.role, a.scope)): bk.remove((fid, mat(a, fid)))
            if self.durable.pop(fid, None):  # physical deletion; the host un-marks it as flushed
                self.purged.append(fid)
                if self.store: self.store.delete(fid)

    # Host out — the host drains validated offers at keys it watches, performs
    # external work, and admits facts reporting what happened. It never writes.
    def watched(self, role, scope):
        return list(self.clean.get((role, scope), ()))

    # Crash story: derived state is a pure, order-independent function of the
    # durable set — a fresh node over the same store, seeded with one total
    # demand, rebuilds it. Volatile facts vanish — completeness, never coherence.
    def derived(self):
        return (sorted((o, t, enc_atom(a)) for rs in self.clean.values() for o, t, a in rs),
                sorted(self.memo.items()))
