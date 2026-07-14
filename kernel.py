"""TinyP2P kernel: the atom model engine, one file (design: DESIGN.md).

The kernel exists to keep one answer current — which facts are valid, and
what do they offer — from nothing but durable fact bytes and the signals the
host hands each turn. Everything in this file serves that answer: naming
facts unforgeably, letting only genuine ones in, matching needs to offers,
and re-judging a fact whenever the offers it depends on change.

The vocabulary: a Fact is the unit of identity — an immutable set of atoms,
named by the hash of its canonical bytes. An Atom is the unit of matching —
a need or an offer at a (role, scope) key. Needs and offers are the whole
fact language: a fact can state nothing else, and an offer counts only
while its owner's verdict is Valid.

The story of one fact:
  1. admit()    the one door in: decode strictly, name the fact by its
                bytes, self-check via its family, index its atoms, queue it.
  2. turn()     the host hands in the clock and the wire's flush reports;
                the engine judges up to `bound` queued facts.
  3. _step()    judge one fact: fault its cold matches in from the Store,
                gate (a matched Suppress kills, an unmet Require parks),
                else hand the fact and the validated answers to its needs
                to its family's project(), which returns the verdict.
  4. _settle()  make the verdict real: memo it, atomically publish or
                withdraw the fact's offers, notify registered observers,
                wake every fact those changed offers answer (back to step
                3), and on a terminal verdict erase the fact whole (_evict).
  5. watched()  the one door out: the host reads validated offers at keys
                it watches, does the external work, and admits new facts
                reporting what happened.

Who owns what: the kernel owns identity, admission, matching, and the turn
loop — and knows no domain. Fact families under facts/ own all judgment
(project()), plus two seams for family state the kernel never reads:
observe() (fold validated offer deltas into a register under regs) and
answer() (serve a reserved role from a family index). The Store owns
existence only — durable atoms, "who offers at this key" — never standing.
The host owns time and effects: it feeds turn(), drains watched(), performs
the I/O; it never writes engine state. Projectors ARE the routers: the kernel
runs one root projector, and a Router is just a projector that dispatches on
the next type-tag segment; extraction routes through the same tree.

Derived state (validity memo, clean twin, frontier) is rebuildable from the
durable fact set alone. There is no replay: a stepped fact's needs fault
their cold matches resident from the Store, so boot is one total demand and
a session pays for what it asks about.

Hash: BLAKE3-256 (the `blake3` package; stdlib has none).
"""
from collections import deque, namedtuple
from dataclasses import dataclass, replace
import sqlite3, time

try:
    from blake3 import blake3 as _b3
except ImportError as e:                 # the repo's one non-crypto-suite dependency
    raise ImportError("TinyP2P needs blake3 (pip install blake3)") from e

H = lambda b: _b3(b).digest()
now = lambda: int(time.time())           # host convenience; never engine input

# Framing: injective concat — distinct structures never share bytes, which is
# what lets the hash of a fact's bytes serve as its name.
def frame(*ps):                          # ‖ : length-framed concat
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
# This makes identity a pure function of one canonical byte encoding.
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
    if a.target == SELF:                tt, tail = SELF_T, ()
    elif a.target[0] == a.target[1]:    tt, tail = EXACT, a.target[:1]    # a point keeps the compact EXACT wire form
    else:                               tt, tail = RANGE, a.target
    return frame(bytes([a.kind, a.effect, tt]), a.role, a.scope,
                 *tail, *(() if a.value is None else (a.value,)))

def dec_atom(b):                         # strict: parse leniently, then the re-encode must match byte-for-byte
    hdr, role, scope, *rest = unframe(b)
    kind, eff, tt = hdr                   # header is exactly (kind, effect, target-tag)
    if kind not in (NEED, OFFER) or eff > SUPPRESS or tt > RANGE: raise ValueError("bad tag")
    if kind == OFFER and eff != NONE: raise ValueError("effect on offer")
    if role[:1] == b"\x00" and (kind, eff) != (NEED, WATCH): raise ValueError("reserved role")
    parts = (1, 0, 2)[tt]                 # target frames after the header: EXACT 1, SELF 0, RANGE 2
    if len(rest) < parts: raise ValueError("short target")
    if tt == SELF_T:   target = SELF
    elif tt == EXACT:  target = Exact(rest[0])
    else:              target = Range(rest[0], rest[1])
    a = Atom(kind, role, scope, target, rest[parts] if len(rest) > parts else None, eff)
    if enc_atom(a) != b: raise ValueError("non-canonical atom")   # extra/misplaced frames re-encode differently
    return a                              # (RANGE-form (v,v) re-encodes EXACT: rejected as non-canonical)

@dataclass(frozen=True)
class Fact:
    type_tag: bytes; atoms: tuple        # strictly increasing by encoding

def fact(tag, *atoms):                   # canonicalize: sort + dedup + validate
    return Fact(tag, tuple(dec_atom(e) for e in sorted({enc_atom(a) for a in atoms})))

DOMAIN = b"tinyp2p.fact.v1"                # the only dialect marker, forever
_blob = lambda f: b"".join(frame(enc_atom(a)) for a in f.atoms)
def fact_id(f): return H(frame(DOMAIN, f.type_tag, _blob(f)))
def encode(f): return frame(f.type_tag) + _blob(f)

def decode(b):                           # strict: reject anything non-canonical
    tag, *encs = unframe(b)              # ValueError on empty/truncated
    if any(x >= y for x, y in zip(encs, encs[1:])): raise ValueError("unsorted/dup")
    return Fact(tag, tuple(dec_atom(e) for e in encs))

# Canonical timestamp atom: 8-byte LE u64; a fact without one promotes at ts=0.
ts_atom = lambda t, scope=b"": Atom(OFFER, b"ts", scope, SELF, t.to_bytes(8, "little"))
def ts_of(f):
    return next((int.from_bytes(a.value, "little")
                 for a in f.atoms if a.kind == OFFER and a.role == b"ts"), 0)

# --- Matching -------------------------------------------------------------------
# This materializes self references and decides which atom targets meet.
def covers(off_t, need_t):               # SELF and span↔span never match; else a match is one
    if SELF in (off_t, need_t): return False                # side being a point inside the other
    if need_t[0] == need_t[1]: return off_t[0] <= need_t[0] <= off_t[1]   # point need in the offer's span
    if off_t[0] == off_t[1]: return need_t[0] <= off_t[0] <= need_t[1]    # point offer in the need's span
    return False

# Materialization rule: every derived row rewrites SELF to the owner id.
def mat(a, fid): return replace(a, target=Exact(fid)) if a.target == SELF else a
def needs_of(f, fid): return [mat(a, fid) for a in f.atoms if a.kind == NEED]

# The one row shape, everywhere a matched atom travels with its owner — both
# match indexes, ctx, watched(). Asserted rows carry ts=0: ts is only ever
# read off clean rows, where settlement stamps ts_of(owner).
Row = namedtuple("Row", "owner ts atom")

# --- Projector contract ----------------------------------------------------------
# This defines what families may return and how each verdict changes standing.
# The verdict alphabet — who says it, and what _settle does with it:
#   Unknown             seeded at admit(): a fact not yet stepped
#   Valid               family: publish out.offers to the clean twin
#   Invalid | Parked    family / engine (unmet Require, or no family): withdraw
#                       offers; the fact stays resident and can re-step
#   Suppressed | Reap   engine (matched Suppress) / family (e.g. a shipped
#                       one-shot): terminal — evict the body and durable bytes
UNKNOWN, VALID, INVALID, PARKED, SUPPRESSED, REAP = (
    "Unknown", "Valid", "Invalid", "Parked", "Suppressed", "Reap")

@dataclass
class Out:                               # project() -> verdict + all it may emit
    verdict: str = VALID
    offers: tuple = ()                   # engine restamps provenance regardless

def by(ctx, role): return [r for n, rs in ctx.items() if n.role == role for r in rs]

# --- Host signals & reserved roles -------------------------------------------------
# This turns clocks, flush reports, and reserved indexes into context rows.
# Roles no ordinary projection answers. Host signals arrive through turn() as
# one transient clean-twin slot each; reserved roles (leading NUL — decode pins
# them to NEED+WATCH, so no family can author or collide with one, and they
# never gate) are answered from indexes by _answer(), injected into ctx exactly
# as valid_offers would be, so `by(ctx, role)` reads every kind uniformly.
#
#   role           scope   answered from                       wakes / serves
#   now            clock   the OS clock, via turn(now=…)       time-waiting needs whose deadline arrived
#   shipped        wire    the daemon's flush report, turn()   senders Watching shipped@SELF
#   \x00resident   sync    the kernel: fid residency           the have/need pull seam
#   \x00all        store   the fault leg (boot total demand)   every stored fact, once
#   \x00<family>   …       a family answer() registrant        a family-owned index (e.g. sync's summary)

# Time is a turn primitive: never stored, so nothing accumulates and durable
# derived state never depends on now — a reboot at any now rebuilds it
# identically. A time-waiting fact carries a Watch need over [deadline, ∞);
# when now reaches the deadline the offer falls in range and wakes it.
NOW_ROLE, NOW_SCOPE, _NOW = b"now", b"clock", b"\x00now"   # sentinel owner, not a fid
now_need = lambda deadline_ms: Atom(NEED, NOW_ROLE, NOW_SCOPE,
                                    Range(deadline_ms.to_bytes(8, "big"), b"\xff" * 8), effect=WATCH)
def now_of(ctx):
    return next((int.from_bytes(r.atom.target[1], "big") for r in by(ctx, NOW_ROLE)), None)

# A woken sender decides its own retirement — Reap (a one-shot vanishes with
# no receipt) or re-arm a retry. Flush reports are re-presented until the
# sender acts, so a bounded drain never drops one.
SHIPPED_ROLE, SHIPPED_SCOPE, _SHIP = b"shipped", b"wire", b"\x00ship"
shipped_need = Atom(NEED, SHIPPED_ROLE, SHIPPED_SCOPE, SELF, effect=WATCH)

RES_ROLE, _RES = b"\x00resident", b"\x00res"
resident_need = lambda fid: Atom(NEED, RES_ROLE, b"sync", Exact(fid), effect=WATCH)

# The total demand is the whole boot story: one reserved Watch need whose key
# the fault leg reads as "every stored fact". Once checked, faulting is over —
# facts enter the store only via admission, so nothing cold appears behind it.
ALL_ROLE = b"\x00all"
FULL = Range(b"", b"\xff" * 64)         # the full-domain range Watch: covers any exact key
all_need = Atom(NEED, ALL_ROLE, b"store", FULL, effect=WATCH)
_ALL_KEY = (ALL_ROLE, b"store", all_need.target)

RESERVED = {RES_ROLE, ALL_ROLE}          # grows via answer(): registration is the census
ANSWERERS = {}                           # reserved role -> fn(node, need) -> ctx rows
OBSERVERS = {}                           # (role, scope) -> [fn(node, before_rows, after_rows)]

def answer(role, fn):                    # a family claims a reserved role at import time
    assert role[:1] == b"\x00" and role not in (RES_ROLE, ALL_ROLE)
    ANSWERERS[role] = fn; RESERVED.add(role)

def observe(role, scope, fn):             # a family indexes one validated offer address
    OBSERVERS.setdefault((role, scope), []).append(fn)

class Router:
    """A projector that dispatches on one type-tag segment and delegates whole.
    Routers narrow inputs and cannot widen a delegate's context; delegation
    must equal the delegate run alone (routing neutrality). Extraction —
    content-pure durability, decided at admission — routes through the same
    tree. Unknown tags are Durable + Parked and project no offers."""

    def __init__(self, routes, depth=0): self.routes, self.depth = routes, depth

    def _child(self, f):
        seg = f.type_tag.split(b".")
        return self.routes.get(seg[self.depth]) if len(seg) > self.depth else None

    def resolve(self, segs):             # dotted api/CLI path -> fact module
        c = self.routes.get(segs[self.depth]) if len(segs) > self.depth else None
        return c.resolve(segs) if isinstance(c, Router) else c

    def extract(self, f):                # -> durable
        c = self._child(f)
        return c.extract(f) if c else True

    def project(self, f, ctx):           # -> Out | None (None: no family, park)
        c = self._child(f)
        return c.project(f, ctx) if c else None

# --- Store -----------------------------------------------------------------------
# This persists admitted atoms and reconstructs only bytes that still hash true.
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

    def add(self, fb):
        """Checked write: decode and derive EVERY row before the first insert,
        so bad bytes are a silent miss. A failed write (SystemExit included)
        tears the savepoint and propagates whole: the caller keeps the fact
        unflushed and retries."""
        try:
            f = decode(fb); fid = fact_id(f)
            rows = [(fid, a.kind, a.effect, a.role, a.scope, a.value,
                     t[0] == t[1], t[0], t[1])
                    for a in f.atoms for t in (mat(a, fid).target,)]
        except Exception: return
        if not self.db.in_transaction: self.db.execute("BEGIN")   # one transaction per host turn:
        self.db.execute("SAVEPOINT a")                            # commit() ends it
        try:
            if self.db.execute("INSERT OR IGNORE INTO facts VALUES(?,?)", (fid, f.type_tag)).rowcount:
                self.db.executemany("INSERT INTO atoms VALUES(?,?,?,?,?,?,?,?,?)", rows)
            self.db.execute("RELEASE a")
        except BaseException:
            try: self.db.execute("ROLLBACK TO a"); self.db.execute("RELEASE a")
            except sqlite3.Error: pass   # (the tx may have auto-rolled-back beneath us)
            raise

    def _mk(self, fid, tag, rows):
        """Regroup -> rebuild -> re-hash: the certificate check. A fact never
        targets its own id (a hash fixpoint), so a stored row targeting the
        owner id can only be a materialized SELF — and the re-hash certifies
        the rewrite back."""
        try:
            f = fact(tag, *(Atom(k, r, s, SELF if lo == fid else (lo, hi), v, e)
                            for k, e, r, s, lo, hi, v in rows))
            return encode(f) if fact_id(f) == fid else None
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

# --- Bucket ----------------------------------------------------------------------
# This narrows point/range matching to only the rows a query can touch.
class Bucket:
    """One match bucket of Rows sharing an index key — (kind, role, scope) in
    the asserted index, (role, scope) in the clean twin. Point-target rows
    live in a dict keyed by the point (the common case: an O(1) lookup, not a
    scan of every same-key atom); the few span-target rows sit in a short
    list. covers() reduces, in BOTH match directions, to the same function of
    the query target — a point hits its bin plus any span over it; a span
    hits the points inside it — so one `match` serves offers_for, needs_for,
    and valid_offers alike. Iterable — every row, in no particular order —
    for watched() and derived()."""
    __slots__ = ("exact", "ranges")
    def __init__(self): self.exact, self.ranges = {}, []      # point -> [Row] ; [Row]

    def add(self, r):
        t = r.atom.target
        (self.exact.setdefault(t[0], []) if t[0] == t[1] else self.ranges).append(r)
    def remove(self, r):
        t = r.atom.target
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
                    + [r for r in self.ranges if r.atom.target[0] <= lo <= r.atom.target[1]])
        return [r for v, rs in self.exact.items() if lo <= v <= hi for r in rs]
    def __iter__(self):                  # every row, in no particular order — for watched() and derived()
        return iter([r for rs in self.exact.values() for r in rs] + self.ranges)
    def __len__(self):
        return sum(len(rs) for rs in self.exact.values()) + len(self.ranges)
    def __bool__(self):                  # truthiness is presence, O(1) — `b.match(t) if b else []`
        return bool(self.exact) or bool(self.ranges)   # must never pay the linear count

# --- Node ------------------------------------------------------------------------
# This carries resident facts from admission to observable validated offers.
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
        # Durable authority; everything below it is derived, rebuildable from
        # the durable set (plus the store) alone.
        self.durable = {}                    # id -> canonical bytes: 'the disk'
        # The resident set and its derived indexes.
        self.facts = {}                      # id -> Fact (resident: durable + volatile)
        self.rows = {}                       # (kind,role,scope) -> Bucket: the asserted match index
        self.memo, self.clean = {}, {}       # id -> verdict ; (role,scope) -> Bucket: the clean twin
        self.owned = {}                      # id -> its clean rows, for owner-scoped replacement
        self.regs = {}                       # scope -> one shared mutable register per family group, written
                                             # by offer observers; volatile derived state, rebuilt by replay
        self.checked = set()                 # need keys already faulted: existence is monotone
                                             # (rows enter the store only via resident facts)
        # Turn machinery and host bookkeeping.
        self.frontier = deque()              # FIFO of fids to (re)step
        self._queued = set()                 # membership mirror of the frontier: O(1) dedup ('in' on a deque is O(n))
        self.purged = []                     # durable fids a terminal verdict evicted, for the host's
                                             # flush bookkeeping (a purged fid is no longer "on disk")

    # --- The way in (admit) -----------------------------------------------------
    # This accepts one canonical fact, indexes it, and queues its first judgment.
    # A failed gate is inert. checked=True (replay from own durable file) skips
    # the family self-check: those bytes passed once.
    def admit(self, b, expect=None, checked=False):
        try: f = decode(b)
        except Exception: return None
        fid = fact_id(f)
        if expect not in (None, fid): return None
        if fid in self.facts: return fid     # idempotent admission
        chk = None if checked else getattr(self.root.resolve(f.type_tag.split(b".")), "check", None)
        if chk and not chk(f): return None   # per-family self-check: falsy = inert miss
        durable = self.root.extract(f)
        self.facts[fid], self.memo[fid] = f, UNKNOWN
        if durable: self.durable[fid] = b
        for a in f.atoms:
            self.rows.setdefault((a.kind, a.role, a.scope), Bucket()).add(Row(fid, 0, mat(a, fid)))
        self._enqueue(fid)
        return fid

    # --- The index queries ------------------------------------------------------
    # This answers asserted discovery, validated standing, and reserved lookups.
    # A shared role+scope is the whole precondition for a match, so it keys the
    # bucket; the bucket's own index narrows the point/range candidates.
    def offers_for(self, need):          # asserted, dirty: discovery only
        b = self.rows.get((OFFER, need.role, need.scope)); return b.match(need.target) if b else []
    def needs_for(self, offer):          # wake fanout direction
        b = self.rows.get((NEED, offer.role, offer.scope)); return b.match(offer.target) if b else []
    def valid_offers(self, need):        # the clean twin: the only justifier
        b = self.clean.get((need.role, need.scope)); return b.match(need.target) if b else []

    # Reserved index needs (see the census above): the kernel answers resident
    # itself, a registered family answerer serves the rest, and everything
    # else falls through to the clean twin.
    def _answer(self, n):
        if n.role == RES_ROLE: return self._resident_rows(n)
        if (fn := ANSWERERS.get(n.role)): return fn(self, n)
        return self.valid_offers(n)

    def _resident_rows(self, n):         # answered iff I already hold the fact — the have/need pull seam
        fid = n.target[1]
        return [Row(_RES, 0, Atom(OFFER, b"resident", b"sync", Exact(fid)))] if fid in self.durable else []

    # --- The turn loop (turn / run / _step / _fault) ---------------------------
    # This presents host signals, judges the frontier, and faults cold matches.
    def turn(self, now=None, shipped=(), bound=64):
        if now is not None:                          # the host hands time to the turn
            self._present(NOW_ROLE, NOW_SCOPE, [Row(_NOW, now,
                          Atom(OFFER, NOW_ROLE, NOW_SCOPE, Exact(now.to_bytes(8, "big"))))])
        self._present(SHIPPED_ROLE, SHIPPED_SCOPE,   # and the wire hands back its flush reports
                      [Row(_SHIP, 0, Atom(OFFER, SHIPPED_ROLE, SHIPPED_SCOPE, Exact(fid))) for fid in shipped])
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
        self._fault(ns)
        # Precedence (ratified): Suppress > Require(Park) > Resolve. Reserved
        # index needs never reach here — decode pins a NUL role to a WATCH need.
        if any(self.valid_offers(n) for n in ns if n.effect == SUPPRESS):
            out = Out(SUPPRESSED)
        elif any(not self.valid_offers(n) for n in ns if n.effect == REQUIRE):
            out = Out(PARKED)
        else:                            # Context<Validated>; Watch never gates. Reserved index needs are
            ctx = {n: self._answer(n) for n in ns if n.effect in (REQUIRE, WATCH)}   # answered from the engine
            out = self.root.project(f, ctx) or Out(PARKED)
        self._settle(fid, f, out)

    def _fault(self, ns):
        """The fault leg: each need key is checked against the store once (a
        checked total covers every key). Cold owners re-enter through ordinary
        admission, and their own needs fault in turn — the step loop IS the
        closure walk."""
        if not self.store or _ALL_KEY in self.checked: return
        for n in ns:
            k = (n.role, n.scope, n.target)
            if k in self.checked: continue
            self.checked.add(k)
            for o in self.store.owners(n):
                if o not in self.facts and (b := self.store.fact_bytes(o)):
                    self.admit(b, checked=True)

    # A host signal is one transient clean-twin slot, replaced each turn
    # (nothing accumulates), waking every need its offers now cover.
    def _present(self, role, scope, rows):
        b = Bucket()
        for r in rows: b.add(r)
        self.clean[(role, scope)] = b
        for r in rows: self._wake(r.atom)

    def _enqueue(self, fid):             # add iff not already pending; the set keeps membership O(1)
        if fid not in self._queued: self.frontier.append(fid); self._queued.add(fid)

    def _wake(self, offer, skip=None):   # re-enqueue every need this offer covers (never its own owner)
        for r in self.needs_for(offer):
            if r.owner != skip: self._enqueue(r.owner)

    def refault(self):                   # the relation changed underneath (delete + re-add):
        self.checked.clear()             # forget the fault memos and re-step every resident
        for fid in self.facts: self._enqueue(fid)     # fact, so their keys re-check the store

    # --- Making a verdict real (_settle / _evict) ------------------------------
    # This records standing, replaces validated offers, notifies observers,
    # wakes dependents, and evicts terminals.
    def _settle(self, fid, f, out):
        self.memo[fid] = out.verdict
        # Owner-scoped replacement: pull this fact's current rows from their
        # buckets, add the new ones — old and new output are never both visible.
        old = self.owned.pop(fid, [])
        for r in old: self.clean[(r.atom.role, r.atom.scope)].remove(r)
        new = ([Row(fid, ts_of(f), mat(a, fid)) for a in out.offers]
               if out.verdict == VALID else [])
        for r in new: self.clean.setdefault((r.atom.role, r.atom.scope), Bucket()).add(r)
        if new: self.owned[fid] = new
        # Family indexes subscribe to validated offer addresses, not fact tags
        # or verdicts. This runs after atomic clean replacement but before wake
        # fanout, so a consumer woken by the delta sees the matching register.
        addresses = {(r.atom.role, r.atom.scope) for r in old + new}
        for address in addresses:
            before = tuple(r for r in old if (r.atom.role, r.atom.scope) == address)
            after = tuple(r for r in new if (r.atom.role, r.atom.scope) == address)
            if set(before) != set(after):
                for hook in OBSERVERS.get(address, ()):
                    hook(self, before, after)
        for r in set(old) ^ set(new):    # wake fanout on every changed offer (never re-wake self)
            self._wake(r.atom, fid)
        if out.verdict in (REAP, SUPPRESSED): self._evict(fid, f, out.verdict, old)

    def _evict(self, fid, f, verdict, old):
        """A terminal verdict evicts the whole body — resident fact, memo,
        asserted rows, durable bytes — leaving no residue. Suppression keeps
        the RELATIONSHIP, never the husk: the suppressor and the death keys it
        matches are durable facts, so a purged fact that re-arrives (a laggard
        peer re-ships it) re-derives Suppressed and dies on arrival. Deletion
        is immediate and real; what remains of a deleted fact is only the edge
        that deleted it. (No guard for Suppressed: withdrawing offers others
        gate on is the point — dependents park, or die by their own death key.)"""
        if verdict == REAP:              # guard: never reap an offer another fact gates on
            for r in old:
                for d in self.needs_for(r.atom):
                    assert d.owner == fid or d.atom.effect not in (REQUIRE, SUPPRESS), "reap of a gating offer"
        self.facts.pop(fid, None); self.memo.pop(fid, None)
        for a in f.atoms:                # drop its asserted rows so nothing re-wakes it
            if bk := self.rows.get((a.kind, a.role, a.scope)): bk.remove(Row(fid, 0, mat(a, fid)))
        if self.durable.pop(fid, None):  # physical deletion; the host un-marks it as flushed
            self.purged.append(fid)
            if self.store: self.store.delete(fid)

    # --- The way out (watched) --------------------------------------------------
    # This exposes validated offers and a deterministic snapshot of derived state.
    def watched(self, role, scope):
        return list(self.clean.get((role, scope), ()))

    # Crash story: derived state is a pure, order-independent function of the
    # durable set — a fresh node over the same store, seeded with one total
    # demand, rebuilds it. Volatile facts vanish — completeness, never coherence.
    def derived(self):
        return (sorted((o, t, enc_atom(a)) for rs in self.clean.values() for o, t, a in rs),
                sorted(self.memo.items()))

    # --- The sync spine (deps / closure) ---------------------------------------
    # This traces asserted Require/Suppress owners for dependency-complete sync.
    def deps(self, fid):                 # direct structural edge owners
        f = self.facts.get(fid)          # asserted, not validity-gated — standing is decided in _step
        return frozenset() if f is None else frozenset(
            r.owner for n in needs_of(f, fid) if n.effect in (REQUIRE, SUPPRESS)
            for r in self.offers_for(n))

    def closure(self, fid, out=None):    # transitive deps, including fid
        out = set() if out is None else out          # a shared visited-set across leaves dedups the union closure
        if fid in out: return out
        out.add(fid)
        for d in self.deps(fid): self.closure(d, out)
        return out
