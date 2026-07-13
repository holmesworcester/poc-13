"""poc-13 kernel: the atom model engine, one file (design: DESIGN.md).

Facts are the unit of identity, atoms the unit of matching, and needs/offers
are the whole fact language. The kernel owns exactly four things: canonical
identity, admission, matching, and the turn loop (which the host feeds `now`).
Everything else — sync, queues, effects, content, retention — is a fact family
under facts/; time alone is a turn primitive, not a family (see turn/now_need).

Projectors ARE the routers: the kernel runs one root projector, and a Router
is just a projector that dispatches on the next type-tag segment. Extraction
routes through the same tree.

Derived state (validity memo, clean twin, slices, frontier) is rebuildable
from the durable fact set alone. There is no replay: a stepped fact's needs
fault their cold matches resident from the Store (the persisted atom
relation), so boot is one total demand and a session pays for what it asks
about. The store answers existence, never standing.

Hash: BLAKE3-256 (the `blake3` package; stdlib has none).
"""
from collections import deque
from dataclasses import dataclass, field, replace
import sqlite3, time

try:
    from blake3 import blake3 as _b3
except ImportError as e:                 # the repo's one non-crypto-suite dependency
    raise ImportError("poc-13 needs blake3 (pip install blake3)") from e

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
EXACT, SELF_T, RANGE = 0, 1, 2
SELF = (SELF_T,)                         # "this fact's eventual FactId"
Exact = lambda b: (EXACT, b)
Range = lambda lo, hi: (RANGE, lo, hi)

@dataclass(frozen=True)
class Atom:
    kind: int; role: bytes; scope: bytes; target: tuple
    value: bytes = None; effect: int = NONE   # effect: needs only

def enc_atom(a):                         # the atom as one frame sequence: header ‖ role ‖ scope ‖ target-tail ‖ value?
    return frame(bytes([a.kind, a.effect, a.target[0]]), a.role, a.scope,
                 *a.target[1:], *(() if a.value is None else (a.value,)))

def dec_atom(b):                         # strict: parse leniently, then the re-encode must match byte-for-byte
    hdr, role, scope, *rest = unframe(b)
    kind, eff, tt = hdr                   # header is exactly (kind, effect, target-tag)
    if kind not in (NEED, OFFER) or eff > SUPPRESS or tt > RANGE: raise ValueError("bad tag")
    if kind == OFFER and eff != NONE: raise ValueError("effect on offer")
    if role[:1] == b"\x00" and (kind, eff) != (NEED, WATCH): raise ValueError("reserved role")
    n = (1, 0, 2)[tt]                     # target parts after the tag: EXACT 1, SELF 0, RANGE 2
    a = Atom(kind, role, scope, (tt, *rest[:n]), rest[n] if len(rest) > n else None, eff)
    if enc_atom(a) != b: raise ValueError("non-canonical atom")   # extra/misplaced frames re-encode differently
    return a

@dataclass(frozen=True)
class Fact:
    type_tag: bytes; atoms: tuple        # strictly increasing by encoding

def fact(tag, *atoms):                   # canonicalize: sort + dedup + validate
    return Fact(tag, tuple(dec_atom(e) for e in sorted({enc_atom(a) for a in atoms})))

DOMAIN = b"poc13.fact.v1"                # the only dialect marker, forever
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
def covers(off_t, need_t):               # SELF never matches; range↔range never matches
    if need_t[0] == EXACT:
        return (off_t == need_t or
                (off_t[0] == RANGE and off_t[1] <= need_t[1] <= off_t[2]))
    if need_t[0] == RANGE:               # range need: demand over exact offers
        return off_t[0] == EXACT and need_t[1] <= off_t[1] <= need_t[2]
    return False

# Materialization rule: every derived row rewrites SELF to the owner id.
mat = lambda a, fid: replace(a, target=Exact(fid)) if a.target == SELF else a
needs_of = lambda f, fid: [mat(a, fid) for a in f.atoms if a.kind == NEED]

# --- The projector contract ------------------------------------------------------
@dataclass
class Out:                               # project() -> verdict + all it may emit
    verdict: str = "Valid"               # Valid | Invalid
    offers: tuple = ()                   # engine restamps provenance regardless
    slice_delta: dict = field(default_factory=dict)

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

# Two further needs are answered the same transient way, but from the engine's
# own indexes rather than the OS clock: a `summary` need over a key RANGE is
# answered with my fingerprint for that range, plus my reconciliation claims (a
# B-way equal-count split, or the range's id list and its deduped dependency
# closure ids when the range is small); a `resident` need over a fact id is
# answered iff I already hold it. Both are the seam the decomposed sync families
# read to descend (summary) and to pull by id (resident); the closure ids are how
# a below-window dependency travels. Reserved roles: the leading NUL cannot occur
# in a family role, so no family can author or collide with them; both are always
# WATCH and never gate. _answer (in _step) injects their rows into ctx exactly as
# valid_offers would, so `by(ctx, role)` reads them uniformly.
SUM_ROLE, RES_ROLE, _SUM, _RES = b"\x00summary", b"\x00resident", b"\x00sum", b"\x00res"

# The total demand is the whole boot story: one reserved Watch need whose key
# the fault leg reads as "every stored fact". Once checked, faulting is over —
# facts enter the store only via admission, so nothing cold appears behind it.
ALL_ROLE = b"\x00all"
FULL = Range(b"", b"\xff" * 64)         # the full-domain range Watch: covers any exact key
all_need = Atom(NEED, ALL_ROLE, b"store", FULL, effect=WATCH)
_ALL_KEY = (ALL_ROLE, b"store", all_need.target)

RESERVED = frozenset((SUM_ROLE, RES_ROLE, ALL_ROLE))
CLOSURE_CAP = 4096                       # generous safety valve on unique closure ids per summary answer
_kb = lambda ts, fid: ts.to_bytes(8, "big") + fid            # (ts, fid) -> the 40-byte reconciliation key
summary_need = lambda lo, hi, floor=b"": Atom(NEED, SUM_ROLE, b"sync", Range(lo, hi), floor, effect=WATCH)
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

    def project(self, f, ctx, sl):       # -> Out | None (None: no family, park)
        c = self._child(f)
        return c.project(f, ctx, sl) if c else None

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
                                           tt INT, t1 BLOB, t2 BLOB, value BLOB,
                                           ex INT, lo BLOB, hi BLOB);
          CREATE INDEX IF NOT EXISTS match_ix ON atoms(kind, role, scope, ex, lo);
          CREATE INDEX IF NOT EXISTS owner_ix ON atoms(fid);""")

    def add(self, fb):                   # checked write: decode + derive EVERY row before the
        try:                             # first insert — bad BYTES are a miss...
            f = decode(fb); fid = fact_id(f)
            rows = [(fid, a.kind, a.effect, a.role, a.scope,
                     *(a.target + (None, None))[:3], a.value,
                     m.target[0] == EXACT, m.target[1], m.target[-1])
                    for a in f.atoms for m in (mat(a, fid),)]
        except Exception: return
        if not self.db.in_transaction: self.db.execute("BEGIN")   # one transaction per host
        self.db.execute("SAVEPOINT a")                            # turn: commit() ends it
        try:
            if self.db.execute("INSERT OR IGNORE INTO facts VALUES(?,?)", (fid, f.type_tag)).rowcount:
                self.db.executemany("INSERT INTO atoms VALUES(?,?,?,?,?,?,?,?,?,?,?,?)", rows)
            self.db.execute("RELEASE a")
        except BaseException:            # ...but a failed WRITE (SystemExit included) tears
            try: self.db.execute("ROLLBACK TO a"); self.db.execute("RELEASE a")
            except sqlite3.Error: pass   # (the tx may have auto-rolled-back beneath us)
            raise                        # propagate whole: the caller keeps it unflushed, retries

    def _mk(self, fid, tag, rows):       # regroup -> rebuild -> re-hash: the certificate check
        try:
            f = fact(tag, *(Atom(k, r, s, (tt, t1, t2)[:1 + (1, 0, 2)[tt]], v, e)
                            for k, e, r, s, tt, t1, t2, v in rows))
            return encode(f) if fact_id(f) == fid else None
        except Exception: return None

    def fact_bytes(self, fid):           # the derived view: canonical bytes, or a miss
        t = self.db.execute("SELECT tag FROM facts WHERE fid=?", (fid,)).fetchone()
        rows = self.db.execute("SELECT kind, effect, role, scope, tt, t1, t2, value"
                               " FROM atoms WHERE fid=?", (fid,)).fetchall()
        return self._mk(fid, t[0], rows) if t else None    # zero atom rows is legal: hash decides

    def owners(self, n):                 # existence: who offers at this (materialized) need's
        if n.role == ALL_ROLE:           # key — never standing. Total demand: every stored fact.
            return [r[0] for r in self.db.execute("SELECT fid FROM facts")]
        return [r[0] for r in self.db.execute(
            "SELECT DISTINCT fid FROM atoms WHERE kind=1 AND role=? AND scope=?" + self._COV,
            (n.role, n.scope, n.target[1], n.target[-1], n.target[0] == EXACT, n.target[1]))]

    def delete(self, fid):               # cold-path purge: forget a fact's rows. The caller
        self.db.execute("DELETE FROM facts WHERE fid=?", (fid,))     # owns the node-side
        self.db.execute("DELETE FROM atoms WHERE fid=?", (fid,))     # discipline: refault().

    def commit(self): self.db.commit()   # host calls it: durable before the reply

# --- The sync skeleton: a clamping-invariant treap ---------------------------------
# Range-based set reconciliation (Meyer & Scherer, rbsr_nonhomomorphic) over the
# 40-byte (ts‖FactId) leaf keys. The reconciliation set is a TREAP — a binary search
# tree on the key AND a heap on a priority. The priority is the leaf hash: a pure
# function of the key, so the tree SHAPE is a function of the set alone (history-
# independence) and two peers holding the same set build the same tree. Each node
# caches its subtree size and a Merkle label lb = H(left.lb ‖ leaf_hash ‖ right.lb).
# A range fingerprint is the CLAMPED label — the label of the tree with all out-of-
# range items discarded — computed by walking only the two boundary spines (reading
# precomputed labels for fully-in subtrees), O(log n) whp. Clamping-invariance makes
# that label a canonical function of the in-range SET (independent of tree shape and
# of out-of-range items), so peers agree using an ORDINARY hash — no homomorphic/xor
# fold. A mismatched range is split into B parts of EQUAL COUNT (an order-statistic
# select, not a key-prefix split), so fanout is B and depth is log_B(n) regardless of
# key distribution. A range of <= T leaves is listed by id instead, ending the
# recursion. (A maliciously degenerate set costs O(n) local compute; the paper shows
# communication, roundtrips, and censorship-resistance stay immune.)
_TREAP_EMPTY = H(b"")                         # the Merkle label of the empty tree

class _Nd:
    # Two axes: the SEARCH key k = ts‖FactId orders the BST (so a ts-range is just a
    # key-range — rbsr's arbitrary ranges are preserved), and the PRIORITY (the leaf
    # hash lh) orders the heap that fixes the shape. lh is uniform and uncorrelated
    # with the ts-major key, so even a run of same-ts facts balances.
    __slots__ = ("k", "lh", "l", "r", "c", "lb")
    def __init__(self, k, lh):
        self.k, self.lh, self.l, self.r = k, lh, None, None
        self.fix()
    def fix(self):                           # recompute subtree count + Merkle label from the children
        l, r = self.l, self.r
        self.c = (l.c if l else 0) + (r.c if r else 0) + 1
        self.lb = H((l.lb if l else _TREAP_EMPTY) + self.lh + (r.lb if r else _TREAP_EMPTY))

def _rot_r(t): x = t.l; t.l = x.r; x.r = t; t.fix(); x.fix(); return x
def _rot_l(t): x = t.r; t.r = x.l; x.l = t; t.fix(); x.fix(); return x

def _t_ins(t, k, lh):                         # insert/update, keeping the (lh, k) max-heap
    if t is None: return _Nd(k, lh)
    if k == t.k:                              # already present: same content => same lh, so a no-op
        return t if lh == t.lh else _t_ins(_t_del(t, k), k, lh)   # (a priority change would re-heapify)
    if k < t.k:
        t.l = _t_ins(t.l, k, lh)
        if (t.l.lh, t.l.k) > (t.lh, t.k): t = _rot_r(t)
    else:
        t.r = _t_ins(t.r, k, lh)
        if (t.r.lh, t.r.k) > (t.lh, t.k): t = _rot_l(t)
    t.fix(); return t

def _t_del(t, k):                             # rotate the target down to a leaf, then drop it
    if t is None: return None
    if k < t.k: t.l = _t_del(t.l, k)
    elif k > t.k: t.r = _t_del(t.r, k)
    else:
        if t.l is None: return t.r
        if t.r is None: return t.l
        if (t.l.lh, t.l.k) > (t.r.lh, t.r.k): t = _rot_r(t); t.r = _t_del(t.r, k)
        else: t = _rot_l(t); t.l = _t_del(t.l, k)
    t.fix(); return t

# The clamped-label walks are ITERATIVE (an explicit spine list, not recursion): honest
# leaf-hash priorities keep height O(log n), but a maliciously degenerate spine must cost
# O(n) time, never a stack overflow.
_lb = lambda t: t.lb if t else _TREAP_EMPTY
def _clamp_lo(t, lo):                         # label of t restricted to keys >= lo — fold the low boundary spine
    spine = []
    while t is not None:
        if t.k < lo: t = t.r                  # t and its left are below lo: drop them, follow the boundary right
        else: spine.append((t.lh, _lb(t.r))); t = t.l   # t in: its left clamps low, its right is wholly in
    acc = _TREAP_EMPTY
    for lh, rlb in reversed(spine): acc = H(acc + lh + rlb)   # fold deepest-first: innermost clamp outward
    return acc
def _clamp_hi(t, hi):                         # label of t restricted to keys < hi — fold the high boundary spine
    spine = []
    while t is not None:
        if t.k >= hi: t = t.l
        else: spine.append((_lb(t.l), t.lh)); t = t.r
    acc = _TREAP_EMPTY
    for llb, lh in reversed(spine): acc = H(llb + lh + acc)
    return acc
def _clamp(t, lo, hi):                        # label of t restricted to [lo, hi) — the range fingerprint
    while t is not None:                      # descend to the split node (the first in-range key)
        if t.k < lo: t = t.r
        elif t.k >= hi: t = t.l
        else: return H(_clamp_lo(t.l, lo) + t.lh + _clamp_hi(t.r, hi))
    return _TREAP_EMPTY

class Treap:
    B, T = 16, 8                              # split fanout ; list-not-fingerprint threshold
    EMPTY = _TREAP_EMPTY
    def __init__(self): self.root = None

    def insert(self, kb, lh): self.root = _t_ins(self.root, kb, lh)
    def remove(self, kb): self.root = _t_del(self.root, kb)

    def _rank(self, x):                       # number of keys < x
        t, r = self.root, 0
        while t:
            if t.k < x: r += (t.l.c if t.l else 0) + 1; t = t.r
            else: t = t.l
        return r
    def _select(self, i):                     # the 0-based i-th smallest key
        t = self.root
        while t:
            lc = t.l.c if t.l else 0
            if i < lc: t = t.l
            elif i == lc: return t.k
            else: i -= lc + 1; t = t.r
        return None

    def count(self, lo, hi): return self._rank(hi) - self._rank(lo)
    def small(self, lo, hi): return self.count(lo, hi) <= self.T
    def fp(self, lo, hi): return _clamp(self.root, lo, hi)
    def parts(self, lo, hi):                  # <= B sub-ranges of equal COUNT (order-statistic select)
        n = self.count(lo, hi)
        if not n: return []                   # empty range: nothing to split (the caller guards via small(); stay total)
        r0 = self._rank(lo)
        bounds = [lo] + [self._select(r0 + (p * n) // self.B) for p in range(1, self.B)] + [hi]
        return [(a, b) for a, b in zip(bounds, bounds[1:]) if a != b]
    def fids(self, lo, hi):                   # the 32-byte FactIds of my leaves in [lo, hi), in key order (iterative)
        out, stack, t = [], [], self.root
        while stack or t is not None:
            if t is not None:
                if t.k < lo: t = t.r          # t and its left subtree are below lo
                else: stack.append(t); t = t.l
            else:
                t = stack.pop()
                if t.k >= hi: break           # in-order is ascending: nothing more is in range
                out.append(t.k[8:]); t = t.r  # lo <= t.k < hi
        return out
    @property
    def keys(self):                           # every 40-byte key in order (iterative; the caller flushes pending first)
        out, stack, t = [], [], self.root
        while stack or t is not None:
            if t is not None: stack.append(t); t = t.l
            else: t = stack.pop(); out.append(t.k); t = t.r
        return out

# --- The match index ---------------------------------------------------------------
class Bucket:
    """One match bucket over atom-LAST rows — (owner, atom) in the asserted index,
    (owner, ts, atom) in the clean twin; the same class serves both. Exact-target
    rows live in a dict keyed by target value (the common case: a point query is
    an O(1) lookup, not a scan of every same-role atom); the few range-target rows
    sit in a short list. covers() reduces, in BOTH match directions, to the same
    function of the query target — a point hits `exact[v]` plus any range that
    spans v; a range hits the exact values inside it (range-vs-range never
    matches) — so one `match` serves offers_for, needs_for and valid_offers alike.
    Iterable — `for row in bucket` yields every row — for watched()/derived()."""
    __slots__ = ("exact", "ranges")
    def __init__(self): self.exact, self.ranges = {}, []      # value -> [row] ; [row]

    def add(self, r):
        (self.exact.setdefault(r[-1].target[1], []) if r[-1].target[0] == EXACT
         else self.ranges).append(r)
    def remove(self, r):
        if r[-1].target[0] == EXACT:
            lst = self.exact.get(r[-1].target[1])
            if lst and r in lst:
                lst.remove(r)
                if not lst: del self.exact[r[-1].target[1]]
        elif r in self.ranges: self.ranges.remove(r)

    def match(self, t):                  # the rows a query target `t` covers-matches (either direction)
        if t[0] == EXACT:                # a point: the exact bin at v, plus every range that spans v
            v = t[1]
            return (list(self.exact.get(v, ()))
                    + [r for r in self.ranges if r[-1].target[1] <= v <= r[-1].target[2]])
        lo, hi = t[1], t[2]              # a range: the exact values inside it (ranges never match ranges;
        return [r for v, rs in self.exact.items() if lo <= v <= hi for r in rs]   # a SELF query raises)
    def __iter__(self):                  # every row, in no particular order — for watched() and derived()
        return iter([r for rs in self.exact.values() for r in rs] + self.ranges)
    def __len__(self):
        return sum(len(rs) for rs in self.exact.values()) + len(self.ranges)

# --- The engine --------------------------------------------------------------------
class Node:
    """One engine over one root projector. Durable authority = self.durable
    (canonical bytes, 'the disk'); memo/clean/slices/frontier are derived.
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
        self.slices = {}                     # key -> (owner, ts, value), LWW by (ts, owner)
        self._deps = {}                      # id -> direct Require/suppress edge owners: the dependency memo
        self._sumcache = {}                  # (lo,hi) -> summary rows: reused while the leaf/durable set holds still
        self.leaf_ver = 0                    # monotonic set-version, bumped on every leaf delta: a hash-free change signal
        self.tree = Treap()                  # the reconciliation set: a clamping-invariant treap (O(log n) range fp)
        self._leaves = set()                 # fids currently in the leaf set: membership, to detect a no-op delta
        self.frontier = deque()              # FIFO of fids to (re)step
        self._queued = set()                 # membership mirror of the frontier: O(1) dedup ('in' on a deque is O(n))

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
        if durable: self.durable[fid] = b; self._sumcache.clear()   # the closure graph grew: drop the memo
        for a in f.atoms:
            self.rows.setdefault((a.kind, a.role, a.scope), Bucket()).add((fid, mat(a, fid)))
        self._enqueue(fid)
        self._deps.clear()                   # the graph changed: rebuild the validated-edge memo lazily
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
        d = self._deps.get(fid)          # STRUCTURAL/asserted (from offers_for), NOT validity-gated — validity is
        if d is None:                    # decided in _step. Rebuildable derived state, cleared when a fact admits.
            f = self.facts.get(fid)
            d = self._deps[fid] = frozenset() if f is None else frozenset(
                o for n in needs_of(f, fid) if n.effect in (REQUIRE, SUPPRESS)
                for o, _ in self.offers_for(n))
        return d

    def closure(self, fid, out=None):    # transitive deps (requires + suppressors), incl fid — the sync spine.
        out = set() if out is None else out          # a shared visited-set across leaves dedups the union closure
        if fid in out: return out
        out.add(fid)
        for d in self.deps(fid): self.closure(d, out)
        return out

    def refault(self):                   # the relation changed underneath (delete + re-add):
        self.checked.clear()             # forget the fault memos and re-step every resident
        for fid in self.facts: self._enqueue(fid)     # fact, so their keys re-check the store

    # Engine-answered needs: a reserved index need is answered from the trie / the
    # durable set and injected into ctx as clean-twin-shaped (owner, ts, atom) rows,
    # exactly the way valid_offers answers an ordinary need, so `by(ctx, role)` reads
    # them uniformly. Everything else falls through to the real clean twin.
    def _answer(self, n):
        if n.role == SUM_ROLE: return self._summary_rows(n)
        if n.role == RES_ROLE: return self._resident_rows(n)
        return self.valid_offers(n)

    def _summary_rows(self, n):          # RBSR: my fingerprint for the range + my reconciliation claims for it.
        lo, hi = n.target[1], n.target[2]; floor = n.value or b""
        if floor > lo: lo = floor        # clip the range to the window floor
        # A summary is a pure function of the leaf set + the durable closure graph;
        # both are held fixed while only volatile sync facts churn, so a peer that
        # re-opens the same round every quiescence answers from this memo instead of
        # re-fingerprinting and re-walking closures. Cleared on any leaf/durable change.
        cached = self._sumcache.get((lo, hi, floor))    # floor keys the memo: it selects which deps ride in cids
        if cached is not None: return cached
        t = self.tree; R = lambda a: (_SUM, 0, a)
        rows = [R(Atom(OFFER, b"fp", b"sync", Range(lo, hi), t.fp(lo, hi)))]   # the prune-check fingerprint
        def claim(a, b):                 # my claim for [a,b): the leaves (+ windowed: their below-floor deps), else a fp
            if t.small(a, b):
                ids = list(t.fids(a, b))                            # my leaves in range: always advertised (enumerate)
                if floor:                                           # a windowed round: a leaf's below-floor deps won't
                    seen = set()                                    # enumerate as leaves of their own, so they ride here
                    for d in ids: self.closure(d, seen)             # as closure ids — only the shareable, below-floor ones
                    ids += [d for d in seen if d in self.facts and _kb(ts_of(self.facts[d]), d) < floor
                            and self.root.extract(self.facts[d])[1]]
                blob = frame(*ids[:CLOSURE_CAP])                    # full round (floor==b""): leaves only — none below b""
                return R(Atom(OFFER, b"cids", b"sync", Range(a, b), blob))
            return R(Atom(OFFER, b"cfp", b"sync", Range(a, b), t.fp(a, b)))
        rows += [claim(lo, hi)] if t.small(lo, hi) else [claim(a, b) for a, b in t.parts(lo, hi)]
        self._sumcache[(lo, hi, floor)] = rows
        return rows

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

    def _present_now(self, now):
        off = Atom(OFFER, NOW_ROLE, NOW_SCOPE, Exact(now.to_bytes(8, "big")))
        self._present(NOW_ROLE, NOW_SCOPE, [(_NOW, now, off)])

    def _present_shipped(self, fids):
        self._present(SHIPPED_ROLE, SHIPPED_SCOPE,
                      [(_SHIP, 0, Atom(OFFER, SHIPPED_ROLE, SHIPPED_SCOPE, Exact(fid))) for fid in fids])

    # Engine drain — bounded; overflow parks on the frontier, never drops.
    def turn(self, now=None, shipped=(), bound=64):
        if now is not None: self._present_now(now)   # the host hands time to the turn
        self._present_shipped(shipped)               # and the wire hands back its flush reports
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
        if any(self.valid_offers(n) for n in ns if n.effect == SUPPRESS):
            out = Out("Suppressed")
        elif any(not self.valid_offers(n) for n in ns if n.effect == REQUIRE):
            out = Out("Parked")
        else:                            # Context<Validated>; Watch never gates. Reserved index needs are
            ctx = {n: self._answer(n) for n in ns if n.effect in (REQUIRE, WATCH)}   # answered from the engine
            out = self.root.project(f, ctx, dict(self.slices)) or Out("Parked")
        self._promote(fid, f, out)

    def _leafset_update(self, fid, f):   # keep the reconciliation treap current with this fact's leaf membership.
        # A fact is a leaf iff durable, shareable, and Valid|Suppressed (tombstones stay, so deletions reconcile).
        # Its leaf hash is a constant per fid (fid/ts/bytes are all fixed), so membership is the only thing that
        # changes; a fid set detects the no-op so a re-promotion neither re-hashes nor spuriously bumps leaf_ver.
        should = (fid in self.durable and self.memo.get(fid) in ("Valid", "Suppressed")
                  and self.root.extract(f)[1])
        if should == (fid in self._leaves): return          # membership unchanged: no delta
        kb = _kb(ts_of(f), fid)
        if should: self._leaves.add(fid); self.tree.insert(kb, H(frame(fid, kb[:8], H(self.durable[fid]))))
        else: self._leaves.discard(fid); self.tree.remove(kb)
        self.leaf_ver += 1               # a cheap "my set moved" signal for the daemon (a counter, never a hash)
        self._sumcache.clear()           # the leaf set moved: the memoised summaries are stale

    def _promote(self, fid, f, out):
        self.memo[fid] = out.verdict
        self._leafset_update(fid, f)
        # Owner-scoped replacement: pull this fact's current rows from their
        # buckets, add the new ones — old and new output are never both visible.
        old = self.owned.pop(fid, [])
        for r in old: self.clean[(r[2].role, r[2].scope)].remove(r)
        new = ([(fid, ts_of(f), mat(a, fid)) for a in out.offers]
               if out.verdict == "Valid" else [])
        for r in new: self.clean.setdefault((r[2].role, r[2].scope), Bucket()).add(r)
        if new: self.owned[fid] = new
        self.slices = {k: v for k, v in self.slices.items() if v[0] != fid}
        if out.verdict == "Valid":
            for k, v in out.slice_delta.items():
                cur = self.slices.get(k)
                if not cur or (cur[2], cur[0]) <= (ts_of(f), fid):
                    self.slices[k] = (fid, v, ts_of(f))
        for _, _, a in set(old) ^ set(new):   # wake fanout on every changed offer (never re-wake self)
            self._wake(a, fid)
        if out.verdict == "Reap":            # terminal: evict the body, leaving no residue
            for r in old:                    # guard: never reap an offer another fact gates on
                for o, na in self.needs_for(r[2]):
                    assert o == fid or na.effect not in (REQUIRE, SUPPRESS), "reap of a gating offer"
            self.facts.pop(fid, None); self.memo.pop(fid, None)
            for a in f.atoms:                # drop its asserted rows so nothing re-wakes it
                if bk := self.rows.get((a.kind, a.role, a.scope)): bk.remove((fid, mat(a, fid)))

    # Host out — the host drains validated offers at keys it watches, performs
    # external work, and admits facts reporting what happened. It never writes.
    def watched(self, role, scope):
        return list(self.clean.get((role, scope), ()))

    # Crash story: derived state is a pure, order-independent function of the
    # durable set — a fresh node over the same store, seeded with one total
    # demand, rebuilds it. Volatile facts vanish — completeness, never coherence.
    def derived(self):
        return (sorted((o, t, enc_atom(a)) for rs in self.clean.values() for o, t, a in rs),
                sorted((k, *v) for k, v in self.slices.items()),
                sorted(self.memo.items()))
