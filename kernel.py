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
from the durable fact set alone: `replay()` is the whole crash story. With a
Store, replay is demand-driven: a stepped fact's needs pull matching cold
facts resident (hydration), so a session pays for what it asks about.

Stand-in: BLAKE2b-256 for BLAKE3-256 (stdlib has no BLAKE3).
"""
from bisect import bisect_left
from collections import deque
from dataclasses import dataclass, field, replace
from itertools import chain
import hashlib, sqlite3, time

H = lambda b: hashlib.blake2b(b, digest_size=32).digest()
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

def enc_atom(a):                         # one fixed self-delimiting byte form
    v = b"\x00" if a.value is None else b"\x01" + frame(a.value)
    return (bytes([a.kind, a.effect]) + frame(a.role, a.scope)
            + bytes([a.target[0]]) + frame(*a.target[1:]) + v)

def dec_atom(b):                         # strict: must re-encode identically
    kind, eff = b[0], b[1]
    role, i = _rd(b, 2); scope, i = _rd(b, i)
    tt = b[i]; i += 1
    if tt == EXACT: k, i = _rd(b, i); tgt = (EXACT, k)
    elif tt == SELF_T: tgt = SELF
    else: lo, i = _rd(b, i); hi, i = _rd(b, i); tgt = (RANGE, lo, hi)
    val = None
    if b[i] == 1: val, i = _rd(b, i + 1)
    else: i += 1
    a = Atom(kind, role, scope, tgt, val, eff)
    if i != len(b) or enc_atom(a) != b: raise ValueError("non-canonical atom")
    if kind not in (NEED, OFFER) or eff > SUPPRESS: raise ValueError("bad tag")
    if kind == OFFER and eff != NONE: raise ValueError("effect on offer")
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
    tag, i = _rd(b, 0); encs = []
    while i < len(b):
        e, i = _rd(b, i); encs.append(e)
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
# accumulates, and durable derived state never depends on now — replay at any now
# rebuilds it identically.
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
RESERVED = frozenset((SUM_ROLE, RES_ROLE))
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
# Hydration window, riding in a Watch need's value: engine-owned bytes, never
# read by matching. Gating needs (Require/Suppress) ignore it — their pulls
# are exhaustive, because a missed offer could change a verdict.
WINDOW_LEN = 21                          # a window blob is lo(u64) + hi(u64) + budget(u32) + order(u8)
def window(lo=0, hi=2**64 - 1, budget=2**32 - 1, order=0):
    return (lo.to_bytes(8, "little") + hi.to_bytes(8, "little")
            + budget.to_bytes(4, "little") + bytes([order]))

_window = lambda v: (int.from_bytes(v[:8], "little"), int.from_bytes(v[8:16], "little"),
                     int.from_bytes(v[16:20], "little"), v[20])

_t8 = lambda t: t.to_bytes(8, "big")     # u64 ts as blob: memcmp order, no i64 overflow

class Store:
    """The db: `facts(fid, bytes)` — the dumb table, canonical fact bytes and
    nothing else — is the one durable authority; `atoms` is a derived match
    index (one materialized offer row per atom, rebuildable from facts); TEMP
    `hot` is this session's delivered set, the per-fact dedup that makes a
    window re-scan never deliver the same owner twice. Outside the trust
    boundary — every pull re-enters through checked admission, so wrong
    bytes are a miss. The atom coverage relation is the one WHERE clause in
    pull(); kernel `covers` is its spec (mirror-tested)."""

    def __init__(self, path=":memory:"):
        self.db = sqlite3.connect(path)
        self.db.execute("PRAGMA busy_timeout=5000")  # tolerate brief lock contention
        self.db.execute("PRAGMA journal_mode=WAL")   # commit per turn without a full fsync
        self.db.execute("PRAGMA synchronous=NORMAL") # fsync at checkpoints, not every commit
        self.db.executescript("""
          CREATE TABLE IF NOT EXISTS facts(fid BLOB PRIMARY KEY, bytes BLOB) WITHOUT ROWID;
          CREATE TABLE IF NOT EXISTS atoms(fid BLOB, ts BLOB, role BLOB, scope BLOB,
                                           ex INT, lo BLOB, hi BLOB);
          CREATE INDEX IF NOT EXISTS match_ix ON atoms(role, scope, lo, ts);
          CREATE TEMP TABLE hot(fid BLOB PRIMARY KEY);""")

    def add(self, fb, hot=False):        # checked load: bad bytes are a miss
        try: f = decode(fb)
        except Exception: return
        fid = fact_id(f)
        if not self.db.execute("INSERT OR IGNORE INTO facts VALUES(?,?)", (fid, fb)).rowcount:
            return                       # already stored: atoms are already indexed
        if hot: self.db.execute("INSERT OR IGNORE INTO hot VALUES(?)", (fid,))
        self.db.executemany("INSERT INTO atoms VALUES(?,?,?,?,?,?,?)",
            [(fid, _t8(ts_of(f)), m.role, m.scope, m.target[0] == EXACT,
              m.target[1], m.target[-1])
             for a in f.atoms if a.kind == OFFER for m in (mat(a, fid),)])

    def pull(self, need):                # matches not yet delivered, (ts, fid) order,
        nlo, nhi = need.target[1], need.target[-1]     # budget counts primary hits
        sql = """SELECT DISTINCT ts, fid FROM atoms WHERE role=? AND scope=?
                 AND ((ex AND lo BETWEEN ? AND ?) OR (NOT ex AND ? AND ? BETWEEN lo AND hi))
                 AND fid NOT IN (SELECT fid FROM hot)"""
        args = [need.role, need.scope, nlo, nhi, need.target[0] == EXACT, nlo]
        if need.effect == WATCH and need.value and len(need.value) == WINDOW_LEN:
            lo, hi, budget, order = _window(need.value)
            d = "DESC" if order else "ASC"
            sql += f" AND ts BETWEEN ? AND ? ORDER BY ts {d}, fid {d} LIMIT ?"
            args += [_t8(lo), _t8(hi), budget]
        else:
            sql += " ORDER BY ts, fid"   # gating: exhaustive, a miss could flip a verdict
        out = []
        for _, fid in self.db.execute(sql, args).fetchall():
            self.db.execute("INSERT OR IGNORE INTO hot VALUES(?)", (fid,))
            out.append(self.db.execute("SELECT bytes FROM facts WHERE fid=?", (fid,)).fetchone()[0])
        return out

    def all(self):                       # full replay: the degenerate demand
        return [r[0] for r in self.db.execute("SELECT bytes FROM facts")]

    def delete(self, fid):               # cold-path purge: forget a fact's bytes and match rows
        self.db.execute("DELETE FROM facts WHERE fid=?", (fid,))
        self.db.execute("DELETE FROM atoms WHERE fid=?", (fid,))

    def commit(self): self.db.commit()   # host calls it: durable before the reply

# --- The sync skeleton -------------------------------------------------------------
class Skeleton:
    """Range-based set reconciliation (Meyer, rbsr_nonhomomorphic) over the sorted
    40-byte (ts‖FactId) leaf keys. A range [lo,hi) is summarised by a NON-homomorphic
    fingerprint — H of its leaf hashes in key order (‖ count) — so it is collision-
    resistant, unlike an XOR/sum fold. A mismatched range is split into B parts of
    EQUAL COUNT (by order-statistic), NOT by key prefix: fanout is the chosen B and
    depth is log_B(n) regardless of key distribution (a radix trie's fanout is
    whatever bytes happen to occur — the thing the paper rejects). A range of <= T
    leaves is listed by id instead of fingerprinted, which ends the recursion and
    lets an empty peer pull by receiving the (possibly empty) list.

    Body-independent: it stores only key -> leaf hash, never fact bytes. So the full
    set can stay resident as the sync index while fact bodies are hydrated on demand
    — the residency/sync split (docs/daemon-transition.md 'Further work'). A sorted
    list keeps this readable; production would swap in a count-augmented balanced
    tree (treap) for O(log n) insert and range fingerprints (see that note)."""
    B, T = 16, 8                             # branching factor ; list-not-fingerprint threshold
    EMPTY = H((0).to_bytes(6, "little"))     # the fingerprint of an empty range

    def __init__(self): self.keys = []; self.h = {}          # sorted 40-byte keys ; key -> leaf hash

    def insert(self, kb, h):
        i = bisect_left(self.keys, kb)
        if i == len(self.keys) or self.keys[i] != kb: self.keys.insert(i, kb)
        self.h[kb] = h
    def remove(self, kb):
        i = bisect_left(self.keys, kb)
        if i < len(self.keys) and self.keys[i] == kb: del self.keys[i]
        self.h.pop(kb, None)

    def _span(self, lo, hi):                 # [i, j): the index range of keys in [lo, hi)
        return bisect_left(self.keys, lo), bisect_left(self.keys, hi)
    def count(self, lo, hi): i, j = self._span(lo, hi); return j - i
    def small(self, lo, hi): return self.count(lo, hi) <= self.T
    def fp(self, lo, hi):                    # non-homomorphic fingerprint of [lo, hi)
        i, j = self._span(lo, hi)
        return H(b"".join(self.h[k] for k in self.keys[i:j]) + (j - i).to_bytes(4, "little"))
    def fids(self, lo, hi):                  # the 32-byte FactIds of my leaves in [lo, hi)
        i, j = self._span(lo, hi); return [k[8:] for k in self.keys[i:j]]
    def parts(self, lo, hi):                 # split [lo, hi) into <= B sub-ranges of equal COUNT
        i, j = self._span(lo, hi); n = j - i
        bounds = [lo] + [self.keys[i + (p * n) // self.B] for p in range(1, self.B)] + [hi]
        return [(a, b) for a, b in zip(bounds, bounds[1:]) if a != b]

# --- The engine --------------------------------------------------------------------
class Node:
    """One engine over one root projector. Durable authority = self.durable
    (canonical bytes, 'the disk'); memo/clean/slices/frontier are derived.
    With a store, residency is demand-driven: a stepped fact's needs pull
    matching cold facts through ordinary admission — replay is the fixpoint
    of demand, and full replay is the degenerate case (one unbounded need)."""

    def __init__(self, root, store=None):
        self.root, self.store = root, store
        self.facts, self.durable = {}, {}    # id -> Fact ; id -> canonical bytes
        # Match indexes bucketed by (kind, role, scope) / (role, scope): a need
        # only ever matches offers sharing its role+scope, so one bucket is the
        # whole candidate set — no linear scan of the asserted set per query.
        self.rows, self.intake = {}, {}      # (kind,role,scope) -> [(owner, atom)]: asserted + overlay
        self.memo, self.clean = {}, {}       # id -> verdict ; (role,scope) -> [(owner, ts, atom)]
        self.owned = {}                      # id -> its clean rows, for owner-scoped replacement
        self.slices = {}                     # key -> (owner, ts, value), LWW by (ts, owner)
        self._deps = {}                      # id -> direct Require/suppress edge owners: the dependency memo
        self.leafset = {}                    # (ts,FactId) -> content leaf hash: the sync reconciliation set
        self.leaf_xor = 0                    # XOR of every leaf hash: an O(1) whole-set change fingerprint
        self.tree = Skeleton()               # the same set as an RBSR skeleton: range fp + count-split descent
        self.frontier = deque()

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
        if durable: self.durable[fid] = b    # atomic flush
        for a in f.atoms:
            self.intake.setdefault((a.kind, a.role, a.scope), []).append((fid, mat(a, fid)))
        self.frontier.append(fid)
        self._deps.clear()                   # the graph changed: rebuild the validated-edge memo lazily
        return fid

    # Both match directions run over index ∪ intake; the overlay is transparent.
    # A shared role+scope is the whole precondition for a match, so it keys the
    # bucket; covers() decides the rest over just those candidates.
    def _bucket(self, k): return chain(self.rows.get(k, ()), self.intake.get(k, ()))
    def offers_for(self, need):          # asserted, dirty: discovery only
        return [(o, a) for o, a in self._bucket((OFFER, need.role, need.scope))
                if covers(a.target, need.target)]
    def needs_for(self, offer):          # wake fanout direction
        return [(o, a) for o, a in self._bucket((NEED, offer.role, offer.scope))
                if covers(offer.target, a.target)]
    def valid_offers(self, need):        # the clean twin: the only justifier
        return [r for r in self.clean.get((need.role, need.scope), ())
                if covers(r[2].target, need.target)]

    def _wake(self, offer, skip=None):   # re-enqueue every need this offer covers (never its own owner)
        for o, _ in self.needs_for(offer):
            if o != skip and o not in self.frontier: self.frontier.append(o)

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

    def missing_needs(self):             # the reserved closure/hydrate need (poc-12 §Hydration):
        out = {}                         # a parked fact's still-unmet REQUIRE keys — the deps it lacks.
        for fid, f in self.facts.items():
            if self.memo.get(fid) != "Parked": continue     # only a parked fact lacks a Require
            for n in needs_of(f, fid):
                if n.effect == REQUIRE and not self.valid_offers(n):
                    out[(n.role, n.scope, n.target)] = n
        return list(out.values())

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
        t = self.tree; R = lambda a: (_SUM, 0, a)
        rows = [R(Atom(OFFER, b"fp", b"sync", Range(lo, hi), t.fp(lo, hi)))]   # the prune-check fingerprint
        def claim(a, b):                 # my claim for [a,b): ids (+ their closures) if small, else a fingerprint
            if t.small(a, b):
                seen = set()
                for f in t.fids(a, b): self.closure(f, seen)        # leaves + their deduped dependency closures
                blob = frame(*[d for d in list(seen)[:CLOSURE_CAP] if d in self.facts])
                return R(Atom(OFFER, b"cids", b"sync", Range(a, b), blob))
            return R(Atom(OFFER, b"cfp", b"sync", Range(a, b), t.fp(a, b)))
        rows += [claim(lo, hi)] if t.small(lo, hi) else [claim(a, b) for a, b in t.parts(lo, hi)]
        return rows

    def _resident_rows(self, n):         # answered iff I already hold the fact — the have/need pull seam
        fid = n.target[1]
        return [(_RES, 0, Atom(OFFER, b"resident", b"sync", Exact(fid)))] if fid in self.durable else []

    # Present the host's clock as one transient offer at the NOW key, waking any
    # time-waiting need whose deadline it now covers. One clean-twin slot,
    # replaced each turn — transient, so nothing accumulates.
    def _present_now(self, now):
        off = Atom(OFFER, NOW_ROLE, NOW_SCOPE, Exact(now.to_bytes(8, "big")))
        self.clean[(NOW_ROLE, NOW_SCOPE)] = [(_NOW, now, off)]
        self._wake(off)

    # Present the daemon's flush reports as transient offers at the SHIPPED key,
    # one per host-watched offer that left the socket, waking the senders that
    # Watch shipped@SELF. One clean-twin slot, replaced each turn — transient.
    def _present_shipped(self, fids):
        rows = [(_SHIP, 0, Atom(OFFER, SHIPPED_ROLE, SHIPPED_SCOPE, Exact(fid))) for fid in fids]
        self.clean[(SHIPPED_ROLE, SHIPPED_SCOPE)] = rows
        for _, _, off in rows: self._wake(off)

    # Engine drain — bounded; overflow parks on the frontier, never drops.
    def turn(self, now=None, shipped=(), bound=64):
        if now is not None: self._present_now(now)   # the host hands time to the turn
        self._present_shipped(shipped)               # and the wire hands back its flush reports
        for _ in range(min(bound, len(self.frontier))):
            self._step(self.frontier.popleft())
        for k, v in self.intake.items(): self.rows.setdefault(k, []).extend(v)
        self.intake = {}                             # flush: moves rows, changes no result

    def run(self):
        for _ in range(100_000):
            if not self.frontier: return self
            self.turn()
        raise RuntimeError("no quiescence")

    def _step(self, fid):
        if fid not in self.facts: return
        f = self.facts[fid]; ns = needs_of(f, fid)
        if self.store:                   # demand: needs pull their cold matches
            for n in ns:                 # resident first; offers never wake cold
                for b in self.store.pull(n): self.admit(b, checked=True)
        # Precedence (ratified): Suppress > Require(Park) > Resolve.
        if any(self.valid_offers(n) for n in ns if n.effect == SUPPRESS and n.role not in RESERVED):
            out = Out("Suppressed")
        elif any(not self.valid_offers(n) for n in ns if n.effect == REQUIRE and n.role not in RESERVED):
            out = Out("Parked")
        else:                            # Context<Validated>; Watch never gates. Reserved index needs are
            ctx = {n: self._answer(n) for n in ns if n.effect in (REQUIRE, WATCH)}   # answered from the engine
            out = self.root.project(f, ctx, dict(self.slices)) or Out("Parked")
        self._promote(fid, f, out)

    def _leafset_update(self, fid, f):   # keep the (ts,FactId)->hash set + XOR fingerprint current.
        key = (ts_of(f), fid)            # a leaf iff durable, shareable, and Valid|Suppressed (tombstones stay)
        new = None
        if (fid in self.durable and self.memo.get(fid) in ("Valid", "Suppressed")
                and self.root.extract(f)[1]):
            new = H(frame(fid, key[0].to_bytes(8, "little"), H(self.durable[fid])))
        old = self.leafset.get(key)
        if old == new: return            # no delta: leave the set and its XOR untouched
        if old is not None: self.leaf_xor ^= int.from_bytes(old, "big"); del self.leafset[key]
        if new is not None: self.leaf_xor ^= int.from_bytes(new, "big"); self.leafset[key] = new
        kb = key[0].to_bytes(8, "big") + fid   # keep the RBSR skeleton in step with the set
        self.tree.remove(kb) if new is None else self.tree.insert(kb, new)

    def _promote(self, fid, f, out):
        self.memo[fid] = out.verdict
        self._leafset_update(fid, f)
        # Owner-scoped replacement: pull this fact's current rows from their
        # buckets, add the new ones — old and new output are never both visible.
        old = self.owned.pop(fid, [])
        for r in old: self.clean[(r[2].role, r[2].scope)].remove(r)
        new = ([(fid, ts_of(f), mat(a, fid)) for a in out.offers]
               if out.verdict == "Valid" else [])
        for r in new: self.clean.setdefault((r[2].role, r[2].scope), []).append(r)
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
            for a in f.atoms:                # drop its asserted/overlay rows so nothing re-wakes it
                k, m = (a.kind, a.role, a.scope), mat(a, fid)
                for tbl in (self.rows, self.intake):
                    if (bk := tbl.get(k)) and (fid, m) in bk: bk.remove((fid, m))

    # Host out — the host drains validated offers at keys it watches, performs
    # external work, and admits facts reporting what happened. It never writes.
    def watched(self, role, scope):
        return list(self.clean.get((role, scope), ()))

    # Crash story: derived state is a pure, order-independent function of the
    # durable set. Volatile facts vanish — completeness, never coherence.
    def replay(self, order=None):
        m = Node(self.root)
        for fid in (order or list(self.durable)): m.admit(self.durable[fid], checked=True)
        return m.run()

    def derived(self):
        return (sorted((o, t, enc_atom(a)) for rs in self.clean.values() for o, t, a in rs),
                sorted((k, *v) for k, v in self.slices.items()),
                sorted(self.memo.items()))
