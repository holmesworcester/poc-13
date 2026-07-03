"""poc-13 kernel: the atom model engine, one file (design: poc-12 docs/DESIGN.md).

Facts are the unit of identity, atoms the unit of matching, and needs/offers
are the whole fact language. The kernel owns exactly four things: canonical
identity, admission, matching, and the turn loop. Everything else — sync,
queues, effects, clocks, content, retention — is a fact family under facts/.

Projectors ARE the routers: the kernel runs one root projector, and a Router
is just a projector that dispatches on the next type-tag segment. Extraction
routes through the same tree.

Derived state (validity memo, clean twin, slices, frontier) is rebuildable
from the durable fact set alone: `replay()` is the whole crash story. With a
Store, replay is demand-driven: a stepped fact's needs pull matching cold
facts resident (hydration), so a session pays for what it asks about.

Stand-in: BLAKE2b-256 for BLAKE3-256 (stdlib has no BLAKE3).
"""
from collections import deque
from dataclasses import dataclass, field, replace
from itertools import chain
import hashlib, time

H = lambda b: hashlib.blake2b(b, digest_size=32).digest()
now = lambda: int(time.time())           # host convenience; never engine input

def frame(*ps):                          # ‖ : length-framed concat (injective)
    assert all(len(p) < 2**32 for p in ps)
    return b"".join(len(p).to_bytes(4, "little") + p for p in ps)

def _rd(b, i):                           # read one frame, strict
    n = int.from_bytes(b[i:i + 4], "little"); j = i + 4 + n
    if j > len(b): raise ValueError("truncated")
    return b[i + 4:j], j

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
def window(lo=0, hi=2**64 - 1, budget=2**32 - 1, order=0):
    return (lo.to_bytes(8, "little") + hi.to_bytes(8, "little")
            + budget.to_bytes(4, "little") + bytes([order]))

_window = lambda v: (int.from_bytes(v[:8], "little"), int.from_bytes(v[8:16], "little"),
                     int.from_bytes(v[16:20], "little"), v[20])

class Store:
    """The durable index: persisted facts not yet resident (cold), keyed by
    fid, plus one materialized offer row per atom under its (role, scope) key.
    Outside the trust boundary — the host feeds it frames, and every pull
    re-enters through checked admission, so wrong bytes are a miss. Popping a
    pulled fact from cold is the per-fact dedup: re-scanning a window never
    delivers the same owner twice."""

    def __init__(self):
        self.ids, self.cold, self.idx = set(), {}, {}   # all fids ; fid -> bytes ; key -> rows

    def add(self, fb):                   # checked load: bad bytes are a miss
        try: f = decode(fb)
        except Exception: return
        fid = fact_id(f)
        if fid in self.ids: return
        self.ids.add(fid); self.cold[fid] = fb
        for a in f.atoms:
            if a.kind == OFFER:
                m = mat(a, fid)
                self.idx.setdefault((m.role, m.scope), []).append((ts_of(f), fid, m))

    def pull(self, need):                # cold matches, (ts, fid) order, budget = primary hits
        rows = [r for r in self.idx.get((need.role, need.scope), ())
                if r[1] in self.cold and covers(r[2].target, need.target)]
        rows.sort(key=lambda r: (r[0], r[1]))
        budget = None
        if need.effect == WATCH and need.value and len(need.value) == 21:
            lo, hi, budget, order = _window(need.value)
            rows = [r for r in rows if lo <= r[0] <= hi]
            if order: rows.reverse()
        fids = list(dict.fromkeys(r[1] for r in rows))
        return [self.cold.pop(x) for x in (fids if budget is None else fids[:budget])]

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
        self.rows, self.intake = [], []      # asserted index + session overlay: (owner, atom)
        self.memo, self.clean = {}, []       # id -> verdict ; validated offers (owner, ts, atom)
        self.slices = {}                     # key -> (owner, ts, value), LWW by (ts, owner)
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
        self.intake += [(fid, mat(a, fid)) for a in f.atoms]
        self.frontier.append(fid)
        return fid

    # Both match directions run over index ∪ intake; the overlay is transparent.
    def _hit(self, need, offer): return ((offer.role, offer.scope) ==
                                         (need.role, need.scope) and covers(offer.target, need.target))
    def offers_for(self, need):          # asserted, dirty: discovery only
        return [(o, a) for o, a in chain(self.rows, self.intake)
                if a.kind == OFFER and self._hit(need, a)]
    def needs_for(self, offer):          # wake fanout direction
        return [(o, a) for o, a in chain(self.rows, self.intake)
                if a.kind == NEED and self._hit(a, offer)]
    def valid_offers(self, need):        # the clean twin: the only justifier
        return [r for r in self.clean if self._hit(need, r[2])]

    # Engine drain — bounded; overflow parks on the frontier, never drops.
    def turn(self, bound=64):
        for _ in range(min(bound, len(self.frontier))):
            self._step(self.frontier.popleft())
        self.rows += self.intake; self.intake = []   # flush: moves rows, changes no result

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
        if any(self.valid_offers(n) for n in ns if n.effect == SUPPRESS):
            out = Out("Suppressed")
        elif any(not self.valid_offers(n) for n in ns if n.effect == REQUIRE):
            out = Out("Parked")
        else:                            # Context<Validated>; Watch never gates
            ctx = {n: self.valid_offers(n) for n in ns if n.effect in (REQUIRE, WATCH)}
            out = self.root.project(f, ctx, dict(self.slices)) or Out("Parked")
        self._promote(fid, f, out)

    def _promote(self, fid, f, out):
        self.memo[fid] = out.verdict
        old = {(t, a) for o, t, a in self.clean if o == fid}
        new = ({(ts_of(f), mat(a, fid)) for a in out.offers}
               if out.verdict == "Valid" else set())
        # Owner-scoped replacement: old and new output are never both visible.
        self.clean = [r for r in self.clean if r[0] != fid] + [(fid, t, a) for t, a in new]
        self.slices = {k: v for k, v in self.slices.items() if v[0] != fid}
        if out.verdict == "Valid":
            for k, v in out.slice_delta.items():
                cur = self.slices.get(k)
                if not cur or (cur[2], cur[0]) <= (ts_of(f), fid):
                    self.slices[k] = (fid, v, ts_of(f))
        for _, a in old ^ new:           # wake fanout on every changed offer
            for o, _ in self.needs_for(a):
                if o != fid and o not in self.frontier: self.frontier.append(o)

    # Host out — the host drains validated offers at keys it watches, performs
    # external work, and admits facts reporting what happened. It never writes.
    def watched(self, role, scope):
        return [r for r in self.clean if (r[2].role, r[2].scope) == (role, scope)]

    # Crash story: derived state is a pure, order-independent function of the
    # durable set. Volatile facts vanish — completeness, never coherence.
    def replay(self, order=None):
        m = Node(self.root)
        for fid in (order or list(self.durable)): m.admit(self.durable[fid], checked=True)
        return m.run()

    def derived(self):
        return (sorted((o, t, enc_atom(a)) for o, t, a in self.clean),
                sorted((k, *v) for k, v in self.slices.items()),
                sorted(self.memo.items()))
