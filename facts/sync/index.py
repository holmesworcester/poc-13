"""facts/sync/index.py — the reconciliation set as FAMILY state: the treap, the
leaf-membership rule, and the `summary` answerer, evicted whole from the kernel.

The kernel's contribution is two generic seams. observe() lets this family
subscribe to one validated offer address and fold its deltas into a register;
answer() lets it serve a reserved need from that register. A replicating
projector emits sync_leaf(), an ordinary projected offer at leaf@sync/SELF.
Only Valid output reaches the clean twin, whose owner and timestamp are the
treap entry. Invalid, Parked, Suppressed, and Reap output no marker, so clean
replacement retracts the leaf through the same observer. What replicates is
therefore a projector decision made identically on peers running the same
family code. The index is pure register state: no wire fact carries this
module's tag, and hydration re-steps every durable fact so its projector
re-emits the marker that rebuilds the register. There is no cursor or second
rebuild path.

The set itself: range-based set reconciliation (Meyer & Scherer,
rbsr_nonhomomorphic) over 40-byte (ts‖FactId) keys, held in a TREAP — a binary
search tree on the key AND a heap on a priority. The priority is the leaf hash:
a pure function of the key, so the tree SHAPE is a function of the set alone
(history-independence) and two peers holding the same set build the same tree.
Each node caches its subtree size and a Merkle label lb = H(left.lb ‖ leaf_hash
‖ right.lb). A range fingerprint is the CLAMPED label — the label of the tree
with all out-of-range items discarded — computed by walking only the two
boundary spines (reading precomputed labels for fully-in subtrees), O(log n)
whp. Clamping-invariance makes that label a canonical function of the in-range
SET (independent of tree shape and of out-of-range items), so peers agree using
an ORDINARY hash — no homomorphic/xor fold. A mismatched range is split into B
parts of EQUAL COUNT (an order-statistic select, not a key-prefix split), so
fanout is B and depth is log_B(n) regardless of key distribution. A range of
<= T leaves is listed by id instead, ending the recursion. (A maliciously
degenerate set costs O(n) local compute; the paper shows communication,
roundtrips, and censorship-resistance stay immune.)"""
from kernel import (Atom, Exact, H, NEED, OFFER, Range, Row, SELF, WATCH,
                    answer, frame, observe, ts_of)

TAG = b"sync.index"                      # the namespace claim; no wire fact carries it yet

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

# SHAPE — the validated marker projected by every replicating family, the
# matching Watch used by sync.need, the reserved summary need this module
# answers, and the 40-byte reconciliation key it answers over.
LEAF_ROLE, LEAF_SCOPE = b"leaf", b"sync"
sync_leaf = lambda: Atom(OFFER, LEAF_ROLE, LEAF_SCOPE, SELF)
sync_leaf_need = lambda fid: Atom(NEED, LEAF_ROLE, LEAF_SCOPE, Exact(fid), effect=WATCH)
is_sync_leaf_row = lambda row: row.atom == Atom(OFFER, LEAF_ROLE, LEAF_SCOPE, Exact(row.owner))
SUM_ROLE, _SUM = b"\x00summary", b"\x00sum"
CLOSURE_CAP = 4096                       # generous safety valve on unique closure ids per summary answer
_kb = lambda ts, fid: ts.to_bytes(8, "big") + fid            # (ts, fid) -> the 40-byte reconciliation key
summary_need = lambda lo, hi, floor=b"": Atom(NEED, SUM_ROLE, b"sync", Range(lo, hi), floor, effect=WATCH)

# EXTRACT — nothing to extract: the index is pure register state, never a fact.

# PROJECT — none: the register is written by the marker observer below and read
# through the summary answerer, not by a projector of its own.

# COMMANDS — the writes. The register: one dict at scope b"sync", shared by
# every opted-in family and created on first touch — tree (the treap), leaves
# (fid membership, to detect the no-op delta), ver (a cheap "my set moved"
# counter, never a hash), memo (summary rows, reused while the set holds still).
def _reg(node):
    return node.regs.setdefault(b"sync", {"tree": Treap(), "leaves": set(), "ver": 0, "memo": {}})

# Fold validated leaf-marker deltas into the shared treap. A fact is a leaf iff
# it is durable and its projector currently publishes exactly leaf@sync/SELF.
# Suppressed is terminal (the kernel purges the husk), so deletions reconcile
# through what DOES replicate: the deletion fact is a durable leaf, and a
# laggard peer re-shipping the purged fact costs one admission that re-derives
# Suppressed and dies on arrival.
# Its leaf hash is a constant per fid (fid/ts/bytes are all fixed), so
# membership is the only thing that changes; the fid set detects the no-op so
# a re-settlement neither re-hashes nor spuriously bumps ver.
def _observe_leaf(node, fid, f, old, new):
    reg = _reg(node)
    should = fid in node.durable and any(is_sync_leaf_row(row) for row in new)
    if should == (fid in reg["leaves"]): return         # membership unchanged: no delta
    kb = _kb(ts_of(f), fid)
    if should:
        reg["leaves"].add(fid)
        reg["tree"].insert(kb, H(frame(fid, kb[:8], H(node.durable[fid]))))
    else:
        reg["leaves"].discard(fid); reg["tree"].remove(kb)
    reg["ver"] += 1
    reg["memo"].clear()                                 # the set moved: the memoised summaries are stale

observe(LEAF_ROLE, LEAF_SCOPE, _observe_leaf)

# QUERIES — the `summary` answerer: my fingerprint for the range + my
# reconciliation claims for it (a B-way equal-count split, or the range's id
# list and its deduped dependency closure ids when the range is small), served
# straight to the engine — the closure ids are how a below-window dependency
# travels. Plus the register read back (tests, bench, daemon change-detection).
def summary(node, n):
    reg = _reg(node); lo, hi = n.target; floor = n.value or b""
    if floor > lo: lo = floor            # clip the range to the window floor
    # A summary is a pure function of the leaf set: closure ids are themselves
    # marker-owning leaves below the floor. The memo therefore lives exactly
    # while the set holds still, and the observer clears it on every change.
    cached = reg["memo"].get((lo, hi, floor))
    if cached is not None: return cached
    t = reg["tree"]
    def row(a): return Row(_SUM, 0, a)
    rows = [row(Atom(OFFER, b"fp", b"sync", Range(lo, hi), t.fp(lo, hi)))]   # the prune-check fingerprint
    def claim(a, b):                     # my claim for [a,b): the leaves (+ windowed: their below-floor deps), else a fp
        if t.small(a, b):
            ids = list(t.fids(a, b))                            # my leaves in range: always advertised (enumerate)
            if floor:                                           # a windowed round: a leaf's below-floor deps won't
                seen = set()                                    # enumerate as leaves of their own, so they ride here
                for d in ids: node.closure(d, seen)             # as closure ids — only marker owners below the floor
                ids += [d for d in seen if d in reg["leaves"]
                        and _kb(ts_of(node.facts[d]), d) < floor]
            blob = frame(*ids[:CLOSURE_CAP])                    # full round (floor==b""): leaves only — none below b""
            return row(Atom(OFFER, b"cids", b"sync", Range(a, b), blob))
        return row(Atom(OFFER, b"cfp", b"sync", Range(a, b), t.fp(a, b)))
    rows += [claim(lo, hi)] if t.small(lo, hi) else [claim(a, b) for a, b in t.parts(lo, hi)]
    reg["memo"][(lo, hi, floor)] = rows
    return rows

answer(SUM_ROLE, summary)                # claim the reserved role: the engine now asks this module

def tree(node): return _reg(node)["tree"]
def ver(node): return _reg(node)["ver"]
def contains(node, fid): return fid in _reg(node)["leaves"]

# CLI — no verbs.
CLI = {}
