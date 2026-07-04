"""facts/sync/compare.py — dependency-aware negentropy reconciliation, housed
as a fact family. A compare fact is one wire frame of session state: it carries
[lo, hi) ranges each labelled with either a fingerprint (split on mismatch) or a
complete leaf list (small ranges), plus `want` markers that pull a missing id.

The reconciled leaf set is `sync_set`: every shareable fact at or after a recent
horizon `lo_ts`, PLUS the Require/suppress closure of each — so a bounded recent
window still carries every dependency (and tombstone) it needs, even deps whose
ts is far below the window (poc-12's `validated_deps` / the reserved `closure`
need). The union of per-seed closures is closure-closed by construction, so a
mismatch ships the BARE leaf: its deps are already leaves in the same set and
reconcile in their own ranges — shared deps cancel in the fingerprint, and a
suppressor rides in as its victim's closure member, so tombstones travel and
nothing resurrects. No send-time closure walk; closure is a property of the set,
computed once per round and amortizable. Leaves are (ts, FactId) over facts
durable, shareable, and Valid|Suppressed — suppressed leaves stay in, so
deletions reconcile.

The pure algorithm — sync_set / fingerprint / closure — is QUERIES over the
engine; the round-trip driver is COMMANDS the daemon calls: `initiate` on
connect, cadence, or leaf-fingerprint change, `respond` to an admitted peer
compare with sub-range compares, wants, and the fact shipments themselves.
Compare facts are volatile and unshareable (extract -> False, False): session
state, never replayed, never in anyone's leaves — excluded from reconciliation.
`lo_ts` defaults to 0 (whole history), so the in-process algorithm harnesses see
the full set; the daemon passes `now - HORIZON` to window."""
from kernel import (Atom, Exact, H, OFFER, Out, REQUIRE, SUPPRESS, Range,
                    encode, fact, frame, ts_of)

TAG = b"sync.compare"
SC = b"sync"                             # scope carried by every sync atom
LO, HI = b"", b"\xff" * 41              # the whole key space; a leaf key is 40 bytes

# SHAPE — the canonical atom set; the only place atoms are chosen.
_kb = lambda k: k[0].to_bytes(8, "big") + k[1]      # (ts, fid) -> sortable key bytes
_fp = lambda ls, ks: H(b"".join(ls[k] for k in sorted(ks, key=_kb))
                       + len(ks).to_bytes(4, "little"))
_in = lambda ls, lo, hi: [k for k in ls if lo <= _kb(k) < hi]      # keys in [lo, hi)

fp_atom = lambda lo, hi, h: Atom(OFFER, b"fp", SC, Range(lo, hi), h)
lst_atom = lambda lo, hi: Atom(OFFER, b"lst", SC, Range(lo, hi))
has_atom = lambda k: Atom(OFFER, b"has", SC, Exact(k[1]), k[0].to_bytes(8, "big"))
want_atom = lambda fid: Atom(OFFER, b"want", SC, Exact(fid))

def _emit(ls, lo, hi):                   # a range claim: leaf-list if small, else median split
    ks = sorted(_in(ls, lo, hi), key=_kb)
    if len(ks) <= 4:
        return [lst_atom(lo, hi)] + [has_atom(k) for k in ks]
    mid = _kb(ks[len(ks) // 2])
    left, right = [k for k in ks if _kb(k) < mid], [k for k in ks if _kb(k) >= mid]
    return [fp_atom(lo, mid, _fp(ls, left)), fp_atom(mid, hi, _fp(ls, right))]

def compare(atoms):                      # bundle claim atoms into one wire fact
    return fact(TAG, *atoms)

# EXTRACT — content-pure: (durable, shareable). Session state is neither.
def extract(f): return False, False

# PROJECT — inert: the driver reads the raw atoms; nothing promotes.
def project(f, ctx, sl): return Out()

# COMMANDS — driver functions the daemon calls; they build wire frames, not verbs.
def initiate(node, ls=None, lo_ts=0):    # a root compare: one fingerprint over the whole space
    return [encode(compare(_emit(leaves(node, lo_ts) if ls is None else ls, LO, HI)))]

def answer_of(node, cid, lo_ts=0):       # -> (compare frame | None, missing-leaf ship ids)
    if node.memo.get(cid, "Invalid") in ("Invalid", "Suppressed"):
        return None, []                  # answer nothing the engine refused
    C, ls, atoms, ship = node.facts[cid], leaves(node, lo_ts), [], []
    for a in C.atoms:
        if a.role == b"fp":              # fingerprint claim: split on mismatch
            lo, hi = a.target[1], a.target[2]
            if _fp(ls, _in(ls, lo, hi)) != a.value: atoms += _emit(ls, lo, hi)
        elif a.role == b"lst":           # complete leaf list: resolve the range fully
            lo, hi = a.target[1], a.target[2]
            peer = {(int.from_bytes(h.value, "big"), h.target[1]) for h in C.atoms
                    if h.role == b"has" and lo <= _kb((int.from_bytes(h.value, "big"),
                                                       h.target[1])) < hi}
            mine = set(_in(ls, lo, hi))
            ship += [k[1] for k in mine - peer]                   # peer lacks -> ship
            atoms += [want_atom(fid) for _, fid in peer - mine]   # I lack -> want
        elif a.role == b"want": ship.append(a.target[1])          # explicit pull
    # The set is closure-closed, so a missing leaf's deps are already leaves that
    # reconcile in their own ranges — ship the bare leaf, no send-time closure walk.
    out = list(dict.fromkeys(fid for fid in ship if fid in node.durable))
    return (encode(compare(atoms)) if atoms else None), out

def respond(node, cid, lo_ts=0):         # the answer as wire frames (in-process harnesses)
    cmp_frame, ship = answer_of(node, cid, lo_ts)
    return ([cmp_frame] if cmp_frame else []) + [node.durable[x] for x in ship]

# QUERIES — the pure algorithm; reads the engine, authority for nothing.
_LEAF = {}                               # fid -> (key, leaf hash); content-addressed, so
def _leaf(node, fid, b):                 # write-once and node-independent — never invalidated
    e = _LEAF.get(fid)
    if e is None:
        ts = ts_of(node.facts[fid])
        e = _LEAF[fid] = ((ts, fid), H(frame(fid, ts.to_bytes(8, "little"), H(b))))
    return e

def _shareable(node, fid):               # a reconcilable leaf: durable, shareable, Valid|Suppressed
    return (fid in node.durable and node.memo.get(fid) in ("Valid", "Suppressed")
            and node.root.extract(node.facts[fid])[1])

def frontier_ts(node):                   # newest reconcilable fact's ts: the window anchor
    return max((ts_of(node.facts[x]) for x in node.durable if _shareable(node, x)), default=0)

def window_lo(node, span):               # window floor anchored to the frontier, not the wall clock —
    return frontier_ts(node) - span      # keeps the leaf set a pure function of the fact set (determinism)

def sync_set(node, lo_ts=0):             # the closure-closed reconciliation set (see module doc)
    out = set()                          # seeds: shareable leaves inside the recent window
    for fid in node.durable:             # closure pulls each seed's deps + suppressors, even old ones
        if _shareable(node, fid) and ts_of(node.facts[fid]) >= lo_ts:
            out |= closure(node, fid)
    return {x for x in out if _shareable(node, x)}

def leaves(node, lo_ts=0):               # reconciliation set -> (ts, FactId) leaf hash
    if lo_ts <= 0:                       # floor 0: the whole set is the engine's incrementally-kept leafset
        return dict(node.leafset)        # no O(n) rebuild — poc-12 skeleton, maintained on validity delta
    return dict(_leaf(node, x, node.durable[x]) for x in sync_set(node, lo_ts))

def closure(node, fid):                  # Require ancestors + suppressors, transitively (poc-12 D(W))
    out, todo = set(), {fid}              # walks the engine's validated_deps memo, not a fresh graph scan
    while todo:
        x = todo.pop(); out.add(x)
        todo |= node.validated_deps(x) - out
    return out

def myfp(node, lo_ts=0): ls = leaves(node, lo_ts); return _fp(ls, list(ls))   # windowed-set fingerprint

# CLI — no verbs: sync has no human authoring surface, only drivers.
CLI = {}
