"""facts/sync/compare.py — dependency-aware negentropy reconciliation, housed
as a fact family. A compare fact is one wire frame of session state: it carries
[lo, hi) ranges each labelled with either a fingerprint (split on mismatch) or a
complete leaf list (small ranges), plus `want` markers that pull a missing id's
closure. Sync reconciles FACTS over (ts, FactId) leaves that are durable,
shareable, and Valid|Suppressed — suppressed leaves stay in, so deletions
reconcile. A shipped id travels with its closure (Require ancestors plus
suppressors), so tombstones ride along and nothing resurrects.

The pure algorithm — leaves / fingerprint / closure — is QUERIES over the
engine; the round-trip driver is COMMANDS the daemon calls: `initiate` on
connect or leaf-fingerprint change, `respond` to an admitted peer compare with
sub-range compares, wants, and the fact shipments themselves. Compare facts are
volatile and unshareable (extract -> False, False): session state, never
replayed, never in anyone's leaves — excluded from their own reconciliation."""
from kernel import (Atom, Exact, H, OFFER, Out, REQUIRE, SUPPRESS, Range,
                    encode, fact, frame, needs_of, ts_of)

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
def initiate(node):                      # open a round: one fingerprint over the whole space
    return [encode(compare(_emit(leaves(node), LO, HI)))]

def respond(node, cid):                  # answer a peer's admitted compare with the next frames
    C, ls, atoms, ship = node.facts[cid], leaves(node), [], []
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
    frames, seen = ([encode(compare(atoms))] if atoms else []), set()
    for fid in ship:                     # each shipped id travels with its whole closure
        for x in closure(node, fid):
            if x in node.durable and x not in seen: seen.add(x); frames.append(node.durable[x])
    return frames

# QUERIES — the pure algorithm; reads the engine, authority for nothing.
_LEAF = {}                               # fid -> (key, leaf hash); content-addressed, so
def _leaf(node, fid, b):                 # write-once and node-independent — never invalidated
    e = _LEAF.get(fid)
    if e is None:
        ts = ts_of(node.facts[fid])
        e = _LEAF[fid] = ((ts, fid), H(frame(fid, ts.to_bytes(8, "little"), H(b))))
    return e

def leaves(node):                        # durable, shareable, Valid|Suppressed -> leaf hash
    out = {}                             # only membership (the memo verdict) varies per call
    for fid, b in node.durable.items():
        if node.memo.get(fid) in ("Valid", "Suppressed") and node.root.extract(node.facts[fid])[1]:
            k, h = _leaf(node, fid, b); out[k] = h
    return out

def closure(node, fid):                  # Require ancestors + suppressors, transitively
    out, todo = set(), {fid}
    while todo:
        x = todo.pop(); out.add(x)
        f = node.facts.get(x)
        if f is None: continue
        todo |= {o for n in needs_of(f, x) if n.effect in (REQUIRE, SUPPRESS)
                 for o, _ in node.offers_for(n)} - out
    return out

def myfp(node): ls = leaves(node); return _fp(ls, list(ls))   # our whole-set fingerprint

# CLI — no verbs: sync has no human authoring surface, only drivers.
CLI = {}
