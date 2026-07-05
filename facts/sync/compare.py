"""facts/sync/compare.py — dependency-aware negentropy reconciliation, housed as
a fact family. A compare fact is one wire frame of session state: it descends the
engine's radix Merkle skeleton (kernel.Skeleton) by key PREFIX. Each claim is a
`fp` (a prefix's node label — split on mismatch, both peers agree on it exactly
when they share the leaves under that prefix), a `lst` + `has` (the leaves of a
resolved prefix, so a set-diff ships/wants them), a `want` (pull a leaf by id),
or a `need` (the reserved closure/hydrate need — a dep the sender still lacks).

Windowing is a clip on the descent: `lo_ts` sets a floor key `lo_ts‖0…`, and the
skeleton emits only the part of the tree at or above it — a prefix wholly inside
the window is one node label, a straddling one is descended, a below-floor one is
skipped. So a bounded recent window reconciles in O(depth). Below-floor deps do
NOT ride the window; instead a fact that lands parked (missing a Require) makes
the engine advertise that dep as a `need`, and the peer answers by shipping the
fact whose validated offer matches — demand-driven closure, pulled over rounds,
never a send-time walk. Leaves are (ts, FactId) over facts durable, shareable,
and Valid|Suppressed — suppressed leaves stay in, so deletions reconcile.

The pure reads — leaves / closure / _shareable — are QUERIES over the engine; the
round-trip driver is COMMANDS the daemon calls: `initiate` on connect, cadence,
or change (leaf set OR unmet-dep set — see `myfp`), `respond`/`answer_of` to an
admitted peer compare with sub-prefix descents, wants/needs, and the shipments.
Compare facts are volatile and unshareable (extract -> False, False): session
state, never replayed, never in anyone's leaves — excluded from reconciliation.
`lo_ts` defaults to 0 (whole history, floor key all-zero), so the in-process
harnesses see the full set; the daemon passes a recent floor to window."""
from kernel import (Atom, Exact, H, NEED, OFFER, Out, REQUIRE, SUPPRESS,
                    _rd, encode, fact, frame, ts_of)

TAG = b"sync.compare"
SC = b"sync"                             # scope carried by every sync atom

# SHAPE — the canonical atom set; the only place atoms are chosen. A claim is a
# fingerprint over a key-PREFIX (split on mismatch), a complete leaf list for a
# resolved prefix, or a `want`/`need` that pulls a fact by id or by need key.
_kb = lambda k: k[0].to_bytes(8, "big") + k[1]      # (ts, fid) -> 40-byte radix key
_fp = lambda ls, ks: H(b"".join(ls[k] for k in sorted(ks, key=_kb))
                       + len(ks).to_bytes(4, "little"))

fp_atom = lambda pfx, h: Atom(OFFER, b"fp", SC, Exact(pfx), h)
lst_atom = lambda pfx: Atom(OFFER, b"lst", SC, Exact(pfx))
has_atom = lambda kb: Atom(OFFER, b"has", SC, Exact(kb))    # kb = the full 40-byte key
want_atom = lambda fid: Atom(OFFER, b"want", SC, Exact(fid))
need_atom = lambda n: Atom(OFFER, b"need", SC, n.target, frame(n.role, n.scope))
_fkey = lambda lo: b"\x00" * 40 if lo <= 0 else lo.to_bytes(8, "big") + b"\x00" * 32

def _atoms(claims):                      # skeleton emit tuples -> wire atoms
    mk = {"fp": lambda c: fp_atom(c[1], c[2]), "lst": lambda c: lst_atom(c[1]),
          "has": lambda c: has_atom(c[1])}
    return [mk[c[0]](c) for c in claims]

def compare(atoms):                      # bundle claim atoms into one wire fact
    return fact(TAG, *atoms)

# EXTRACT — content-pure: (durable, shareable). Session state is neither.
def extract(f): return False, False

# PROJECT — inert: the driver reads the raw atoms; nothing promotes.
def project(f, ctx, sl): return Out()

# COMMANDS — driver functions the daemon calls; they build wire frames, not verbs.
def initiate(node, ls=None, lo_ts=0):    # a root compare over the window + the deps I still lack
    claims = _atoms(node.tree.emit(b"", _fkey(lo_ts)))
    return [encode(compare(claims + _wants(node)))]

def answer_of(node, cid, lo_ts=0):       # -> (compare frame | None, ship ids)
    if node.memo.get(cid, "Invalid") in ("Invalid", "Suppressed"):
        return None, []                  # answer nothing the engine refused
    C, T, atoms, ship = node.facts[cid], node.tree, [], []
    has = [a.target[1] for a in C.atoms if a.role == b"has"]
    for a in C.atoms:
        if a.role == b"fp":              # prefix fingerprint: descend on mismatch
            pfx = a.target[1]
            if T.label(pfx) != a.value: atoms += _atoms(T.emit(pfx, _fkey(lo_ts)))
        elif a.role == b"lst":           # complete leaf list: resolve this prefix fully
            pfx = a.target[1]
            peer = {kb for kb in has if kb.startswith(pfx)}
            mine = set(T.gather(pfx))
            ship += [kb[8:] for kb in mine - peer]                # peer lacks -> ship
            atoms += [want_atom(kb[8:]) for kb in peer - mine]    # I lack -> want
        elif a.role == b"want": ship.append(a.target[1])          # explicit leaf pull
        elif a.role == b"need":          # the peer's reserved closure need: ship what answers it
            role, i = _rd(a.value, 0); scope, _ = _rd(a.value, i)
            n = Atom(NEED, role, scope, a.target, effect=REQUIRE)
            ship += [r[0] for r in node.valid_offers(n)]          # the dep fact(s), by validated offer
    # The window ships bare leaves; a below-floor dep rides in only when the peer's
    # closure need pulls it — so ship exactly the shareable facts asked for.
    out = list(dict.fromkeys(fid for fid in ship if _shareable(node, fid)))
    outbound = atoms + _wants(node)      # piggyback my own unmet deps on the answer
    return (encode(compare(outbound)) if outbound else None), out

def respond(node, cid, lo_ts=0):         # the answer as wire frames (in-process harnesses)
    cmp_frame, ship = answer_of(node, cid, lo_ts)
    return ([cmp_frame] if cmp_frame else []) + [node.durable[x] for x in ship]

# QUERIES — the pure algorithm; reads the engine, authority for nothing.
def _wants(node):                        # my reserved closure needs as wire atoms
    return [need_atom(n) for n in node.missing_needs()]

def _shareable(node, fid):               # a reconcilable fact: durable, shareable, Valid|Suppressed
    return (fid in node.durable and node.memo.get(fid) in ("Valid", "Suppressed")
            and node.root.extract(node.facts[fid])[1])

def leaves(node, lo_ts=0):               # the reconciliation set: (ts, FactId) -> leaf hash
    return dict(node.leafset)            # the engine's incrementally-kept leaf set (poc-12 skeleton)

def closure(node, fid):                  # Require ancestors + suppressors, transitively (poc-12 D(W))
    out, todo = set(), {fid}              # walks the engine's validated_deps memo, not a fresh graph scan
    while todo:
        x = todo.pop(); out.add(x)
        todo |= node.validated_deps(x) - out
    return out

def myfp(node, lo_ts=0):                 # change fingerprint: reopen a round when leaves OR unmet deps move
    needs = sorted(H(frame(n.role, n.scope)) for n in node.missing_needs())
    return H(node.leaf_xor.to_bytes(32, "big") + b"".join(needs))

# CLI — no verbs: sync has no human authoring surface, only drivers.
CLI = {}
