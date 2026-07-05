"""facts/sync/compare.py — dependency-aware negentropy as a single-range descent.
A compare fact carries one key PREFIX, the sender's fingerprint for that prefix,
and a window floor. Admitting it asks the engine for my `summary` of that prefix
(the reserved need): my own label, my child fingerprints, and — at a prefix that
resolves to a leaf — that leaf plus its deduped dependency-closure ids. The
projector then reconciles that ONE range:

  * my label == the sender's fingerprint  -> the ranges agree, prune (emit nothing);
  * mismatch at an internal prefix         -> emit one child compare per child,
                                              each carrying MY child label (we split);
  * mismatch at a leaf prefix              -> emit a `have` per leaf + closure id.

Descent is symmetric: each compare carries its sender's label, the receiver checks
it against its own and splits its own children, so both trees advertise their
leaves and each side pulls what it lacks (have -> need -> ship). No rounds: it is
content-addressed and self-deduping, so an overlapping re-descent under latency
only wastes bounded work; convergence is fingerprint agreement, re-checked each
cadence. Volatile (extract -> False, False): session state, never a leaf itself.
A bare root (fingerprint b"") never matches, so opening one always emits my
children — that is how a driver bootstraps a round without knowing the peer."""
from kernel import (Atom, Exact, OFFER, Out, SUM_ROLE, by, encode, fact,
                    summary_need, shipped_need, ts_atom)
from facts.sync.have import have

TAG = b"sync.compare"
SC = b"sync"
_tgt = lambda f, r: next((a.target[1] for a in f.atoms if a.role == r), b"")
_val = lambda f, r: next((a.value for a in f.atoms if a.role == r), b"")
_send = lambda cid, blob: Atom(OFFER, b"send", b"outbox", Exact(cid), blob)

# SHAPE — cid + (prefix, floor) + the sender's fingerprint for the prefix; the
# summary Watch makes the engine deliver my label/children/leaves for the prefix.
def compare(cid, pfx, floor, fp):
    return fact(TAG, ts_atom(0, SC),
                Atom(OFFER, b"cid",  SC, Exact(cid)),
                Atom(OFFER, b"pfx",  SC, Exact(pfx), floor),   # target = prefix, value = window floor key
                Atom(OFFER, b"peer", SC, Exact(pfx), fp),      # the sender's fingerprint for the prefix
                summary_need(pfx, floor),
                shipped_need)

# EXTRACT — content-pure: (durable, shareable). Session state is neither.
def extract(f): return False, False

# PROJECT — reconcile one range from my summary: prune, split, or advertise leaves.
def project(f, ctx, sl):
    if by(ctx, b"shipped"): return Out("Reap")
    cid = _tgt(f, b"cid"); pfx = _tgt(f, b"pfx"); floor = _val(f, b"pfx"); peer = _val(f, b"peer")
    S = by(ctx, SUM_ROLE)
    mine = next((a.value for _, _, a in S if a.role == b"fp" and a.target[1] == pfx), b"")
    if peer and peer == mine: return Out("Reap")                # ranges agree: done — reap, don't linger
    kids  = [(a.target[1], a.value) for _, _, a in S if a.role == b"fp" and a.target[1] != pfx]
    haves = [a.target[1] for _, _, a in S if a.role == b"has"]  # leaves + their closure ids (40-byte keys)
    if kids:                                                     # internal: split, one child compare each
        out = [_send(cid, encode(compare(cid, cp, floor, lbl))) for cp, lbl in kids]
    elif haves:                                                 # my leaf: advertise what I hold here, by id
        out = [_send(cid, encode(have(cid, kb[8:]))) for kb in haves]
    else:                                                       # I am empty here but the peer is not: solicit
        out = [_send(cid, encode(compare(cid, pfx, floor, mine)))]   # my empty fingerprint -> peer advertises
    return Out(offers=tuple(out))

# COMMANDS — open a round toward a connection: a bare root that emits my children.
def open_round(node, cid, floor=b""):
    return node.admit(encode(compare(cid, b"", floor, b"")))

# QUERIES — none: the engine answers the summary need straight into project().

# CLI — no verbs.
CLI = {}
