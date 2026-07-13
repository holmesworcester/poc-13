"""facts/sync/compare.py — range-based set reconciliation (RBSR; Meyer,
rbsr_nonhomomorphic) as one bundled fact. A compare carries a set of CLAIMS about
key ranges — `fp` (a range's fingerprint) or `ids` (the complete id list of a small
range) — and, paired with each claim, a reserved summary need so that whoever admits
the compare has the engine hand back its OWN view of that range (fingerprint + the
range's B-way equal-count split, or its id list when small). The projector then
reconciles each claim against that view:

  * fp that matches mine            -> the range agrees, prune it;
  * fp that differs                 -> emit my claims for the range (my split, or my
                                       id list if the range is small on my side) —
                                       we descend, splitting by COUNT not by prefix;
  * ids naming ids I lack           -> one batched `need` pulls them; if I hold ids
                                       the peer's list omits, I re-advertise mine.

Bundled: one compare is a whole message (many ranges), so the round count is
log_B(n) and matched subranges are pruned wholesale. No rounds and no daemon
reaction: convergence is fingerprint agreement, every response is a projector offer
at the connection's outbox key, and a dropped frame just re-descends next cadence.
Volatile (extract -> False, False): session state, never itself a leaf."""
from bisect import bisect_left
from kernel import (Atom, Exact, OFFER, Out, Range, SUM_ROLE, by, encode, fact,
                    summary_need, shipped_need, ts_atom, unframe)
from facts.sync.need import need

TAG = b"sync.compare"
SC = b"sync"
HI = b"\xff" * 41                        # an upper bound above every 40-byte key (half-open domain end)
_tgt = lambda f, r: next((a.target[1] for a in f.atoms if a.role == r), b"")
_send = lambda cid, blob: Atom(OFFER, b"send", b"outbox", Exact(cid), blob)
def sorted_claims(S):                    # my split claims (cfp|cids) as wire claims, sorted by low key
    return sorted((a.target[1], a.target[2], b"fp" if a.role == b"cfp" else b"ids", a.value)
                  for _, _, a in S if a.role in (b"cfp", b"cids"))
def claims_within(claims, los, lo, hi):  # the claims fully inside [lo,hi), by bisect (claims are disjoint)
    out, i = [], bisect_left(los, lo)    # first claim with low >= lo; scan forward while still below hi
    while i < len(claims) and claims[i][0] < hi:
        clo, chi, role, val = claims[i]; i += 1
        if chi <= hi: out.append((role, clo, chi, val))
    return out

# SHAPE — a compare bundles claims (fp | ids) over key ranges, each paired with the
# reserved summary need (carrying the window floor, so the admitter's engine answers
# with its own view AND, when windowed, the below-floor deps of each small range).
def compare(cid, claims, floor=b""):     # claims: list of (role, lo, hi, payload)
    atoms = [ts_atom(0, SC), Atom(OFFER, b"cid", SC, Exact(cid)),
             Atom(OFFER, b"floor", SC, Exact(cid), floor), shipped_need]
    for role, lo, hi, payload in claims:
        atoms.append(Atom(OFFER, role, SC, Range(lo, hi), payload))
        atoms.append(summary_need(lo, hi, floor))
    return fact(TAG, *atoms)

# EXTRACT — volatile session state.
def extract(f): return False, False

# PROJECT — reconcile each peer claim against my summary; emit my claims + pulls.
def project(f, ctx, sl):
    if by(ctx, b"shipped"): return Out("Reap")
    cid = _tgt(f, b"cid")
    floor = next((a.value for a in f.atoms if a.role == b"floor"), b"")   # the window floor rides for re-threading
    S = by(ctx, SUM_ROLE)                                            # my view of each claimed range
    myfp   = {(a.target[1], a.target[2]): a.value for _, _, a in S if a.role == b"fp"}
    mycids = {(a.target[1], a.target[2]): a.value for _, _, a in S if a.role == b"cids"}
    claims = sorted_claims(S); los = [c[0] for c in claims]         # sorted once, range-restricted by bisect
    within = lambda R: claims_within(claims, los, R[0], R[1])       # my claims inside a range, as wire claims
    out, want, seen = [], [], set()                                 # out: claims to descend; want: ids to pull
    for a in f.atoms:
        if a.role not in (b"fp", b"ids"): continue                  # a peer claim
        R = (a.target[1], a.target[2])
        if a.role == b"fp":
            if myfp.get(R) == a.value: continue                     # ranges agree: prune
            out += within(R)                                        # differ: descend / advertise my side
        elif R in mycids:                                           # peer id list, small on my side too: diff
            mset, pids = set(unframe(mycids[R])), unframe(a.value)
            for x in pids:                                          # accumulate what I lack (deduped, ordered)
                if x not in mset and x not in seen: seen.add(x); want.append(x)
            if mset - set(pids): out.append((b"ids", R[0], R[1], mycids[R]))   # I hold extras: re-advertise
        else:                                                       # peer id list, large on my side: descend
            out += within(R)
    offers = []
    if want: offers.append(_send(cid, encode(need(cid, want))))     # ONE batched pull for everything I lack
    if out: offers.append(_send(cid, encode(compare(cid, out, floor))))   # re-thread the window floor into the descent
    if not offers: return Out("Reap")    # fully pruned, nothing to pull: done — reap, don't linger
    return Out(offers=tuple(offers))

# COMMANDS — open a round: a bare fp-claim (b"" never matches) over the windowed
# domain, so admitting it emits my split toward the peer without knowing theirs.
def open_round(node, cid, floor=b""):
    return node.admit(encode(compare(cid, [(b"fp", floor or b"", HI, b"")], floor)))

# QUERIES — none: the summary need is answered by the engine straight into project().

# CLI — no verbs.
CLI = {}
