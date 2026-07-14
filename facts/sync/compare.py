"""facts/sync/compare.py — range-based set reconciliation (RBSR; Meyer,
rbsr_nonhomomorphic) as one bundled fact. A compare carries a set of CLAIMS about
key ranges — `fp` (a range's fingerprint) or `ids` (the complete id list of a small
range) — and, paired with each claim, a reserved summary Gather so whoever admits
the compare has the engine hand back its OWN view of that range (fingerprint + the
range's B-way equal-count split, or its id list when small). The projector then
reconciles each claim against that view:

  * fp that matches mine            -> answer `done` for the range — the explicit
                                       match that lets a fully-agreed round become a
                                       CERTIFICATE instead of a silent prune;
  * fp that differs                 -> emit my claims for the range (my split, or my
                                       id list if the range is small on my side) —
                                       we descend, splitting by COUNT not by prefix;
  * ids naming ids I lack           -> one batched `need` pulls them; if I hold ids
                                       the peer's list omits, I re-advertise mine;
                                       identical lists are a match: `done` too.

A reply that is ALL done claims proves the opener's whole split matched — it pulses
`confirmed@cid` (folded by the cadence into its tick register, attesting the opener
it hashed) and reaps on its next wake, after every watcher has folded.

Bundled: one compare is a whole message (many ranges), so the round count is
log_B(n) and matched subranges are pruned wholesale. No rounds and no daemon
reaction: convergence is fingerprint agreement, every response is a projector Provide
at the connection's outbox key, and a dropped frame just re-descends next cadence.
Volatile (extract -> False): session state, never itself a leaf."""
from bisect import bisect_left
from kernel import (Atom, Exact, PROVIDE, Out, Range, GATHER, by, encode,
                    fact, now_gather, shipped_gather, ts_atom, unframe)
from facts.sync.index import SUM_NAME, summary_gather
from facts.sync.need import need

TAG = b"sync.compare"
SC = b"sync"
HI = b"\xff" * 41                        # an upper bound above every 40-byte key (half-open domain end)
_tgt = lambda f, r: next((a.target[1] for a in f.atoms if a.name == r), b"")
_send = lambda cid, blob: Atom(PROVIDE, b"send", b"outbox", Exact(cid), blob)
def sorted_claims(S):                    # my split claims (cfp|cids) as wire claims, sorted by low key
    return sorted((*a.target, b"fp" if a.name == b"cfp" else b"ids", a.value)
                  for _, _, a in S if a.name in (b"cfp", b"cids"))
def claims_within(claims, los, lo, hi):  # the claims fully inside [lo,hi), by bisect (claims are disjoint)
    out, i = [], bisect_left(los, lo)    # first claim with low >= lo; scan forward while still below hi
    while i < len(claims) and claims[i][0] < hi:
        clo, chi, name, val = claims[i]; i += 1
        if chi <= hi: out.append((name, clo, chi, val))
    return out

# SHAPE — a compare bundles claims (fp | ids) over key ranges, each paired with the
# reserved summary Gather (carrying the window floor, so the admitter's engine answers
# with its own view AND, when windowed, the below-floor deps of each small range).
def compare(cid, claims, floor=b"", pulse=False):   # claims: list of (name, lo, hi, payload)
    atoms = [ts_atom(0, SC), Atom(PROVIDE, b"cid", SC, Exact(cid)),
             Atom(PROVIDE, b"floor", SC, Exact(cid), floor), shipped_gather]
    if pulse:                            # an all-done reply: it will pulse confirmed@cid
        atoms += [now_gather(0),           # and gathers a next-tick wake plus sight of its
                  Atom(GATHER, b"confirmed", SC, Exact(cid))]   # own pulse to reap
    for name, lo, hi, payload in claims:
        atoms.append(Atom(PROVIDE, name, SC, Range(lo, hi), payload))
        if name != b"done": atoms.append(summary_gather(lo, hi, floor))   # done: nothing to reconcile
    return fact(TAG, *atoms)

# EXTRACT — volatile session state.
def extract(f): return False

# PROJECT — reconcile each peer claim against my summary; emit my claims + pulls.
def project(f, ctx):
    if by(ctx, b"shipped"): return Out("Reap")
    cid = _tgt(f, b"cid")
    floor = next((a.value for a in f.atoms if a.name == b"floor"), b"")   # the window floor rides for re-threading
    S = by(ctx, SUM_NAME)                                            # my view of each claimed range
    myfp   = {a.target: a.value for _, _, a in S if a.name == b"fp"}
    mycids = {a.target: a.value for _, _, a in S if a.name == b"cids"}
    claims = sorted_claims(S); los = [c[0] for c in claims]         # sorted once, range-restricted by bisect
    within = lambda R: claims_within(claims, los, R[0], R[1])       # my claims inside a range, as wire claims
    out, want, seen = [], [], set()                                 # out: claims to descend; want: ids to pull
    for a in f.atoms:
        if a.name not in (b"fp", b"ids"): continue                  # a peer claim
        R = a.target
        if a.name == b"fp":
            if myfp.get(R) == a.value:                              # ranges agree: say so
                out.append((b"done", R[0], R[1], b"")); continue
            out += within(R)                                        # differ: descend / advertise my side
        elif R in mycids:                                           # peer id list, small on my side too: diff
            mset, pids = set(unframe(mycids[R])), unframe(a.value)
            for x in pids:                                          # accumulate what I lack (deduped, ordered)
                if x not in mset and x not in seen: seen.add(x); want.append(x)
            if mset - set(pids): out.append((b"ids", R[0], R[1], mycids[R]))   # I hold extras: re-advertise
            elif not [x for x in pids if x not in mset]:            # identical lists: a match
                out.append((b"done", R[0], R[1], b""))
        else:                                                       # peer id list, large on my side: descend
            out += within(R)
    provides = []
    if want: provides.append(_send(cid, encode(need(cid, want))))     # ONE batched pull for everything I lack
    live = [c for c in out if c[0] != b"done"]
    if out and (live or want):           # something to descend or advertise: reply (done
        provides.append(_send(cid, encode(compare(cid, out, floor))))    # claims ride along)
    elif out:                            # EVERY claim matched: the round is a certificate —
        provides.append(_send(cid, encode(compare(cid, out, floor, pulse=True))))
    if provides: return Out(provides=tuple(provides))
    if any(a.relationship == GATHER and a.name == b"confirmed" for a in f.atoms):
        if by(ctx, b"confirmed"): return Out("Reap")    # I am the arriving certificate:
        return Out(provides=(Atom(PROVIDE, b"confirmed", SC, Exact(cid)),))   # pulse once, reap
    return Out("Reap")                   # fully pruned, nothing to pull: done — reap
                                         # (done claims in a reply that also pulled are
                                         # information only — not a certificate)

# COMMANDS — open a round: a bare fp-claim (b"" never matches) over the windowed
# domain, so admitting it emits my split toward the peer without knowing theirs.
def open_round(node, cid, floor=b""):
    return node.admit(encode(compare(cid, [(b"fp", floor or b"", HI, b"")], floor)))

# QUERIES — none: the summary Gather is answered by the engine straight into project().

# CLI — no verbs.
CLI = {}
