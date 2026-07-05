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
from kernel import (Atom, Exact, OFFER, Out, Range, SUM_ROLE, by, encode, fact,
                    summary_need, shipped_need, ts_atom, _rd)
from facts.sync.need import need

TAG = b"sync.compare"
SC = b"sync"
HI = b"\xff" * 41                        # an upper bound above every 40-byte key (half-open domain end)
_tgt = lambda f, r: next((a.target[1] for a in f.atoms if a.role == r), b"")
_send = lambda cid, blob: Atom(OFFER, b"send", b"outbox", Exact(cid), blob)
def _unframe(v):
    out, i = [], 0
    while i < len(v): x, i = _rd(v, i); out.append(x)
    return out

# SHAPE — a compare bundles claims (fp | ids) over key ranges, each paired with the
# reserved summary need so the admitter's engine answers with its own view.
def compare(cid, claims):                # claims: list of (role, lo, hi, payload)
    atoms = [ts_atom(0, SC), Atom(OFFER, b"cid", SC, Exact(cid)), shipped_need]
    for role, lo, hi, payload in claims:
        atoms.append(Atom(OFFER, role, SC, Range(lo, hi), payload))
        atoms.append(summary_need(lo, hi))
    return fact(TAG, *atoms)

# EXTRACT — volatile session state.
def extract(f): return False, False

# PROJECT — reconcile each peer claim against my summary; emit my claims + pulls.
def project(f, ctx, sl):
    if by(ctx, b"shipped"): return Out("Reap")
    cid = _tgt(f, b"cid")
    S = by(ctx, SUM_ROLE)                                            # my view of each claimed range
    myfp   = {(a.target[1], a.target[2]): a.value for _, _, a in S if a.role == b"fp"}
    mycids = {(a.target[1], a.target[2]): a.value for _, _, a in S if a.role == b"cids"}
    mine   = [(a.role, a.target[1], a.target[2], a.value) for _, _, a in S if a.role in (b"cfp", b"cids")]
    def within(R):                       # my claim rows inside R, as wire (fp | ids) claims
        return [(b"fp" if k == b"cfp" else b"ids", lo, hi, v)
                for k, lo, hi, v in mine if R[0] <= lo and hi <= R[1]]
    out, offers = [], []
    for a in f.atoms:
        if a.role not in (b"fp", b"ids"): continue                  # a peer claim
        R = (a.target[1], a.target[2])
        if a.role == b"fp":
            if myfp.get(R) == a.value: continue                     # ranges agree: prune
            out += within(R)                                        # differ: descend / advertise my side
        elif R in mycids:                                           # peer id list, small on my side too: diff
            mset, pset = set(_unframe(mycids[R])), set(_unframe(a.value))
            lack = [x for x in _unframe(a.value) if x not in mset]
            if lack: offers.append(_send(cid, encode(need(cid, lack))))   # pull what I lack, batched
            if mset - pset: out.append((b"ids", R[0], R[1], mycids[R]))    # I hold extras: re-advertise
        else:                                                       # peer id list, large on my side: descend
            out += within(R)
    if out: offers.append(_send(cid, encode(compare(cid, out))))
    if not offers: return Out("Reap")    # fully pruned, nothing to pull: done — reap, don't linger
    return Out(offers=tuple(offers))

# COMMANDS — open a round: a bare fp-claim (b"" never matches) over the windowed
# domain, so admitting it emits my split toward the peer without knowing theirs.
def open_round(node, cid, floor=b""):
    return node.admit(encode(compare(cid, [(b"fp", floor or b"", HI, b"")])))

# QUERIES — none: the summary need is answered by the engine straight into project().

# CLI — no verbs.
CLI = {}
