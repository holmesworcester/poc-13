"""facts/sync/cadence.py — the sync round timer as volatile facts, a TIER PAIR per
connection (docs/anchor-sync.md):

  * the ANCHOR tier opens a round every (long) period UNCONDITIONALLY — the liveness
    anchor. No gate can starve it, so any persistent diff is re-descended within one
    anchor period no matter what was dropped, duplicated, reordered, or restarted.
    Its due-branch is the whole liveness proof: due -> emit my current claims.
  * the GATED fast tier carries latency: it opens only when my split has CHANGED
    since my last opener (converged silence on this tier) and has SETTLED for a full
    period (quiet while a round's cascade is still filling my set, so a catch-up
    runs as ONE cascade, not a new overlapping one per period). The gates are
    byte/latency optimizations the anchor is allowed to outlive: a starved or wrong
    fast tier costs milliseconds, never convergence.

Each tier Gathers the clock and Provides a `wake@clock` alarm at its next boundary so
the daemon sleeps exactly until then (runtime.next_wake). Its memory — last boundary,
last opener hash (`sent`), last observed hash (`seen`), and the confirmed opener hash
(`conf`) — is its own tick Provide, self-Gathered and re-emitted by EVERY branch that
saw a clock, or the memory is lost; the tick key includes period and mode, so two
tiers over one (cid, floor) never collide. Arming stays idempotent (no arm-time in
the bytes): the daemon needs no armed-marker.

The CERTIFICATE: a peer whose reply matched every claim of my opener answers all
`done`, which pulses `confirmed@cid` when that reply is admitted here. The fold
attests my last opener (`conf = sent`) only while my current split still hashes to
it — `synced` is then a locally provable predicate: someone matched fingerprints
over exactly the split I hold now. SUPPRESS_IF on `closed@conn` tears both tiers down;
being volatile, a reconnect re-arms them."""
from kernel import (Atom, Exact, H, PROVIDE, Out, SELF, SUPPRESS_IF, GATHER,
                    by, encode, fact, frame, now_gather, now_of, ts_atom, unframe)
from facts.sync.index import SUM_NAME, summary, summary_gather
from facts.sync.compare import compare, sorted_claims, HI

TAG = b"sync.cadence"
SC = b"sync"
WAKE = (b"wake", b"clock")               # the alarm name/scope the daemon reads for next_wake
ANCHOR, GATED = b"anchor", b"gated"      # tier modes: unconditional loop / changed+settled
ANCHOR_W = 4000                          # the anchor period; runtime.SENT_TTL must stay below it
_T8 = lambda ms: ms.to_bytes(8, "big")
_tgt = lambda f, r: next((a.target[1] for a in f.atoms if a.name == r), b"")
_val = lambda f, r: next((a.value for a in f.atoms if a.name == r), b"")

# SHAPE — cid in a target; floor/period/mode as values; an unbounded clock Gather, my
# domain summary, my per-tier tick register, the confirm pulse, and teardown.
def cadence(cid, floor, period_ms, mode=ANCHOR):
    return fact(TAG, ts_atom(0, SC),
                Atom(PROVIDE, b"cid",    SC, Exact(cid)),
                Atom(PROVIDE, b"floor",  SC, SELF, floor),
                Atom(PROVIDE, b"period", SC, SELF, _T8(period_ms)),
                Atom(PROVIDE, b"mode",   SC, SELF, mode),
                now_gather(0),                                     # woken by every clock the turn presents
                summary_gather(floor or b"", HI, floor),           # my claims for the (windowed) domain
                Atom(GATHER, b"tick", SC, Exact(cid + floor + _T8(period_ms) + mode)),                              # my own memory (self-Provide)
                Atom(GATHER, b"confirmed", SC, Exact(cid)),
                Atom(SUPPRESS_IF, b"closed", b"conn", Exact(cid)))

# EXTRACT — volatile session state.
def extract(f): return False

# PROJECT — hold the alarm until due; when due, the anchor opens unconditionally and
# the gated tier opens iff my split CHANGED since my last opener (`sent`) AND has
# SETTLED since the previous due tick (`seen`). A confirm pulse folds into `conf`
# only while the current opener still hashes to `sent` — a set that moved since
# retires the certificate. Every branch that saw a clock re-emits the tick.
def project(f, ctx):
    cid, floor = _tgt(f, b"cid"), _val(f, b"floor")
    period, mode = int.from_bytes(_val(f, b"period"), "big"), _val(f, b"mode")
    now = now_of(ctx)
    if now is None: return Out()                             # no clock yet: nothing to hold
    key = cid + floor + _T8(period) + mode
    tick = lambda t, sent, seen, conf: Atom(PROVIDE, b"tick", SC, Exact(key),
                                            frame(_T8(t), sent, seen, conf))
    rv = next((r[2].value for r in by(ctx, b"tick")), None)
    last, sent, seen, conf = None, b"", b"", b""
    if rv is not None:
        lb, sent, seen, conf = unframe(rv); last = int.from_bytes(lb, "big")
    body = [None]                                            # my current opener, computed at most once
    def cur():
        if body[0] is None:
            claims = [(name, lo, hi, v) for lo, hi, name, v in sorted_claims(by(ctx, SUM_NAME))]
            body[0] = encode(compare(cid, claims, floor)) if claims else b""
        return body[0]
    if by(ctx, b"confirmed") and sent:                       # the certificate: attests my last
        if cur() and H(cur()) == sent: conf = sent           # opener iff my split has not moved
    if last is None:                                         # first clock sight anchors the boundary
        return Out(provides=(Atom(PROVIDE, *WAKE, Exact(_T8(now + period))), tick(now, b"", b"", b"")))
    if now < last + period:                                  # not due: hold the alarm, CARRY the tick
        return Out(provides=(Atom(PROVIDE, *WAKE, Exact(_T8(last + period))), tick(last, sent, seen, conf)))
    provides = []
    if cur():                                                # due: open a round toward the peer
        h = H(cur())
        if mode != GATED or (seen in (b"", h) and h != sent):
            provides.append(Atom(PROVIDE, b"send", b"outbox", Exact(cid), cur()))
            if h != sent: sent, conf = h, b""                # a new opener: the old certificate dies
        seen = h
    provides += [Atom(PROVIDE, *WAKE, Exact(_T8(now + period))), tick(now, sent, seen, conf)]
    return Out(provides=tuple(provides))

# COMMANDS — arm the tier pair; idempotent (content-addressed, no arm-time field).
TIERS = ((b"", 500, GATED), (b"", ANCHOR_W, ANCHOR))         # (floor, period_ms, mode)
def arm(node, cid, tiers=TIERS):
    for floor, period, mode in tiers:
        node.admit(encode(cadence(cid, floor, period, mode)))

# QUERIES — the certificate, read back: synced iff some tier's confirmed opener hash
# still matches the opener my CURRENT split would produce.
def synced(node, cid, floor=b""):
    rows = summary(node, summary_gather(floor or b"", HI, floor))
    claims = [(name, lo, hi, v) for lo, hi, name, v in sorted_claims(rows)]
    if not claims: return False
    h = H(encode(compare(cid, claims, floor)))
    for _, _, a in node.provided(b"tick", SC):
        if a.target[0].startswith(cid + floor):
            parts = unframe(a.value)
            if len(parts) == 4 and parts[3] and parts[3] == h: return True
    return False

# CLI — no verbs.
CLI = {}
