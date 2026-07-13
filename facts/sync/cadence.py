"""facts/sync/cadence.py — the sync round timer as a volatile fact, one per
(connection, tier). It Watches the clock and, once per `period`, opens a fresh
round toward the peer (emits my domain claims — pulling the peer's changes) with no
process-local daemon marker. It offers a `wake@clock` alarm at its next boundary so
the daemon sleeps exactly until then (runtime.next_wake); its own `tick` offer —
self-Watched, re-emitted by EVERY branch that saw a clock, or the memory is lost —
remembers the last boundary it fired, so although the clock re-wakes it every turn
it fires at most once per period. SUPPRESS on `closed@conn` tears it down; being
volatile, a reconnect re-arms it (poc-10: sync cadence is process-local, cleared on
restart). Tiers — narrow+frequent … wide+rare — are several of these per
connection."""
from kernel import (Atom, Exact, NEED, OFFER, Out, SELF, SUM_ROLE, SUPPRESS, WATCH,
                    by, encode, fact, now_need, now_of, summary_need, ts_atom)
from facts.sync.compare import compare, sorted_claims, HI

TAG = b"sync.cadence"
SC = b"sync"
WAKE = (b"wake", b"clock")               # the alarm role/scope the daemon reads for next_wake
_T8 = lambda ms: ms.to_bytes(8, "big")
_tgt = lambda f, r: next((a.target[1] for a in f.atoms if a.role == r), b"")
_val = lambda f, r: next((a.value for a in f.atoms if a.role == r), b"")

# SHAPE — cid in a target; floor/period as values; a clock Watch, my domain summary,
# and a close Suppress for teardown. No arm-time field: the same (cid, floor, period)
# is the same fact, so arming is idempotent — the daemon needs no armed-marker.
def cadence(cid, floor, period_ms):
    return fact(TAG, ts_atom(0, SC),
                Atom(OFFER, b"cid",    SC, Exact(cid)),
                Atom(OFFER, b"floor",  SC, SELF, floor),
                Atom(OFFER, b"period", SC, SELF, _T8(period_ms)),
                now_need(0),                                     # woken by every clock the turn presents
                summary_need(floor or b"", HI, floor),           # my claims for the (windowed) domain, floor for deps
                Atom(NEED, b"tick", SC, Exact(cid + floor), effect=WATCH),     # my own last-fired memory (self-offer)
                Atom(NEED, b"closed", b"conn", Exact(cid), effect=SUPPRESS))   # teardown on close

# EXTRACT — volatile session state.
def extract(f): return False, False

# PROJECT — hold the alarm until due; when due, open a round and re-arm. The tick
# memory is this fact's own validated offer, read back through its tick Watch:
# every branch below either saw no clock (so no tick can exist yet — a tick is
# only ever minted from a clock, and the clock slot never empties) or re-emits it.
def project(f, ctx):
    cid, floor = _tgt(f, b"cid"), _val(f, b"floor")
    period = int.from_bytes(_val(f, b"period"), "big")
    now = now_of(ctx)
    if now is None: return Out()                             # no clock yet: nothing to hold
    tick = lambda t: Atom(OFFER, b"tick", SC, Exact(cid + floor), _T8(t))
    lv = next((r[2].value for r in by(ctx, b"tick")), None)
    last = int.from_bytes(lv, "big") if lv is not None else None
    if last is None:                                         # first clock sight anchors the first boundary
        return Out(offers=(Atom(OFFER, *WAKE, Exact(_T8(now + period))), tick(now)))
    if now < last + period:                                  # not due: hold the alarm, CARRY the tick
        return Out(offers=(Atom(OFFER, *WAKE, Exact(_T8(last + period))), tick(last)))
    claims = [(role, lo, hi, v) for lo, hi, role, v in sorted_claims(by(ctx, SUM_ROLE))]   # due: open a round
    offers = [Atom(OFFER, b"send", b"outbox", Exact(cid), encode(compare(cid, claims, floor)))] if claims else []
    offers += [Atom(OFFER, *WAKE, Exact(_T8(now + period))), tick(now)]   # re-arm + remember this boundary
    return Out(offers=tuple(offers))

# COMMANDS — arm the tiers for a connection; idempotent (content-addressed).
TIERS = ((b"", 500),)                    # (floor, period_ms): one full-domain tier by default
def arm(node, cid, tiers=TIERS):
    for floor, period in tiers:
        node.admit(encode(cadence(cid, floor, period)))

# QUERIES — none: the wake alarm is read off the outbox-like clock key by the daemon.

# CLI — no verbs.
CLI = {}
