"""facts/sync/cadence.py — the sync round timer as a volatile fact, one per
(connection, tier). It Watches the clock and, once per `period`, opens a fresh
round toward the peer (emits my domain claims — pulling the peer's changes) with no
process-local daemon marker. It offers a `wake@clock` alarm at its next boundary so
the daemon sleeps exactly until then (runtime.next_wake); a slice remembers the last
boundary it fired, so although the clock re-wakes it every turn it fires at most once
per period. SUPPRESS on `closed@conn` tears it down; being volatile, a reconnect
re-arms it (poc-10: sync cadence is process-local, cleared on restart). Tiers —
narrow+frequent … wide+rare — are several of these per connection, staggered by
their first boundary."""
from kernel import (Atom, Exact, NEED, OFFER, Out, SELF, SUM_ROLE, SUPPRESS, WATCH,
                    by, encode, fact, now_need, now_of, summary_need, ts_atom)
from facts.sync.compare import compare, claims_within, HI

TAG = b"sync.cadence"
SC = b"sync"
WAKE = (b"wake", b"clock")               # the alarm role/scope the daemon reads for next_wake
_T8 = lambda ms: ms.to_bytes(8, "big")
_tgt = lambda f, r: next((a.target[1] for a in f.atoms if a.role == r), b"")
_val = lambda f, r: next((a.value for a in f.atoms if a.role == r), b"")

# SHAPE — cid in a target; floor/period/first as values; a first-boundary clock Watch,
# my domain summary, and a close Suppress for teardown.
def cadence(cid, floor, period_ms, first_ms):
    return fact(TAG, ts_atom(0, SC),
                Atom(OFFER, b"cid",    SC, Exact(cid)),
                Atom(OFFER, b"floor",  SC, SELF, floor),
                Atom(OFFER, b"period", SC, SELF, _T8(period_ms)),
                Atom(OFFER, b"first",  SC, SELF, _T8(first_ms)),
                now_need(first_ms),                              # first wake at the first boundary
                summary_need(floor or b"", HI),                  # my claims for the (windowed) domain
                Atom(NEED, b"closed", b"conn", Exact(cid), effect=SUPPRESS))   # teardown on close

# EXTRACT — volatile session state.
def extract(f): return False, False

# PROJECT — hold the alarm until due; when due, open a round and re-arm.
def project(f, ctx, sl):
    cid, floor = _tgt(f, b"cid"), _val(f, b"floor")
    period, first = int.from_bytes(_val(f, b"period"), "big"), int.from_bytes(_val(f, b"first"), "big")
    now = now_of(ctx)
    rec = sl.get((b"tick", cid, floor)); last = int.from_bytes(rec[1], "big") if rec else None
    due = (last + period) if last is not None else first
    if now is None or now < due:                             # not due: just hold the alarm at `due`
        return Out(offers=(Atom(OFFER, *WAKE, Exact(_T8(due))),))
    claims = claims_within(by(ctx, SUM_ROLE), floor or b"", HI)   # due: open a round toward the peer
    offers = [Atom(OFFER, b"send", b"outbox", Exact(cid), encode(compare(cid, claims)))] if claims else []
    offers.append(Atom(OFFER, *WAKE, Exact(_T8(now + period))))   # re-arm the next boundary
    return Out(offers=tuple(offers), slice_delta={(b"tick", cid, floor): _T8(now)})

# COMMANDS — arm the tiers for a connection (staggered first boundaries).
TIERS = ((b"", 500),)                    # (floor, period_ms): one full-domain tier by default
def arm(node, cid, now_ms, tiers=TIERS):
    for i, (floor, period) in enumerate(tiers):
        node.admit(encode(cadence(cid, floor, period, now_ms + period + i * 50)))

# QUERIES — none: the wake alarm is read off the outbox-like clock key by the daemon.

# CLI — no verbs.
CLI = {}
