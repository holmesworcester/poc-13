"""facts/clock/tick.py — the clock driver: host time as facts, demand-driven.

A tick is one volatile fact offering `tick` at its 100ms bucket; the daemon
admits at most one per loop, and only while some fact keeps a standing `alarm`
offer at a due deadline — zero alarms, zero ticks, ever. THE RETRY IDIOM
(reused by any family that awaits an answer): bake a bounded backoff schedule
of `alarm` offers at authoring (facts are immutable — a deadline can never
move, so the schedule is chosen up front); Watch — never Require — `tick` over
the bounded window Range(first deadline, last + GRACE), so a resolved or
expired fact stops matching new ticks and can never storm; project drops the
alarms (and the send/intent offers they pace) the moment the resolution key
appears in ctx. The daemon side: standing alarms set the select timeout, and
a newly crossed deadline clears the owner's process-local shipped marker so
its standing send offers re-stage — operational repetition stays host-side,
policy (deadlines, what to offer, when to stop) stays in the fact."""
from kernel import Atom, Exact, NEED, OFFER, Out, Range, WATCH, encode, fact

TAG = b"clock.tick"
SC = b"clock"
BUCKET = 100                             # ms; a tick's identity is its bucket
GRACE = 60_000                           # ms; how long past a deadline ticks still wake

t8 = lambda ms: ms.to_bytes(8, "big")    # clock keys: 8-byte BE milliseconds
_ms = lambda b: int.from_bytes(b, "big")

# SHAPE — the canonical atom set; the only place atoms are chosen.
def tick(t_ms):
    return fact(TAG, Atom(OFFER, b"tick", SC, Exact(t8(t_ms // BUCKET * BUCKET))))

def alarm_atom(deadline_ms):             # families offer these to demand ticks
    return Atom(OFFER, b"alarm", SC, Exact(t8(deadline_ms)))

def tick_watch(first_ms, last_ms):       # families Watch this bounded window
    return Atom(NEED, b"tick", SC, Range(t8(first_ms), t8(last_ms + GRACE)), effect=WATCH)

# EXTRACT — content-pure: (durable, shareable). A session's clock dies with it.
def extract(f): return False, False

# PROJECT — must promote: Watch ctx reads only the clean twin.
def project(f, ctx, sl):
    return Out(offers=tuple(a for a in f.atoms if a.role == b"tick"))

# COMMANDS — build a fact, admit it, stop.
def strike(node, t_ms):
    return node.admit(encode(tick(t_ms)))

# QUERIES — observations over validated state only.
def alarms(node):                        # [(owner, deadline_ms)], soonest first
    return sorted(((o, _ms(a.target[1])) for o, _, a in node.watched(b"alarm", SC)),
                  key=lambda x: x[1])

def next_alarm(node):                    # earliest standing deadline, or None
    al = alarms(node)
    return al[0][1] if al else None

# CLI — no verbs: the clock has no human authoring surface, only the daemon.
CLI = {}
