"""facts/sync/reply.py — one sync answer as a send intent. A reply carries the
compare frame and the missing-leaf shipments that answering a peer's compare (or
opening a fresh root compare) calls for, offered at the host-watched outbox
keys until the daemon reports the flush (shipped@SELF), on which it reaps.
Shipments ride by reference — fact ids, resolved against the durable set at
send time, so a queued shipment is never stale bytes. Deps are not bundled here:
a below-floor dep rides in only when the receiver's reserved closure need pulls
it (see compare.py), never a send-time walk. Volatile session state: a reply dies with the
session and is never resent on restart; the next cadence compare regenerates
whatever still matters (poc-10: network_outgoing is a TEMP table)."""
from kernel import (Atom, Exact, OFFER, Out, by, encode, fact, frame,
                    shipped_need, ts_atom)
from facts.sync import compare

TAG = b"sync.reply"
SC = b"outbox"                           # replies live at the outbox keys
CHUNK = 256                              # fact ids per ship offer (~9 KiB of value)

# SHAPE — the canonical atom set; the only place atoms are chosen.
def reply(dest, cmp_frame, ship_ids, t):
    atoms = [ts_atom(t, SC), shipped_need]
    if cmp_frame:
        atoms.append(Atom(OFFER, b"send", SC, Exact(dest), cmp_frame))
    for i in range(0, len(ship_ids), CHUNK):
        atoms.append(Atom(OFFER, b"ship", SC, Exact(dest), frame(*ship_ids[i:i + CHUNK])))
    return fact(TAG, *atoms)

# EXTRACT — content-pure: (durable, shareable). Session state is neither.
def extract(f): return False, False

# PROJECT — offer the queue rows until the flush report, then reap.
def project(f, ctx, sl):
    if by(ctx, b"shipped"): return Out("Reap")   # flushed: the queue rows vanish
    return Out(offers=tuple(a for a in f.atoms if a.role in (b"send", b"ship")))

# COMMANDS — build a fact, admit it, stop.
def answer(node, cid, dest, t, lo_ts=0):     # answer an admitted peer compare (windowed set)
    cmp_frame, ship = compare.answer_of(node, cid, lo_ts)
    if not cmp_frame and not ship: return None
    return node.admit(encode(reply(dest, cmp_frame, ship, t)))

def open_round(node, dest, t, root=None):    # a fresh root compare toward dest (root pre-windowed)
    return node.admit(encode(reply(dest, root or compare.initiate(node)[0], [], t)))

# QUERIES — none: the daemon's pump reads the outbox keys directly.

# CLI — no verbs: sync has no human authoring surface, only drivers.
CLI = {}
