"""facts/connection/frame.py — the throughput fact: poc-10's frame_bundle. A
volatile, unshareable wrapper whose one value is MANY length-framed canonical
fact bytes. The sync driver packs its shipments into bundles (a few KiB each)
instead of one fact per wire frame, so a receiver absorbs a whole batch per turn
instead of one fact — that is the fix for the bulk-catch-up gap, where per-turn
gating, not the pipe, set the pace. The daemon unpacks a received bundle and
admits each inner fact through the NORMAL gate; a corrupt inner is a per-fact
miss that never poisons its siblings. Never persisted, never in leaves, excluded
from sync: pure transport the daemon puts on the wire, like a sync compare."""
from kernel import Atom, OFFER, Out, SELF, _rd, encode, fact, frame

TAG = b"connection.frame"
SC = b"conn"
TARGET = 48 << 10                        # pack up to ~48 KiB of inner fact bytes per bundle

# SHAPE — the canonical atom set; the only place atoms are chosen.
def bundle(items):
    return fact(TAG, Atom(OFFER, b"bundle", SC, SELF, frame(*items)))

# EXTRACT — content-pure: volatile + unshareable. Transport, never stored,
# never synced — the daemon ships bundles explicitly, exactly like compares.
def extract(f): return False, False

# PROJECT — inert: a bundle is unpacked by the daemon, never projected.
def project(f, ctx, sl): return Out()

# COMMANDS — none: a bundle is authored onto the wire, not into the db.

# QUERIES — pure transforms over bundle bytes; authority for nothing.
def pack(items):                         # group fact frames into ~TARGET-sized bundles
    out, cur, sz = [], [], 0
    for b in items:
        if cur and sz + len(b) > TARGET: out.append(encode(bundle(cur))); cur, sz = [], 0
        cur.append(b); sz += len(b)
    if cur: out.append(encode(bundle(cur)))
    return out

def items(f):                            # a bundle fact -> its inner fact byte-frames
    v = next(a.value for a in f.atoms if a.role == b"bundle")
    out, i = [], 0
    while i < len(v): b, i = _rd(v, i); out.append(b)
    return out

# CLI — no human surface.
CLI = {}
