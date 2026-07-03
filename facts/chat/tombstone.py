"""facts/chat/tombstone.py — semantic deletion. A valid `dead` offer at the
target's id flips every fact carrying that death key to Suppressed."""
from kernel import Atom, Exact, OFFER, Out, encode, fact, now, ts_atom

TAG = b"chat.tombstone"

# SHAPE — the canonical atom set; the only place atoms are chosen.
def tombstone(channel, target_id, t):
    return fact(TAG, ts_atom(t, channel),
                Atom(OFFER, b"dead", channel, Exact(target_id)))

# EXTRACT — content-pure: (durable, shareable). Tombstones must travel.
def extract(f): return True, True

# PROJECT — the only place this family's meaning lives.
def project(f, ctx, sl):
    return Out(offers=tuple(a for a in f.atoms if a.role == b"dead"))

# COMMANDS — build a fact, admit it, stop.
def delete(node, channel, target_id, t):
    return node.admit(encode(tombstone(channel, target_id, t)))

# QUERIES — none yet.

# CLI — string boundary over COMMANDS/QUERIES.
CLI = {"delete": lambda n, ch, tid, t=None: delete(n, ch.encode(),
                                                   bytes.fromhex(tid), int(t or now())).hex()}
