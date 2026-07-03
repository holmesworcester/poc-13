"""Semantic deletion: a valid `dead` offer at the target's id flips every
fact carrying that death key to Suppressed."""
from kernel import Atom, Exact, OFFER, Out, fact, ts_atom

TAG = b"chat.tombstone"

def tombstone(channel, target_id, t):
    return fact(TAG, ts_atom(t, channel),
                Atom(OFFER, b"dead", channel, Exact(target_id)))

def extract(f): return True, True        # tombstones must travel

def project(f, ctx, sl):
    return Out(offers=tuple(a for a in f.atoms if a.role == b"dead"))
