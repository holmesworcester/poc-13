"""The host's report that an intent's effect happened, as a fact — the host
never mutates validated state directly."""
from kernel import Atom, Exact, OFFER, Out, fact, ts_atom

TAG = b"outbox.performed"

def performed(intent_id, t):
    return fact(TAG, ts_atom(t, b"outbox"),
                Atom(OFFER, b"done", b"outbox", Exact(intent_id)))

def extract(f): return True, False

def project(f, ctx, sl):
    return Out(offers=tuple(a for a in f.atoms if a.role == b"done"))
