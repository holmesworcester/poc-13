"""A chat message. Carries its own death key (Suppress on its own id, via
SELF), so deletion is local — no consumer demotion cascade."""
from kernel import Atom, Exact, NEED, OFFER, Out, SELF, SUPPRESS, fact, ts_atom

TAG = b"chat.note"

def note(channel, body, t):
    return fact(TAG, ts_atom(t, channel),
                Atom(OFFER, b"msg", channel, Exact(b"feed"), body),
                Atom(NEED, b"dead", channel, SELF, effect=SUPPRESS))

def extract(f): return True, True        # Durable + Shareable

def project(f, ctx, sl):
    return Out(offers=tuple(a for a in f.atoms if a.role == b"msg"))
