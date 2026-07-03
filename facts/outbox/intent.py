"""An effect intent: offers `send` at the host-watched outbox key until a
performed fact — which it Watches, never Requires — reports the effect."""
from kernel import Atom, Exact, NEED, OFFER, Out, SELF, WATCH, by, fact, ts_atom

TAG = b"outbox.intent"

def intent(dest, payload, t):
    return fact(TAG, ts_atom(t, b"outbox"),
                Atom(OFFER, b"send", b"outbox", Exact(dest), payload),
                Atom(NEED, b"done", b"outbox", SELF, effect=WATCH))

def extract(f): return True, False       # a local queue never syncs

def project(f, ctx, sl):
    if by(ctx, b"done"): return Out()    # effect reported: stop offering
    return Out(offers=tuple(a for a in f.atoms if a.role == b"send"))
