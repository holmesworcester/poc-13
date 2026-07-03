"""facts/outbox/intent.py — an effect intent: offers `send` at the
host-watched outbox key until a performed fact — which it Watches, never
Requires — reports the effect happened."""
from kernel import (Atom, Exact, NEED, OFFER, Out, SELF, WATCH, by, encode,
                    fact, now, ts_atom)
from facts.store import hydrate

TAG = b"outbox.intent"

# SHAPE — the canonical atom set; the only place atoms are chosen.
def intent(dest, payload, t):
    return fact(TAG, ts_atom(t, b"outbox"),
                Atom(OFFER, b"send", b"outbox", Exact(dest), payload),
                Atom(NEED, b"done", b"outbox", SELF, effect=WATCH))

# EXTRACT — content-pure: (durable, shareable). A local queue never syncs.
def extract(f): return True, False

# PROJECT — the only place this family's meaning lives.
def project(f, ctx, sl):
    if by(ctx, b"done"): return Out()    # effect reported: stop offering
    return Out(offers=tuple(a for a in f.atoms if a.role == b"send"))

# COMMANDS — build a fact, admit it, stop.
def queue(node, dest, payload, t):
    return node.admit(encode(intent(dest, payload, t)))

# QUERIES — observations over validated state only, ordered by (ts, owner).
def pending(node):
    hydrate.demand(node, b"send", b"outbox"); node.run()
    return sorted(node.watched(b"send", b"outbox"), key=lambda r: (r[1], r[0]))

# CLI — string boundary over COMMANDS/QUERIES.
CLI = {"queue": lambda n, dest, p, t=None: queue(n, dest.encode(), p.encode(),
                                                 int(t or now())).hex(),
       "pending": lambda n: "\n".join(f"{o.hex()} {a.target[1].decode()} {a.value.decode()}"
                                      for o, _, a in pending(n))}
