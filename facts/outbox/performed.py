"""facts/outbox/performed.py — the host's report that an intent's effect
happened, as a fact: the host never mutates validated state directly."""
from kernel import Atom, Exact, OFFER, Out, encode, fact, now, ts_atom

TAG = b"outbox.performed"

# SHAPE — the canonical atom set; the only place atoms are chosen.
def performed(intent_id, t):
    return fact(TAG, ts_atom(t, b"outbox"),
                Atom(OFFER, b"done", b"outbox", Exact(intent_id)))

# EXTRACT — content-pure: (durable, shareable).
def extract(f): return True, False

# PROJECT — the only place this family's meaning lives.
def project(f, ctx, sl):
    return Out(offers=tuple(a for a in f.atoms if a.role == b"done"))

# COMMANDS — build a fact, admit it, stop.
def report(node, intent_id, t):
    return node.admit(encode(performed(intent_id, t)))

# QUERIES — none yet.

# CLI — string boundary over COMMANDS/QUERIES.
CLI = {"report": lambda n, iid, t=None: report(n, bytes.fromhex(iid),
                                               int(t or now())).hex()}
