"""facts/outbox/sent.py — the host's receipt that a session send left the
socket, as a volatile fact: it offers `done` at the sender's id, retiring that
sender's queue-row offers the next projection. Volatile on purpose — it dies
with the session exactly like the volatile senders it retires, so a restart
wipes staged sends and their receipts together (poc-10: network_outgoing is a
TEMP table). A durable effect report is outbox.performed; this is only the
wire's own bookkeeping."""
from kernel import Atom, Exact, OFFER, Out, encode, fact, now, ts_atom

TAG = b"outbox.sent"

# SHAPE — the canonical atom set; the only place atoms are chosen.
def sent(sender_id, t):
    return fact(TAG, ts_atom(t, b"outbox"),
                Atom(OFFER, b"done", b"outbox", Exact(sender_id)))

# EXTRACT — content-pure: (durable, shareable). Session bookkeeping is neither.
def extract(f): return False, False

# PROJECT — the only place this family's meaning lives.
def project(f, ctx, sl):
    return Out(offers=tuple(a for a in f.atoms if a.role == b"done"))

# COMMANDS — build a fact, admit it, stop.
def report(node, sender_id, t):
    return node.admit(encode(sent(sender_id, t)))

# QUERIES — none: a receipt is observed only through the sender it retires.

# CLI — no verbs: only the daemon's pump authors receipts.
CLI = {}
