"""facts/connection/fact_receipt.py — the daemon's record that a fact arrived
over the wire (poc-10 tag 164): the received fact id, the path it came in on
(request or frame), the origin address, and a frame hash. Durable + LocalOnly:
replay re-derives the responder's work from it (the origin address a connection
must reply to), and it is never authority for anything — it only gates the
sealed request's `respond` emission (proof the request actually arrived here)
and marks an opened frame drained. A receipt is the daemon's observation, so
it is authored host-in, never by a projector."""
from kernel import Atom, Exact, OFFER, Out, encode, fact, frame, now, ts_atom

TAG = b"connection.fact_receipt"
SC = b"conn"
REQUEST, FRAME = 0, 1                     # the path a fact arrived on

# SHAPE — the canonical atom set; the only place atoms are chosen.
def receipt(received_id, path, origin, frame_hash, t):
    return fact(TAG, ts_atom(t, SC),
                Atom(OFFER, b"receipt", SC, Exact(received_id),
                     frame(bytes([path]), origin, frame_hash)))

# EXTRACT — content-pure: (durable, LocalOnly). Receive metadata never syncs.
def extract(f): return True, False

# PROJECT — publish the receipt at the received fact's id.
def project(f, ctx, sl):
    return Out(offers=tuple(a for a in f.atoms if a.role == b"receipt"))

# COMMANDS — the daemon records one per inbound fact. Build, admit, stop.
def observe(node, received_id, origin, path=REQUEST, t=None):
    return node.admit(encode(receipt(received_id, path, origin, b"", int(t or now()))))

# QUERIES — none: a receipt is read only as the offer the request Watches.

# CLI — no verbs: only the daemon authors receipts.
CLI = {}
