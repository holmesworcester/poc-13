"""facts/connection/close.py — ends a session by naming the request it retires.
Durable + LocalOnly: a closed peer stays closed across restart, and the decision
never syncs. It offers `closed` at the request's id, which the request
Suppress-needs at SELF (the death key the request carries), so admitting a close
flips that request to Suppressed — the daemon drops the socket and stops dialing.
Suppression, not deletion: the request's atoms remain until retention purges."""
from kernel import Atom, Exact, OFFER, Out, encode, fact, now, ts_atom

TAG = b"connection.close"
SC = b"conn"

# SHAPE — the canonical atom set; the only place atoms are chosen.
def close(request_id, t):
    return fact(TAG, ts_atom(t, SC),
                Atom(OFFER, b"closed", SC, Exact(request_id)))

# EXTRACT — content-pure: durable + LocalOnly, exactly like the request it kills.
def extract(f): return True, False

# PROJECT — the only place this family's meaning lives.
def project(f, ctx, sl):
    return Out(offers=tuple(a for a in f.atoms if a.role == b"closed"))

# COMMANDS — build a fact, admit it, stop.
def stop(node, request_id, t):
    return node.admit(encode(close(request_id, t)))

# QUERIES — none: a close is observed only through the request it suppresses.

# CLI — string boundary over COMMANDS/QUERIES.
CLI = {"close": lambda n, rid, t=None: stop(n, bytes.fromhex(rid), int(t or now())).hex()}
