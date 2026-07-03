"""facts/connection/request.py — the desire to reach a peer: a durable,
LocalOnly config fact carrying the peer's address (host:port). The daemon
watches validated `peer` offers and dials each; recurrence IS liveness — a
dropped socket redials while the request stays valid. NEVER shareable: a node's
dial list is its own config, not a fact to sync. A connection.close naming this
request suppresses it through the death key it carries here (Suppress on SELF),
so a closed peer stays closed across restart. --peer flags are bootstrap sugar:
the daemon authors one request per flag through the normal gate at startup."""
from kernel import (Atom, NEED, OFFER, Out, SELF, SUPPRESS, encode, fact, now,
                    ts_atom)

TAG = b"connection.request"
SC = b"conn"

# SHAPE — the canonical atom set; the only place atoms are chosen.
def request(addr, t):
    return fact(TAG, ts_atom(t, SC),
                Atom(OFFER, b"peer", SC, SELF, addr),
                Atom(NEED, b"closed", SC, SELF, effect=SUPPRESS))

# EXTRACT — content-pure: durable (survives restart), LocalOnly (never syncs).
def extract(f): return True, False

# PROJECT — the only place this family's meaning lives.
def project(f, ctx, sl):
    return Out(offers=tuple(a for a in f.atoms if a.role == b"peer"))

# COMMANDS — build a fact, admit it, stop.
def connect(node, addr, t):
    return node.admit(encode(request(addr, t)))

# QUERIES — the daemon's dial set: the addresses of still-valid requests.
def dials(node):
    return sorted({a.value for _, _, a in node.watched(b"peer", SC)})

# CLI — string boundary over COMMANDS/QUERIES.
CLI = {"connect": lambda n, addr, t=None: connect(n, addr.encode(), int(t or now())).hex(),
       "dials": lambda n: b"\n".join(dials(n)).decode()}
