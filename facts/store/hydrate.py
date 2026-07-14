"""facts/store/hydrate.py — hydration is just a fact. A demand is one Gather,
and the engine answers every consumer relationship the same way: the fault leg
checks its address against the persisted atom relation and admits every cold
provider, whose own consumers then fault in turn — the step loop is the closure walk, so
this family adds no machinery, it only names a key. The total demand (no
key) is the whole boot story: a fresh node over an old db admits one fact
and runs; there is no load and no replay. Volatile — a demand is session
state, never stored, never synced. A durable variant is a pin (wave 2)."""
from kernel import Atom, Out, Range, GATHER, all_gather, encode, fact, remote_suppress

TAG = b"store.hydrate"
ALL = Range(b"", b"\xff" * 64)           # covers every exact target in practice

# SHAPE — the canonical atom set; the only place atoms are chosen.
def hydrate(name=None, scope=None, target=ALL):
    return fact(TAG, remote_suppress,
                all_gather if name is None else Atom(GATHER, name, scope, target))

# EXTRACT — volatile session demand.
def extract(f): return False

# CHECK — exactly one demand plus the graph-native remote suppression.
def check(f):
    try:
        demands = [a for a in f.atoms if a.relationship == GATHER and a != remote_suppress]
        if len(demands) != 1: return False
        d = demands[0]
        return f == (hydrate() if d == all_gather else hydrate(d.name, d.scope, d.target))
    except Exception:
        return False

# PROJECT — demand is inert: valid, Provides nothing, changes nothing.
def project(f, ctx): return Out()

# COMMANDS — admit the demand and drain; the fault leg does the rest.
# Content-addressed, so the same demand twice is one fact, one check.
def demand(node, name=None, scope=None, target=ALL):
    fid = node.admit(encode(hydrate(name, scope, target)))
    node.run()
    return fid

# QUERIES — none: hydration is observed through the families it loads.

# CLI — string boundary: pull one (name, scope) key, or everything. Scope is
# hex when it parses as hex (workspace ids), utf-8 otherwise (b"outbox").
def _scope(s):
    try: return bytes.fromhex(s)
    except ValueError: return s.encode()

CLI = {"pull": lambda n, name=None, scope=None:
           demand(n, name and name.encode(), scope and _scope(scope)).hex()}
