"""facts/store/hydrate.py — hydration is just a fact. A demand is one Watch
need, and the engine answers every need the same way: the fault leg checks
its key against the persisted atom relation and admits the cold owners,
whose own needs then fault in turn — the step loop is the closure walk, so
this family adds no machinery, it only names a key. The total demand (no
key) is the whole boot story: a fresh node over an old db admits one fact
and runs; there is no load and no replay. Volatile — a demand is session
state, never stored, never synced. A durable variant is a pin (wave 2)."""
from kernel import Atom, NEED, Out, Range, WATCH, all_need, encode, fact

TAG = b"store.hydrate"
ALL = Range(b"", b"\xff" * 64)           # covers every exact target in practice

# SHAPE — the canonical atom set; the only place atoms are chosen.
def hydrate(role=None, scope=None, target=ALL):
    return fact(TAG, all_need if role is None else Atom(NEED, role, scope, target, effect=WATCH))

# EXTRACT — content-pure: volatile session demand, never stored, never synced.
def extract(f): return False, False

# PROJECT — demand is inert: valid, offers nothing, changes nothing.
def project(f, ctx, sl): return Out()

# COMMANDS — admit the demand and drain; the fault leg does the rest.
# Content-addressed, so the same demand twice is one fact, one check.
def demand(node, role=None, scope=None, target=ALL):
    fid = node.admit(encode(hydrate(role, scope, target)))
    node.run()
    return fid

# QUERIES — none: hydration is observed through the families it loads.

# CLI — string boundary: pull one (role, scope) key, or everything. Scope is
# hex when it parses as hex (workspace ids), utf-8 otherwise (b"outbox").
def _scope(s):
    try: return bytes.fromhex(s)
    except ValueError: return s.encode()

CLI = {"pull": lambda n, role=None, scope=None:
           demand(n, role and role.encode(), scope and _scope(scope)).hex()}
