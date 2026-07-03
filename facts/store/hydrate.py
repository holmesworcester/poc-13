"""facts/store/hydrate.py — hydration demand: a volatile fact whose one
Watch need pulls matching cold facts resident through ordinary admission.
Fact creation and matching control replay, not process boot. Gating needs
(Require/Suppress) pull their own cold matches exhaustively whenever any
resident fact steps; this family exists for bulk, windowed demand — queries,
viewports, pages. The window (ts range, budget, order) rides in the need's
value, engine-owned and never read by matching; budget counts primary hits
and is an amortization knob, never a semantic limit — paging to exhaustion
equals one unbudgeted pull, because the store pops delivered facts (per-fact
dedup), so a re-scan from the last ts never re-delivers an owner. A durable
variant of this fact is a pin (wave 2)."""
from kernel import Atom, NEED, Out, Range, WATCH, encode, fact, window

TAG = b"store.hydrate"
ALL = Range(b"", b"\xff" * 64)           # covers every exact target in practice

# SHAPE — the canonical atom set; the only place atoms are chosen.
def hydrate(role, scope, target=ALL, win=None):
    return fact(TAG, Atom(NEED, role, scope, target, win, WATCH))

# EXTRACT — content-pure: volatile session demand, never stored, never synced.
def extract(f): return False, False

# PROJECT — demand is inert: valid, offers nothing, changes nothing.
def project(f, ctx, sl): return Out()

# COMMANDS — build a fact, admit it, stop. Callers drain (node.run()) to let
# the pulled facts validate before reading; same demand twice is one fact.
def demand(node, role, scope, target=ALL, win=None):
    return node.admit(encode(hydrate(role, scope, target, win)))

# QUERIES — none: hydration is observed through the families it loads.

# CLI — string boundary: pull everything at a (role, scope) key. Scope is
# hex when it parses as hex (workspace ids), utf-8 otherwise (b"outbox").
def _scope(s):
    try: return bytes.fromhex(s)
    except ValueError: return s.encode()

CLI = {"pull": lambda n, role, scope: demand(n, role.encode(), _scope(scope)).hex()}
