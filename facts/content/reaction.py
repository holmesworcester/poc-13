"""facts/content/reaction.py — an emoji on a message. Requires the target's
`posted` offer: Require gates on VALID offers, so a missing message parks the
reaction and a deleted one un-validates it naturally. It also carries the
target's death key (suppression closure, DESIGN.md Need Effects), so it dies
with the message — Suppressed, purged with it — rather than merely parking."""
from kernel import (Atom, Exact, NEED, OFFER, Out, REQUIRE, SUPPRESS, encode,
                    fact, now, ts_atom)
from facts.store import hydrate

TAG = b"content.reaction"

# SHAPE — the canonical atom set; the only place atoms are chosen.
def reaction(workspace_id, message_id, emoji, t):
    return fact(TAG, ts_atom(t, workspace_id),
                Atom(NEED, b"posted", workspace_id, Exact(message_id), effect=REQUIRE),
                Atom(NEED, b"dead", workspace_id, Exact(message_id), effect=SUPPRESS),
                Atom(OFFER, b"reaction", workspace_id, Exact(message_id), emoji))

# EXTRACT — content-pure: (durable, shareable).
def extract(f): return True, True
from facts.sync.index import settle      # opt in: these facts replicate (one line is the whole choice)

# PROJECT — the only place this family's meaning lives.
def project(f, ctx):
    return Out(offers=tuple(a for a in f.atoms if a.role == b"reaction"))

# COMMANDS — build a fact, admit it, stop.
def react(node, workspace_id, message_id, emoji, t):
    return node.admit(encode(reaction(workspace_id, message_id, emoji, t)))

# QUERIES — observations over validated state only, ordered by (ts, owner).
def on(node, workspace_id, message_id):
    hydrate.demand(node, b"reaction", workspace_id)
    return [a.value for o, t, a in sorted(node.watched(b"reaction", workspace_id),
                                          key=lambda r: (r[1], r[0]))
            if a.target == Exact(message_id)]

# CLI — string boundary over COMMANDS/QUERIES.
CLI = {"react": lambda n, wid, mid, emoji, t=None:
           react(n, bytes.fromhex(wid), bytes.fromhex(mid), emoji.encode(),
                 int(t or now())).hex(),
       "on": lambda n, wid, mid:
           b"\n".join(on(n, bytes.fromhex(wid), bytes.fromhex(mid))).decode()}
