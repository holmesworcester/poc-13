"""facts/content/reaction.py — an emoji on a message, member-signed. Requires
the target's `posted` Provide: Require gates on VALID provides, so a missing message
parks the reaction and a deleted one un-validates it naturally. It also carries
the target's death key (suppression closure, DESIGN.md Relationships), so it dies
with the message — Suppressed, purged with it — rather than merely parking. The
value frames (reactor member id, emoji): who reacted is content, and the signer
gate proves that member's blessed key signed this fact."""
from kernel import (Atom, Exact, PROVIDE, Out, REQUIRE, SELF, SUPPRESS_IF,
                    encode, fact, frame, now, ts_atom, ts_of, unframe)
from facts.auth import signature
from facts.store import hydrate
import cliargs

TAG = b"content.reaction"

# SHAPE — the canonical atom set; the only place atoms are chosen.
def reaction(workspace_id, message_id, reactor_id, emoji, t):
    return fact(TAG, ts_atom(t, workspace_id),
                Atom(REQUIRE, b"posted", workspace_id, Exact(message_id)),
                Atom(SUPPRESS_IF, b"dead", workspace_id, Exact(message_id)),
                Atom(REQUIRE, b"pk", workspace_id, SELF),
                Atom(REQUIRE, b"key", workspace_id, Exact(workspace_id)),
                Atom(PROVIDE, b"reaction", workspace_id, Exact(message_id),
                     frame(reactor_id, emoji)))

# EXTRACT — content-pure durability.
def extract(f): return True
from facts.sync.index import sync_leaf

# PROJECT — the only place this family's meaning lives.
def project(f, ctx):
    try:
        r = next(a for a in f.atoms if a.name == b"reaction")
        reactor_id, emoji = unframe(r.value)
        if f != reaction(r.scope, r.target[0], reactor_id, emoji, ts_of(f)): return Out("Invalid")
    except Exception:
        return Out("Invalid")
    signer, members = signature.blessed(ctx)
    if members.get(reactor_id) not in signer: return Out("Invalid")   # the reactor signed it
    return Out(provides=(r, sync_leaf()))

# COMMANDS — build a fact, admit it, stop.
def react(node, workspace_id, message_id, emoji, t):
    return signature.signed_admit(
        node, workspace_id, lambda mid: reaction(workspace_id, message_id, mid, emoji, t), t)

# QUERIES — observations over validated state only, ordered by (ts, owner).
def on(node, workspace_id, message_id):
    hydrate.demand(node, b"reaction", workspace_id)
    hydrate.demand(node, b"member", workspace_id)
    names = {o: a.value for o, _, a in node.provided(b"member", workspace_id)}
    out = []
    for o, t, a in sorted(node.provided(b"reaction", workspace_id), key=lambda r: (r[1], r[0])):
        if a.target != Exact(message_id): continue
        reactor_id, emoji = unframe(a.value)
        out.append(emoji + b" " + names.get(reactor_id, reactor_id.hex().encode()[:8]))
    return out

# CLI — string boundary over COMMANDS/QUERIES. Grammar: `[wid=] <message-id>
# <emoji> [t=]`.
def _cli_react(n, *argv):
    kv, pos = cliargs.split(argv)
    if len(pos) != 2: raise RuntimeError("usage: content.reaction.react [wid=<id>] <message-id> <emoji> [t=<n>]")
    return react(n, cliargs.wid_of(n, kv), bytes.fromhex(pos[0]), pos[1].encode(),
                 cliargs.t_of(kv)).hex()

def _cli_on(n, *argv):
    kv, pos = cliargs.split(argv)
    if len(pos) != 1: raise RuntimeError("usage: content.reaction.on [wid=<id>] <message-id>")
    return b"\n".join(on(n, cliargs.wid_of(n, kv), bytes.fromhex(pos[0]))).decode()

CLI = {"react": _cli_react, "on": _cli_on}
