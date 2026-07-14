"""facts/content/message.py — a member-signed message in a real channel.
The channel id is the id of a validated `content.channel` fact, not a
caller-chosen label; this fact Requires that channel and therefore inherits
its workspace dependency. Its own signature and workspace member keys bind
the posted author id to the member whose blessed key signed the fact. It also
carries its own death key (Suppress on SELF)."""
from kernel import (Atom, Exact, NEED, OFFER, Out, REQUIRE, SELF, SUPPRESS,
                    encode, fact, now, ts_atom, ts_of)
from facts.auth import signature
from facts.content import channel as channels
from facts.store import hydrate

TAG = b"content.message"

# SHAPE — the canonical atom set; the only place atoms are chosen.
def message(workspace_id, channel_id, author_id, body, t):
    return fact(TAG, ts_atom(t, workspace_id),
                Atom(NEED, b"channel", workspace_id, Exact(channel_id), effect=REQUIRE),
                Atom(NEED, b"pk", workspace_id, SELF, effect=REQUIRE),
                Atom(NEED, b"key", workspace_id, Exact(workspace_id), effect=REQUIRE),
                Atom(OFFER, b"msg", workspace_id, Exact(channel_id), body),
                Atom(OFFER, b"posted", workspace_id, SELF, author_id),
                Atom(NEED, b"dead", workspace_id, SELF, effect=SUPPRESS))

# EXTRACT — content-pure: (durable, shareable).
def extract(f): return True, True
from facts.sync.index import settle      # opt in: these facts replicate (one line is the whole choice)

# PROJECT — the only place this family's meaning lives.
def project(f, ctx):
    try:
        m = next(a for a in f.atoms if a.role == b"msg")
        p = next(a for a in f.atoms if a.role == b"posted")
        if len(m.target[0]) != 32: return Out("Invalid")
        if f != message(m.scope, m.target[0], p.value, m.value, ts_of(f)): return Out("Invalid")
    except Exception:
        return Out("Invalid")
    signer, members = signature.blessed(ctx)
    if members.get(p.value) not in signer: return Out("Invalid")   # the author signed it
    return Out(offers=(m, p))

# COMMANDS — build a fact, admit it, stop. Authorship is the local signer's
# membership; the signature travels with the message.
def send(node, workspace_id, channel_id, body, t):
    return signature.signed_admit(
        node, workspace_id, lambda mid: message(workspace_id, channel_id, mid, body, t), t)

# QUERIES — observations over validated state only, ordered by (ts, owner).
# Queries author volatile demand (never durable facts) and drain before reading.
def feed(node, workspace_id, channel_id):
    hydrate.demand(node, b"msg", workspace_id)
    return [a.value for o, t, a in sorted(node.watched(b"msg", workspace_id),
                                          key=lambda r: (r[1], r[0]))
            if a.target == Exact(channel_id)]

# CLI — string boundary over COMMANDS/QUERIES. A not-yet-synced name reads as
# an empty feed so polling can observe the channel arrive; sends still fail
# closed unless given a validated name or an explicit 32-byte id.
def _cli_feed(node, workspace_id, ref):
    try: channel_id = channels.resolve(node, workspace_id, ref)
    except RuntimeError as e:
        if str(e).startswith("unknown channel:"): return ""
        raise
    return b"\n".join(feed(node, workspace_id, channel_id)).decode()

# CLI — string boundary over COMMANDS/QUERIES. The author is the local signer;
# the `who` slot is accepted and ignored for wire-compat until the CLI rework.
CLI = {"send": lambda n, wid, ch, who, body, t=None:
           send(n, bytes.fromhex(wid), channels.resolve(n, bytes.fromhex(wid), ch),
                body.encode(), int(t or now())).hex(),
       "feed": lambda n, wid, ch:
           _cli_feed(n, bytes.fromhex(wid), ch)}
