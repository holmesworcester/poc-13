"""facts/content/message.py — a message in a real channel. The channel id is
the id of a validated `content.channel` fact, not a caller-chosen label; this
fact Requires that channel and therefore inherits its workspace dependency.
The author stays a plain value (signed authorship is wave 2). It offers a feed
row keyed by channel id and a `posted` marker at its own id for reactions to
Require, and carries its own death key (Suppress on SELF)."""
from kernel import (Atom, Exact, NEED, OFFER, Out, REQUIRE, SELF, SUPPRESS,
                    encode, fact, now, ts_atom, ts_of)
from facts.content import channel as channels
from facts.store import hydrate

TAG = b"content.message"

# SHAPE — the canonical atom set; the only place atoms are chosen.
def message(workspace_id, channel_id, author, body, t):
    return fact(TAG, ts_atom(t, workspace_id),
                Atom(NEED, b"channel", workspace_id, Exact(channel_id), effect=REQUIRE),
                Atom(OFFER, b"msg", workspace_id, Exact(channel_id), body),
                Atom(OFFER, b"posted", workspace_id, SELF, author),
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
    return Out(offers=(m, p))

# COMMANDS — build a fact, admit it, stop.
def send(node, workspace_id, channel_id, author, body, t):
    return node.admit(encode(message(workspace_id, channel_id, author, body, t)))

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

CLI = {"send": lambda n, wid, ch, who, body, t=None:
           send(n, bytes.fromhex(wid), channels.resolve(n, bytes.fromhex(wid), ch),
                who.encode(), body.encode(),
                int(t or now())).hex(),
       "feed": lambda n, wid, ch:
           _cli_feed(n, bytes.fromhex(wid), ch)}
