"""facts/content/message.py — a workspace message. Requires its workspace
(author stays a plain value; signed authorship is wave 2), offers a feed row
and a `posted` marker at its own id for reactions to Require, and carries its
own death key (Suppress on SELF). Scope is the workspace id alone — channel
rides as the feed offer's target, which beats a composite scope on LOC."""
from kernel import (Atom, Exact, NEED, OFFER, Out, REQUIRE, SELF, SUPPRESS,
                    encode, fact, now, ts_atom)

TAG = b"content.message"

# SHAPE — the canonical atom set; the only place atoms are chosen.
def message(workspace_id, channel, author, body, t):
    return fact(TAG, ts_atom(t, workspace_id),
                Atom(NEED, b"workspace", b"auth", Exact(workspace_id), effect=REQUIRE),
                Atom(OFFER, b"msg", workspace_id, Exact(channel), body),
                Atom(OFFER, b"posted", workspace_id, SELF, author),
                Atom(NEED, b"dead", workspace_id, SELF, effect=SUPPRESS))

# EXTRACT — content-pure: (durable, shareable).
def extract(f): return True, True

# PROJECT — the only place this family's meaning lives.
def project(f, ctx, sl):
    return Out(offers=tuple(a for a in f.atoms if a.role in (b"msg", b"posted")))

# COMMANDS — build a fact, admit it, stop.
def send(node, workspace_id, channel, author, body, t):
    return node.admit(encode(message(workspace_id, channel, author, body, t)))

# QUERIES — observations over validated state only, ordered by (ts, owner).
def feed(node, workspace_id, channel):
    return [a.value for o, t, a in sorted(node.watched(b"msg", workspace_id),
                                          key=lambda r: (r[1], r[0]))
            if a.target == Exact(channel)]

# CLI — string boundary over COMMANDS/QUERIES.
CLI = {"send": lambda n, wid, ch, who, body, t=None:
           send(n, bytes.fromhex(wid), ch.encode(), who.encode(), body.encode(),
                int(t or now())).hex(),
       "feed": lambda n, wid, ch:
           b"\n".join(feed(n, bytes.fromhex(wid), ch.encode())).decode()}
