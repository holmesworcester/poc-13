"""facts/chat/note.py — a chat message. Carries its own death key (Suppress
on its own id via SELF), so deletion is local: no consumer demotion cascade."""
from kernel import (Atom, Exact, NEED, OFFER, Out, SELF, SUPPRESS, encode,
                    fact, now, ts_atom)

TAG = b"chat.note"

# SHAPE — the canonical atom set; the only place atoms are chosen.
def note(channel, body, t):
    return fact(TAG, ts_atom(t, channel),
                Atom(OFFER, b"msg", channel, Exact(b"feed"), body),
                Atom(NEED, b"dead", channel, SELF, effect=SUPPRESS))

# EXTRACT — content-pure: (durable, shareable).
def extract(f): return True, True

# PROJECT — the only place this family's meaning lives.
def project(f, ctx, sl):
    return Out(offers=tuple(a for a in f.atoms if a.role == b"msg"))

# COMMANDS — build a fact, admit it, stop.
def send(node, channel, body, t):
    return node.admit(encode(note(channel, body, t)))

# QUERIES — observations over validated state only, ordered by (ts, owner).
def feed(node, channel):
    return [a.value for o, t, a in sorted(node.watched(b"msg", channel),
                                          key=lambda r: (r[1], r[0]))]

# CLI — string boundary over COMMANDS/QUERIES.
CLI = {"send": lambda n, ch, body, t=None: send(n, ch.encode(), body.encode(),
                                                int(t or now())).hex(),
       "feed": lambda n, ch: b"\n".join(feed(n, ch.encode())).decode()}
