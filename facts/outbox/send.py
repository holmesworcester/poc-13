"""facts/outbox/send.py — a one-shot wire send. It provides its payload at the
host-read `send` outbox key; the daemon flushes it to the socket and reports
the flush by presenting shipped@SELF, on which this fact reaps — a volatile row
that lives exactly from stage to flush, then vanishes with no receipt. The wire
is best-effort (sync heals loss), so there is nothing to persist or retry here:
this is poc-10's network_outgoing row — staged, flushed, deleted."""
from kernel import (Atom, Exact, PROVIDE, Out, by, encode, fact, now,
                    remote_suppress, shipped_gather, ts_atom, ts_of)
from facts.store import hydrate

TAG = b"outbox.send"

# SHAPE — the canonical atom set; the only place atoms are chosen.
def send(dest, payload, t):
    return fact(TAG, ts_atom(t, b"outbox"), remote_suppress, shipped_gather,
                Atom(PROVIDE, b"send", b"outbox", Exact(dest), payload))

# EXTRACT — volatile one-shot work.
def extract(f): return False

# CHECK — exact one-shot shape. Only locally authored work lacks the remote
# provenance Provide that matches remote_suppress.
def check(f):
    try:
        row = next(a for a in f.atoms if a.name == b"send")
        return row.target[0] == row.target[1] and f == send(row.target[0], row.value, ts_of(f))
    except Exception:
        return False

# PROJECT — Provide the payload until the flush report, then reap with no residue.
def project(f, ctx):
    if by(ctx, b"shipped"): return Out("Reap")   # flushed: vanish
    return Out(provides=tuple(a for a in f.atoms if a.name == b"send"))

# COMMANDS — build a fact, admit it, stop.
def queue(node, dest, payload, t):
    return node.admit(encode(send(dest, payload, t)))

# QUERIES — observations over validated state only, ordered by (ts, owner).
def pending(node):
    hydrate.demand(node, b"send", b"outbox")
    return sorted(node.provided(b"send", b"outbox"), key=lambda r: (r[1], r[0]))

# CLI — string boundary over COMMANDS/QUERIES.
CLI = {"queue": lambda n, dest, p, t=None: queue(n, dest.encode(), p.encode(),
                                                 int(t or now())).hex(),
       "pending": lambda n: "\n".join(f"{o.hex()} {a.target[1].decode()} {a.value.decode()}"
                                      for o, _, a in pending(n))}
