"""facts/sync/have.py — one leg of decomposed negentropy: an advertisement that
the sender holds a fact (a leaf, or one of a leaf's dependency-closure ids). The
receiver admits it and asks one question of the engine — do I already hold this
id? — answered by the reserved `resident` need. If I hold it, nothing to do: the
fact vanishes. If I lack it, I answer with a `need(cid, fid)` back at the outbox
key, and the peer ships it. This is the whole of dependency completion: a
below-window dependency is advertised as its own `have` (the summary attaches the
closure ids to a leaf) and pulled as its own `need` — convergent, because I only
ever request an id a peer vouched for, never one inferred into the void. Volatile
(extract -> False, False); content-minimal so duplicate advertisements dedupe."""
from kernel import (Atom, Exact, OFFER, Out, RES_ROLE, by, encode, fact,
                    resident_need, shipped_need, ts_atom)
from facts.sync.need import need

TAG = b"sync.have"
SC = b"sync"
_tgt = lambda f, r: next((a.target[1] for a in f.atoms if a.role == r), b"")

# SHAPE — cid + advertised id in targets; a resident Watch asks the engine whether
# I hold it, a shipped Watch reaps the request once it flushes.
def have(cid, fid):
    return fact(TAG, ts_atom(0, SC),
                Atom(OFFER, b"cid", SC, Exact(cid)),
                Atom(OFFER, b"id",  SC, Exact(fid)),
                resident_need(fid),
                shipped_need)

# EXTRACT — content-pure: (durable, shareable). Session state is neither.
def extract(f): return False, False

# PROJECT — hold it already -> vanish; lack it -> request it; flushed -> reap.
def project(f, ctx, sl):
    if by(ctx, b"shipped"): return Out("Reap")
    if by(ctx, RES_ROLE):   return Out("Reap")     # the engine says I already hold it: done
    cid = _tgt(f, b"cid"); fid = _tgt(f, b"id")
    return Out(offers=(Atom(OFFER, b"send", b"outbox", Exact(cid), encode(need(cid, fid))),))

# COMMANDS — none: a have is authored only by `compare`'s projector at a leaf.

# QUERIES — none.

# CLI — no verbs.
CLI = {}
