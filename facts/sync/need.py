"""facts/sync/need.py — one leg of decomposed negentropy: a request for a single
fact by id. A peer advertised `have(cid, fid)`; if I lacked it I answered with a
`need(cid, fid)`; the peer admits this and its projector ships that one fact's
bytes back at the connection's outbox key. Volatile session state (extract ->
False, False): it dies with the session, reaps when its shipment flushes, and the
next cadence re-descends whatever still differs. Content-minimal — cid + id only —
so a duplicate request is byte-identical and the outbox dedupes it. cid rides in
the atom targets (Exact) so the pump routes the ship by connection, symmetric with
`have`/`compare`; there is no daemon reaction, only the projector's ship offer."""
from kernel import (Atom, Exact, OFFER, Out, by, fact, frame, shipped_need,
                    ts_atom)

TAG = b"sync.need"
SC = b"sync"
_tgt = lambda f, r: next((a.target[1] for a in f.atoms if a.role == r), b"")

# SHAPE — the canonical atom set. cid + the wanted id in targets; a shipped Watch
# turns the courier into a one-shot that reaps once its ship offer has flushed.
def need(cid, fid):
    return fact(TAG, ts_atom(0, SC),
                Atom(OFFER, b"cid", SC, Exact(cid)),
                Atom(OFFER, b"id",  SC, Exact(fid)),
                shipped_need)

# EXTRACT — content-pure: (durable, shareable). Session state is neither.
def extract(f): return False, False

# PROJECT — ship the one fact by id, then reap when the ship flushes.
def project(f, ctx, sl):
    if by(ctx, b"shipped"): return Out("Reap")
    cid = _tgt(f, b"cid"); fid = _tgt(f, b"id")
    return Out(offers=(Atom(OFFER, b"ship", b"outbox", Exact(cid), frame(fid)),))

# COMMANDS — none: a need is authored only by `have`'s projector, never a driver.

# QUERIES — none.

# CLI — no verbs: sync has no human authoring surface.
CLI = {}
