"""facts/sync/need.py — the pull leg of range reconciliation: a batched request for
a set of facts by id. When a peer's id list (a small range's `ids` claim) names ids
I lack, my compare projector authors one `need` carrying all of them; the peer
admits it and its projector ships exactly those facts at the connection's outbox
key. Batched (one need, many ids) so a fresh peer pulls in O(1) request frames, not
one per fact. Volatile session state (extract -> False): it reaps when its
shipment flushes, and the next cadence re-descends whatever still differs."""
from kernel import (Atom, Exact, PROVIDE, Out, by, fact, frame, shipped_gather,
                    ts_atom, unframe)
from facts.sync.index import LEAF_NAME, is_sync_leaf_row, sync_leaf_gather

TAG = b"sync.need"
SC = b"sync"
_tgt = lambda f, r: next((a.target[1] for a in f.atoms if a.name == r), b"")

# SHAPE — cid in the target, the wanted ids length-framed in one atom's value.
def need(cid, fids):
    return fact(TAG, ts_atom(0, SC),
                Atom(PROVIDE, b"cid", SC, Exact(cid)),
                Atom(PROVIDE, b"ids", SC, Exact(cid), frame(*fids)),
                shipped_gather, *(sync_leaf_gather(fid) for fid in fids))

# EXTRACT — volatile session state.
def extract(f): return False

# PROJECT — ship the requested ids, then reap when the shipment flushes.
def project(f, ctx):
    if by(ctx, b"shipped"): return Out("Reap")
    cid = _tgt(f, b"cid")
    allowed = {row.owner for row in by(ctx, LEAF_NAME) if is_sync_leaf_row(row)}
    ids = [fid for fid in unframe(next((a.value for a in f.atoms if a.name == b"ids"), b""))
           if fid in allowed]
    return Out(provides=(Atom(PROVIDE, b"ship", b"outbox", Exact(cid), frame(*ids)),))

# COMMANDS — none: a need is authored only by compare's projector.

# QUERIES — none.

# CLI — no verbs.
CLI = {}
