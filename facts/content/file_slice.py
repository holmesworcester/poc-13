"""facts/content/file_slice.py — one attachment range, named but not carried.

The slice fact used to carry the whole canonical Bao proof (~205 KiB) as its
`slice` Provide value, so the bytes rode the fact graph, the reconciliation
treap, and the SQLite atom relation. Now it carries only the proof's 32-byte
content id (`cid = H(proof)`): the fact is tiny and still syncs (a peer learns
which cid to fetch), while the proof itself is a blob in the content store,
pulled out-of-line and Bao-verified against the descriptor root at fetch/save
time. The slice still Requires that descriptor and carries the message death key
directly, so deletion physically purges the naming fact; the blob is reclaimed
by lazy content-store GC once nothing names its cid."""
from kernel import (Atom, Exact, PROVIDE, Out, REQUIRE, SELF, SUPPRESS_IF,
                    by, fact, ts_atom, ts_of)
import tinyp2p_bao

TAG = b"content.file_slice"
SLICE_BYTES = 256 * 1024
MAX_FILE_BYTES = 10 * 1024 * 1024 * 1024
CID_BYTES = 32                           # a slice names its proof by BLAKE3-256 content id

# SHAPE — the descriptor it proves against, named; the proof blob's cid Provided.
def file_slice(workspace_id, message_id, file_id, root, index, cid, t):
    return fact(TAG, ts_atom(t, workspace_id),
                Atom(REQUIRE, b"descriptor", file_id, Exact(root)),
                Atom(REQUIRE, b"file", workspace_id, Exact(message_id)),
                Atom(REQUIRE, b"file_size", file_id, Exact(root)),
                Atom(REQUIRE, b"file_slices", file_id, Exact(root)),
                Atom(REQUIRE, b"file_slice_bytes", file_id, Exact(root)),
                Atom(SUPPRESS_IF, b"dead", workspace_id, Exact(message_id)),
                Atom(PROVIDE, b"slice", file_id, Exact(index.to_bytes(4, "big")), cid))


# EXTRACT — content-pure durability.
def extract(f): return True
from facts.sync.index import sync_leaf


# CHECK — exact intrinsic SHAPE and a fixed-width content id.
def _canonical(f):
    try:
        descriptor = next(a for a in f.atoms if a.relationship == REQUIRE and a.name == b"descriptor")
        parent = next(a for a in f.atoms if a.relationship == REQUIRE and a.name == b"file")
        atom = next(a for a in f.atoms if a.relationship == PROVIDE and a.name == b"slice")
        file_id, root, workspace_id = descriptor.scope, descriptor.target[1], parent.scope
        message_id = parent.target[1]
        if not (len(file_id) == len(root) == len(workspace_id) == len(message_id) == 32
                and len(atom.target[1]) == 4 and len(atom.value) == CID_BYTES):
            return None
        index = int.from_bytes(atom.target[1], "big")
        rebuilt = file_slice(workspace_id, message_id, file_id, root, index,
                             atom.value, ts_of(f))
        return (atom, descriptor) if f == rebuilt else None
    except Exception:
        return None


def check(f): return _canonical(f) is not None


# PROJECT — bind the cid to a consistent descriptor; the proof is verified
# out-of-line when its blob is fetched, so projection only checks geometry.
def project(f, ctx):
    canonical = _canonical(f)
    if canonical is None: return Out("Invalid")
    atom, descriptor = canonical
    index = int.from_bytes(atom.target[1], "big")
    for owner, _, _ in by(ctx, b"descriptor"):
        rows = {name: next((row for row in by(ctx, name) if row[0] == owner), None)
                for name in (b"file", b"file_size", b"file_slices", b"file_slice_bytes")}
        if any(row is None for row in rows.values()) or rows[b"file"][2].value != atom.scope:
            continue
        try:
            blob_bytes = int.from_bytes(rows[b"file_size"][2].value, "big")
            total = int.from_bytes(rows[b"file_slices"][2].value, "big")
            width = int.from_bytes(rows[b"file_slice_bytes"][2].value, "big")
            if width != SLICE_BYTES:
                continue
            if total != (0 if blob_bytes == 0 else (blob_bytes + width - 1) // width):
                continue
            if index >= total:                       # a slice past the descriptor's end is inert
                continue
            return Out(provides=(atom, sync_leaf()))
        except Exception:
            continue
    return Out("Invalid")


# COMMANDS — authored by content.file.send after every source proof is stored.


# QUERIES — a fetched proof is re-verified against the root before its bytes are
# exposed; a corrupt or wrong blob is a miss, never wrong bytes.
def verified_bytes(proof, root, index, blob_bytes, slice_bytes=SLICE_BYTES):
    if index < 0 or index >= (0 if blob_bytes == 0 else (blob_bytes + slice_bytes - 1) // slice_bytes):
        raise ValueError("slice index outside descriptor")
    start = index * slice_bytes
    count = min(slice_bytes, blob_bytes - start)
    return tinyp2p_bao.decode_slice(proof, root, start, count, blob_bytes)


# CLI — slices have no independent human surface.
CLI = {}
