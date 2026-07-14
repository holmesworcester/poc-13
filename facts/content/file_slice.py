"""facts/content/file_slice.py — one independently verifiable attachment
range. Its value is a canonical Bao slice encoding: payload bytes plus the
authentication path needed to prove them against the descriptor's BLAKE3 root.
The slice Requires that descriptor and carries the message death key directly,
so deletion physically purges every proof and payload byte."""
from kernel import (Atom, Exact, PROVIDE, Out, REQUIRE, SELF, SUPPRESS_IF,
                    by, fact, ts_atom, ts_of)
import tinyp2p_bao

TAG = b"content.file_slice"
SLICE_BYTES = 256 * 1024
MAX_FILE_BYTES = 10 * 1024 * 1024 * 1024
BAO_CHUNK_BYTES = 1024
MAX_TREE_DEPTH = ((MAX_FILE_BYTES + BAO_CHUNK_BYTES - 1) // BAO_CHUNK_BYTES - 1).bit_length()
MAX_PROOF_BYTES = ((SLICE_BYTES + BAO_CHUNK_BYTES - 1) // BAO_CHUNK_BYTES + 1) * \
                  BAO_CHUNK_BYTES + (SLICE_BYTES // BAO_CHUNK_BYTES +
                                     2 * MAX_TREE_DEPTH) * 64 + 8

# SHAPE — one bounded Bao proof behind the descriptor root it authenticates.
def file_slice(workspace_id, message_id, file_id, root, index, proof, t):
    return fact(TAG, ts_atom(t, workspace_id),
                Atom(REQUIRE, b"descriptor", file_id, Exact(root)),
                Atom(REQUIRE, b"file", workspace_id, Exact(message_id)),
                Atom(REQUIRE, b"file_size", file_id, Exact(root)),
                Atom(REQUIRE, b"file_slices", file_id, Exact(root)),
                Atom(REQUIRE, b"file_slice_bytes", file_id, Exact(root)),
                Atom(SUPPRESS_IF, b"dead", workspace_id, Exact(message_id)),
                Atom(PROVIDE, b"slice", file_id, Exact(index.to_bytes(4, "big")), proof))


# EXTRACT — content-pure durability.
def extract(f): return True
from facts.sync.index import sync_leaf


# CHECK — exact intrinsic SHAPE and bounded canonical Bao header geometry.
def _canonical(f):
    try:
        descriptor = next(a for a in f.atoms if a.relationship == REQUIRE and a.name == b"descriptor")
        parent = next(a for a in f.atoms if a.relationship == REQUIRE and a.name == b"file")
        atom = next(a for a in f.atoms if a.relationship == PROVIDE and a.name == b"slice")
        file_id, root, workspace_id = descriptor.scope, descriptor.target[1], parent.scope
        message_id = parent.target[1]
        if not (len(file_id) == len(root) == len(workspace_id) == len(message_id) == 32
                and len(atom.target[1]) == 4 and 8 <= len(atom.value) <= MAX_PROOF_BYTES
                and int.from_bytes(atom.value[:8], "little") <= MAX_FILE_BYTES):
            return None
        index = int.from_bytes(atom.target[1], "big")
        rebuilt = file_slice(workspace_id, message_id, file_id, root, index,
                             atom.value, ts_of(f))
        return (atom, descriptor) if f == rebuilt else None
    except Exception:
        return None


def check(f): return _canonical(f) is not None


# PROJECT — join one descriptor owner, then verify and expose the Bao proof.
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
            verified_bytes(atom.value, descriptor.target[1], index, blob_bytes, width)
            return Out(provides=(atom, sync_leaf()))
        except Exception:
            continue
    return Out("Invalid")


# COMMANDS — authored by content.file.send after every source proof is ready.


# QUERIES — saving re-verifies a promoted proof before exposing its bytes.
def verified_bytes(proof, root, index, blob_bytes, slice_bytes=SLICE_BYTES):
    if index < 0 or index >= (0 if blob_bytes == 0 else (blob_bytes + slice_bytes - 1) // slice_bytes):
        raise ValueError("slice index outside descriptor")
    start = index * slice_bytes
    count = min(slice_bytes, blob_bytes - start)
    return tinyp2p_bao.decode_slice(proof, root, start, count, blob_bytes)


# CLI — slices have no independent human surface.
CLI = {}
