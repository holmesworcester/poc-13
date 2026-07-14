"""facts/content/file_slice.py — one independently verifiable attachment
range. Its value is a canonical Bao slice encoding: payload bytes plus the
authentication path needed to prove them against the descriptor's BLAKE3 root.
The slice Requires that descriptor and carries the message death key directly,
so deletion physically purges every proof and payload byte."""
from kernel import (Atom, Exact, NEED, OFFER, Out, REQUIRE, SELF, SUPPRESS,
                    by, fact, ts_atom)
import poc13_bao

TAG = b"content.file_slice"
SLICE_BYTES = 256 * 1024
MAX_FILE_BYTES = 10 * 1024 * 1024 * 1024
BAO_CHUNK_BYTES = 1024
MAX_TREE_DEPTH = ((MAX_FILE_BYTES + BAO_CHUNK_BYTES - 1) // BAO_CHUNK_BYTES - 1).bit_length()
MAX_PROOF_BYTES = ((SLICE_BYTES + BAO_CHUNK_BYTES - 1) // BAO_CHUNK_BYTES + 1) * \
                  BAO_CHUNK_BYTES + (SLICE_BYTES // BAO_CHUNK_BYTES +
                                     2 * MAX_TREE_DEPTH) * 64 + 8


def _atoms(f, kind, role): return [a for a in f.atoms if a.kind == kind and a.role == role]


# SHAPE — one bounded Bao proof behind the descriptor root it authenticates.
def file_slice(workspace_id, message_id, file_id, root, index, proof, t):
    return fact(TAG, ts_atom(t, workspace_id),
                Atom(NEED, b"descriptor", file_id, Exact(root), effect=REQUIRE),
                Atom(NEED, b"file", workspace_id, Exact(message_id), effect=REQUIRE),
                Atom(NEED, b"file_size", file_id, Exact(root), effect=REQUIRE),
                Atom(NEED, b"file_slices", file_id, Exact(root), effect=REQUIRE),
                Atom(NEED, b"file_slice_bytes", file_id, Exact(root), effect=REQUIRE),
                Atom(NEED, b"file_encoding", file_id, Exact(root), effect=REQUIRE),
                Atom(NEED, b"dead", workspace_id, Exact(message_id), effect=SUPPRESS),
                Atom(OFFER, b"slice", file_id, Exact(index.to_bytes(4, "big")), proof))


# EXTRACT — durable and shared; each proof is an independently useful byte fact.
def extract(f): return True, True
from facts.sync.index import settle      # opt in: these facts replicate


# CHECK — exact intrinsic shape and bounded canonical Bao header geometry.
def check(f):
    try:
        if len(f.atoms) != 9: return False
        roles = (b"descriptor", b"file", b"file_size", b"file_slices",
                 b"file_slice_bytes", b"file_encoding", b"dead")
        needs = {role: _atoms(f, NEED, role) for role in roles}
        slices, stamps = _atoms(f, OFFER, b"slice"), _atoms(f, OFFER, b"ts")
        if any(len(items) != 1 for items in needs.values()) or len(slices) != 1 or len(stamps) != 1:
            return False
        descriptor, parent, dead, atom = (needs[b"descriptor"][0], needs[b"file"][0],
                                           needs[b"dead"][0], slices[0])
        file_id, root, workspace_id = descriptor.scope, descriptor.target[1], parent.scope
        geometry = (b"file_size", b"file_slices", b"file_slice_bytes", b"file_encoding")
        return (len(file_id) == len(root) == len(workspace_id) == 32
                and descriptor.target[0] == root and descriptor.effect == REQUIRE
                and parent.target[0] == parent.target[1] and len(parent.target[1]) == 32
                and parent.effect == REQUIRE and dead.scope == workspace_id
                and dead.target == parent.target and dead.effect == SUPPRESS
                and all(items[0].value is None for items in needs.values())
                and all(needs[role][0].scope == file_id
                        and needs[role][0].target == Exact(root)
                        and needs[role][0].effect == REQUIRE for role in geometry)
                and atom.scope == file_id and atom.target[0] == atom.target[1]
                and len(atom.target[1]) == 4 and 8 <= len(atom.value) <= MAX_PROOF_BYTES
                and int.from_bytes(atom.value[:8], "little") <= MAX_FILE_BYTES
                and stamps[0].scope == workspace_id and stamps[0].target == SELF)
    except Exception:
        return False


# PROJECT — join one descriptor owner, then verify and expose the Bao proof.
def project(f, ctx):
    atom = next(a for a in f.atoms if a.kind == OFFER and a.role == b"slice")
    descriptor = next(a for a in f.atoms if a.kind == NEED and a.role == b"descriptor")
    index = int.from_bytes(atom.target[1], "big")
    for owner, _, _ in by(ctx, b"descriptor"):
        rows = {role: next((row for row in by(ctx, role) if row[0] == owner), None)
                for role in (b"file", b"file_size", b"file_slices",
                             b"file_slice_bytes", b"file_encoding")}
        if any(row is None for row in rows.values()) or rows[b"file"][2].value != atom.scope:
            continue
        try:
            blob_bytes = int.from_bytes(rows[b"file_size"][2].value, "big")
            total = int.from_bytes(rows[b"file_slices"][2].value, "big")
            width = int.from_bytes(rows[b"file_slice_bytes"][2].value, "big")
            if rows[b"file_encoding"][2].value != b"clear-v1" or width != SLICE_BYTES:
                continue
            if total != (0 if blob_bytes == 0 else (blob_bytes + width - 1) // width):
                continue
            verified_bytes(atom.value, descriptor.target[1], index, blob_bytes, width)
            return Out(offers=(atom,))
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
    return poc13_bao.decode_slice(proof, root, start, count, blob_bytes)


# CLI — slices have no independent human surface.
CLI = {}
