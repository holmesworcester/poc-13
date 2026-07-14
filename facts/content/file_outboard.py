"""facts/content/file_outboard.py — the compact integrity index for one
attachment. It commits the ordered chunk hashes to the descriptor root, Requires
that descriptor, and directly carries the parent message's death key. Chunks
verify publicly against this value; no second blob trust path exists."""
from kernel import (Atom, Exact, H, NEED, OFFER, Out, REQUIRE, SELF, SUPPRESS,
                    by, fact, frame, ts_atom, unframe)
from facts.content.file import CHUNK_BYTES, ENCODING_CLEAR, MAX_FILE_BYTES

TAG = b"content.file_outboard"
VERSION = b"\x01"
CHUNK_DOMAIN = b"poc13.file.chunk.v1"
ROOT_DOMAIN = b"poc13.file.outboard.v1"


def chunk_hash(index, data):
    return H(frame(CHUNK_DOMAIN, index.to_bytes(4, "big"), data))


def root_for(hashes, blob_bytes, chunk_bytes=CHUNK_BYTES, encoding=ENCODING_CLEAR):
    return H(frame(ROOT_DOMAIN, blob_bytes.to_bytes(8, "big"),
                   chunk_bytes.to_bytes(4, "big"), encoding, frame(*hashes)))


def value(workspace_id, message_id, file_id, root, blob_bytes, hashes,
          encoding=ENCODING_CLEAR):
    return frame(VERSION, workspace_id, message_id, file_id, root,
                 blob_bytes.to_bytes(8, "big"), CHUNK_BYTES.to_bytes(4, "big"),
                 len(hashes).to_bytes(4, "big"), encoding, frame(*hashes))


def decode_value(blob):
    parts = unframe(blob)
    if len(parts) != 10 or parts[0] != VERSION:
        raise ValueError("invalid file outboard")
    _, workspace_id, message_id, file_id, root, size_raw, chunk_raw, total_raw, \
        encoding, hash_blob = parts
    if not all(len(x) == 32 for x in (workspace_id, message_id, file_id, root)):
        raise ValueError("invalid outboard id")
    if len(size_raw) != 8 or len(chunk_raw) != 4 or len(total_raw) != 4:
        raise ValueError("invalid outboard geometry")
    blob_bytes = int.from_bytes(size_raw, "big")
    chunk_bytes = int.from_bytes(chunk_raw, "big")
    total_chunks = int.from_bytes(total_raw, "big")
    hashes = unframe(hash_blob)
    if chunk_bytes != CHUNK_BYTES:
        raise ValueError("invalid outboard chunk size")
    expected = 0 if blob_bytes == 0 else (blob_bytes + chunk_bytes - 1) // chunk_bytes
    if (blob_bytes > MAX_FILE_BYTES or total_chunks != expected
            or total_chunks != len(hashes)
            or encoding != ENCODING_CLEAR or any(len(item) != 32 for item in hashes)):
        raise ValueError("invalid outboard contents")
    if root_for(hashes, blob_bytes, chunk_bytes, encoding) != root:
        raise ValueError("outboard does not match root")
    return {"workspace_id": workspace_id, "message_id": message_id,
            "file_id": file_id, "root": root, "blob_bytes": blob_bytes,
            "chunk_bytes": chunk_bytes, "total_chunks": total_chunks,
            "encoding": encoding, "hashes": tuple(hashes)}


def _atoms(f, kind, role):
    return [a for a in f.atoms if a.kind == kind and a.role == role]


# SHAPE — one root-bound hash index behind its descriptor.
def outboard(workspace_id, message_id, file_id, root, blob_bytes, hashes, t,
             encoding=ENCODING_CLEAR):
    return fact(TAG, ts_atom(t, workspace_id),
                Atom(NEED, b"descriptor", file_id, Exact(file_id), effect=REQUIRE),
                Atom(NEED, b"dead", workspace_id, Exact(message_id), effect=SUPPRESS),
                Atom(OFFER, b"outboard", file_id, Exact(file_id),
                     value(workspace_id, message_id, file_id, root, blob_bytes,
                           hashes, encoding)))


# EXTRACT — durable and shared; the small index travels separately from bytes.
def extract(f): return True, True
from facts.sync.index import settle      # opt in: these facts replicate


# CHECK — canonical geometry, commitment, dependency, and direct death key.
def check(f):
    try:
        if len(f.atoms) != 4:
            return False
        descriptors = _atoms(f, NEED, b"descriptor")
        dead = _atoms(f, NEED, b"dead")
        outboards = _atoms(f, OFFER, b"outboard")
        stamps = _atoms(f, OFFER, b"ts")
        if not all(len(x) == 1 for x in (descriptors, dead, outboards, stamps)):
            return False
        parsed = decode_value(outboards[0].value)
        return (descriptors[0].scope == parsed["file_id"]
                and descriptors[0].target == Exact(parsed["file_id"])
                and descriptors[0].effect == REQUIRE and descriptors[0].value is None
                and dead[0].scope == parsed["workspace_id"]
                and dead[0].target == Exact(parsed["message_id"])
                and dead[0].effect == SUPPRESS and dead[0].value is None
                and outboards[0].scope == parsed["file_id"]
                and outboards[0].target == Exact(parsed["file_id"])
                and stamps[0].scope == parsed["workspace_id"]
                and stamps[0].target == SELF)
    except Exception:
        return False


# PROJECT — bind the intrinsic outboard to the exact descriptor context.
def project(f, ctx):
    from facts.content.file import decode_metadata

    atom = next(a for a in f.atoms if a.kind == OFFER and a.role == b"outboard")
    parsed = decode_value(atom.value)
    descriptors = []
    for row in by(ctx, b"descriptor"):
        try: descriptors.append(decode_metadata(row[2].value))
        except Exception: pass
    matched = any(all(meta[key] == parsed[key] for key in
                      ("workspace_id", "message_id", "file_id", "root", "blob_bytes",
                       "chunk_bytes", "total_chunks", "encoding"))
                  for meta in descriptors)
    return Out(offers=(atom,)) if matched else Out("Invalid")


# COMMANDS — authored by content.file.send as part of the attachment DAG.


# QUERIES — consumed as validated context by file chunks.


# CLI — no independent human surface.
CLI = {}
