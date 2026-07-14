"""facts/content/file_chunk.py — one fixed-budget byte range of an attachment.
The chunk Requires its validated outboard, which binds its index and bytes to
the descriptor root. It also carries the parent message's death key directly,
so message deletion physically purges every byte fact even when a parent has
already disappeared."""
from kernel import (Atom, Exact, NEED, OFFER, Out, REQUIRE, SELF, SUPPRESS,
                    by, fact, ts_atom)
from facts.content.file import CHUNK_BYTES

TAG = b"content.file_chunk"


def _atoms(f, kind, role):
    return [a for a in f.atoms if a.kind == kind and a.role == role]


# SHAPE — one indexed byte range behind its outboard.
def chunk(workspace_id, message_id, file_id, index, data, t):
    return fact(TAG, ts_atom(t, workspace_id),
                Atom(NEED, b"outboard", file_id, Exact(file_id), effect=REQUIRE),
                Atom(NEED, b"dead", workspace_id, Exact(message_id), effect=SUPPRESS),
                Atom(OFFER, b"chunk", file_id, Exact(index.to_bytes(4, "big")), data))


# EXTRACT — durable and shared; bytes remain ordinary facts.
def extract(f): return True, True
from facts.sync.index import settle      # opt in: these facts replicate


# CHECK — intrinsic indexed payload plus the direct message death key.
def check(f):
    try:
        if len(f.atoms) != 4:
            return False
        outboards = _atoms(f, NEED, b"outboard")
        dead = _atoms(f, NEED, b"dead")
        chunks = _atoms(f, OFFER, b"chunk")
        stamps = _atoms(f, OFFER, b"ts")
        if not all(len(x) == 1 for x in (outboards, dead, chunks, stamps)):
            return False
        file_id = outboards[0].scope
        workspace_id = dead[0].scope
        return (len(file_id) == 32 and len(workspace_id) == 32
                and dead[0].target[0] == dead[0].target[1]
                and len(dead[0].target[1]) == 32
                and outboards[0].target == Exact(file_id)
                and outboards[0].effect == REQUIRE and outboards[0].value is None
                and dead[0].effect == SUPPRESS and dead[0].value is None
                and chunks[0].scope == file_id
                and chunks[0].target[0] == chunks[0].target[1]
                and len(chunks[0].target[1]) == 4
                and 0 < len(chunks[0].value) <= CHUNK_BYTES
                and stamps[0].scope == workspace_id and stamps[0].target == SELF)
    except Exception:
        return False


# PROJECT — verify index, exact range length, and hash against the outboard.
def project(f, ctx):
    from facts.content.file_outboard import chunk_hash, decode_value

    atom = next(a for a in f.atoms if a.kind == OFFER and a.role == b"chunk")
    dead = next(a for a in f.atoms if a.kind == NEED and a.role == b"dead")
    index = int.from_bytes(atom.target[1], "big")
    candidates = []
    for row in by(ctx, b"outboard"):
        try: candidates.append(decode_value(row[2].value))
        except Exception: pass
    for item in candidates:
        if (item["workspace_id"] != dead.scope or item["message_id"] != dead.target[1]
                or item["file_id"] != atom.scope or index >= item["total_chunks"]):
            continue
        start = index * item["chunk_bytes"]
        expected = min(item["chunk_bytes"], item["blob_bytes"] - start)
        if len(atom.value) != expected:
            continue
        if chunk_hash(index, atom.value) == item["hashes"][index]:
            return Out(offers=(atom,))
    return Out("Invalid")


# COMMANDS — authored by content.file.send as part of the attachment DAG.


# QUERIES — consumed through content.file progress and save queries.


# CLI — no independent human surface.
CLI = {}
