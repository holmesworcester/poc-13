"""facts/content/file.py — a message attachment descriptor and its user
surface. The descriptor names one content instance, commits to its outboard
root, and carries filename/MIME metadata. It Requires the parent message and
directly carries that message's death key: deletion suppresses and therefore
physically purges the descriptor. The byte-bearing outboard and chunk families
carry the same key, so no parked attachment residue survives deletion."""
import mimetypes, os, tempfile
from kernel import (Atom, Exact, H, NEED, OFFER, Out, REQUIRE, SELF, SUPPRESS,
                    encode, fact, fact_id, frame, now, ts_atom, unframe)
from facts.store import hydrate

TAG = b"content.file"
VERSION = b"\x01"
ENCODING_CLEAR = b"clear-v1"
FILE_ID_DOMAIN = b"poc13.file.id.v1"
CHUNK_BYTES = 256 * 1024
MAX_FILE_BYTES = 10 * 1024 * 1024 * 1024
MAX_FILENAME_BYTES = 255
MAX_MIME_BYTES = 128


def metadata(workspace_id, message_id, file_id, root, blob_bytes,
             total_chunks, filename, mime_type, encoding=ENCODING_CLEAR):
    return frame(VERSION, workspace_id, message_id, file_id, root,
                 blob_bytes.to_bytes(8, "big"), CHUNK_BYTES.to_bytes(4, "big"),
                 total_chunks.to_bytes(4, "big"), encoding, filename, mime_type)


def decode_metadata(value):
    parts = unframe(value)
    if len(parts) != 11 or parts[0] != VERSION:
        raise ValueError("invalid file metadata")
    _, workspace_id, message_id, file_id, root, blob_raw, chunk_raw, total_raw, \
        encoding, filename, mime_type = parts
    if not all(len(x) == 32 for x in (workspace_id, message_id, file_id, root)):
        raise ValueError("invalid file id")
    if len(blob_raw) != 8 or len(chunk_raw) != 4 or len(total_raw) != 4:
        raise ValueError("invalid file geometry")
    blob_bytes = int.from_bytes(blob_raw, "big")
    chunk_bytes = int.from_bytes(chunk_raw, "big")
    total_chunks = int.from_bytes(total_raw, "big")
    if blob_bytes > MAX_FILE_BYTES or chunk_bytes != CHUNK_BYTES:
        raise ValueError("unsupported file geometry")
    expected = 0 if blob_bytes == 0 else (blob_bytes + chunk_bytes - 1) // chunk_bytes
    if total_chunks != expected or total_chunks >= 2 ** 32:
        raise ValueError("file chunk count does not match size")
    if not filename or len(filename) > MAX_FILENAME_BYTES or len(mime_type) > MAX_MIME_BYTES:
        raise ValueError("invalid file metadata text")
    filename.decode("utf-8"); mime_type.decode("utf-8")
    if encoding != ENCODING_CLEAR:
        raise ValueError("unsupported file encoding")
    return {"workspace_id": workspace_id, "message_id": message_id,
            "file_id": file_id, "root": root, "blob_bytes": blob_bytes,
            "chunk_bytes": chunk_bytes, "total_chunks": total_chunks,
            "encoding": encoding, "filename": filename, "mime_type": mime_type}


def _atoms(f, kind, role):
    return [a for a in f.atoms if a.kind == kind and a.role == role]


# SHAPE — descriptor offered both beside its message and at its content id.
def file(workspace_id, message_id, file_id, root, blob_bytes, total_chunks,
         filename, mime_type, t, encoding=ENCODING_CLEAR):
    value = metadata(workspace_id, message_id, file_id, root, blob_bytes,
                     total_chunks, filename, mime_type, encoding)
    return fact(TAG, ts_atom(t, workspace_id),
                Atom(NEED, b"posted", workspace_id, Exact(message_id), effect=REQUIRE),
                Atom(NEED, b"dead", workspace_id, Exact(message_id), effect=SUPPRESS),
                Atom(OFFER, b"file", workspace_id, Exact(message_id), value),
                Atom(OFFER, b"descriptor", file_id, Exact(file_id), value))


# EXTRACT — durable and shared; attachment descriptors reconcile like messages.
def extract(f): return True, True
from facts.sync.index import settle      # opt in: these facts replicate


# CHECK — intrinsic shape and geometry. Contextual parent proof is PROJECT's job.
def check(f):
    try:
        if len(f.atoms) != 5:
            return False
        files = _atoms(f, OFFER, b"file")
        descriptors = _atoms(f, OFFER, b"descriptor")
        posted = _atoms(f, NEED, b"posted")
        dead = _atoms(f, NEED, b"dead")
        stamps = _atoms(f, OFFER, b"ts")
        if not all(len(x) == 1 for x in (files, descriptors, posted, dead, stamps)):
            return False
        meta = decode_metadata(files[0].value)
        return (descriptors[0].value == files[0].value
                and files[0].scope == meta["workspace_id"]
                and files[0].target == Exact(meta["message_id"])
                and descriptors[0].scope == meta["file_id"]
                and descriptors[0].target == Exact(meta["file_id"])
                and posted[0].scope == meta["workspace_id"]
                and posted[0].target == Exact(meta["message_id"])
                and posted[0].effect == REQUIRE and posted[0].value is None
                and dead[0].scope == meta["workspace_id"]
                and dead[0].target == Exact(meta["message_id"])
                and dead[0].effect == SUPPRESS and dead[0].value is None
                and stamps[0].scope == meta["workspace_id"]
                and stamps[0].target == SELF)
    except Exception:
        return False


# PROJECT — parent existence is already proven by the posted Require.
def project(f, ctx):
    return Out(offers=tuple(a for a in f.atoms
                            if a.kind == OFFER and a.role in (b"file", b"descriptor")))


# COMMANDS — author the complete message/descriptor/outboard/chunk DAG only
# after the source has been read successfully. A temporary spool keeps memory
# bounded while preserving an all-inputs-before-admission boundary.
def send(node, workspace_id, channel, author, body, path, mime_type=None, t=None):
    from facts.content import file_chunk, file_outboard, message

    t = int(now() if t is None else t)
    source_path = os.fspath(path)
    if not os.path.isfile(source_path):
        raise ValueError("file path is not a regular file")
    declared_size = os.path.getsize(source_path)
    if declared_size > MAX_FILE_BYTES:
        raise ValueError("file exceeds the 10 GiB limit")
    filename = os.path.basename(source_path).encode("utf-8")
    guessed = mimetypes.guess_type(source_path)[0] or "application/octet-stream"
    mime_bytes = (guessed if mime_type is None else mime_type)
    if isinstance(mime_bytes, str):
        mime_bytes = mime_bytes.encode("utf-8")
    if not filename or len(filename) > MAX_FILENAME_BYTES or len(mime_bytes) > MAX_MIME_BYTES:
        raise ValueError("filename or MIME type is too long")

    message_fact = message.message(workspace_id, channel, author, body, t)
    message_id = fact_id(message_fact)
    hashes, read_bytes = [], 0
    with tempfile.TemporaryFile() as spool, open(source_path, "rb") as source:
        while True:
            data = source.read(CHUNK_BYTES)
            if not data:
                break
            if read_bytes + len(data) > MAX_FILE_BYTES:
                raise ValueError("file exceeds the 10 GiB limit")
            index = len(hashes)
            hashes.append(file_outboard.chunk_hash(index, data))
            spool.write(len(data).to_bytes(4, "big")); spool.write(data)
            read_bytes += len(data)
        if read_bytes != declared_size:
            raise ValueError("file size changed while reading")

        root = file_outboard.root_for(hashes, read_bytes, CHUNK_BYTES, ENCODING_CLEAR)
        file_id = H(frame(FILE_ID_DOMAIN, workspace_id, message_id, root, filename, mime_bytes))
        descriptor_fact = file(workspace_id, message_id, file_id, root, read_bytes,
                               len(hashes), filename, mime_bytes, t)
        outboard_fact = file_outboard.outboard(workspace_id, message_id, file_id,
                                               root, read_bytes, hashes, t)
        parents = (message_fact, descriptor_fact, outboard_fact)
        parent_ids = []
        for item in parents:
            fid = node.admit(encode(item))
            if fid is None:
                raise RuntimeError("locally authored attachment fact failed admission")
            parent_ids.append(fid)

        chunk_ids = []
        spool.seek(0)
        for index in range(len(hashes)):
            raw_len = spool.read(4)
            size = int.from_bytes(raw_len, "big")
            data = spool.read(size)
            if len(raw_len) != 4 or len(data) != size:
                raise RuntimeError("temporary attachment spool is truncated")
            chunk_fact = file_chunk.chunk(workspace_id, message_id, file_id, index, data, t)
            chunk_id = node.admit(encode(chunk_fact))
            if chunk_id is None:
                raise RuntimeError("locally authored attachment chunk failed admission")
            chunk_ids.append(chunk_id)

    return {"message_id": parent_ids[0], "file_fact_id": parent_ids[1],
            "outboard_fact_id": parent_ids[2], "chunk_fact_ids": tuple(chunk_ids),
            "file_id": file_id, "filename": filename, "mime_type": mime_bytes,
            "blob_bytes": read_bytes, "total_chunks": len(hashes)}


def save(node, workspace_id, selector, output_path):
    from facts.content import file_outboard

    record = resolve(node, workspace_id, selector)
    if record is None:
        raise ValueError("file selector did not match a visible attachment")
    if record["chunks_received"] != record["total_chunks"]:
        raise ValueError("file incomplete: have %d/%d chunks" %
                         (record["chunks_received"], record["total_chunks"]))
    chunks = _chunks(node, record["file_id"])
    ordered = [chunks[i] for i in range(record["total_chunks"])]
    hashes = [file_outboard.chunk_hash(i, data) for i, data in enumerate(ordered)]
    root = file_outboard.root_for(hashes, record["blob_bytes"],
                                  record["chunk_bytes"], record["encoding"])
    if root != record["root"] or sum(map(len, ordered)) != record["blob_bytes"]:
        raise ValueError("file root or length mismatch")

    target = os.path.abspath(os.fspath(output_path))
    directory = os.path.dirname(target) or "."
    fd, temporary = tempfile.mkstemp(prefix=".poc13-file-", dir=directory)
    try:
        with os.fdopen(fd, "wb") as output:
            for data in ordered:
                output.write(data)
            output.flush(); os.fsync(output.fileno())
        os.replace(temporary, target)
    except BaseException:
        try: os.unlink(temporary)
        except FileNotFoundError: pass
        raise
    return {"file_fact_id": record["file_fact_id"], "filename": record["filename"],
            "bytes_written": record["blob_bytes"], "output_path": target}


# QUERIES — visible descriptors and validated chunks only. Progress is the
# count of unique indexes whose chunk projector proved against the outboard.
def _chunks(node, file_id):
    hydrate.demand(node, b"chunk", file_id)
    out = {}
    for owner, t, atom in sorted(node.watched(b"chunk", file_id), key=lambda r: (r[1], r[0])):
        index = int.from_bytes(atom.target[1], "big")
        out.setdefault(index, atom.value)
    return out


def files(node, workspace_id, limit=0):
    hydrate.demand(node, b"file", workspace_id)
    records = []
    for owner, t, atom in sorted(node.watched(b"file", workspace_id), key=lambda r: (r[1], r[0])):
        meta = decode_metadata(atom.value)
        chunks = _chunks(node, meta["file_id"])
        item = dict(meta)
        item.update(file_fact_id=owner, created_at=t, chunks_received=len(chunks),
                    complete=len(chunks) == meta["total_chunks"])
        records.append(item)
    return records[:limit] if limit else records


def resolve(node, workspace_id, selector):
    records = files(node, workspace_id)
    text = selector.decode() if isinstance(selector, bytes) else str(selector)
    numbered = text[1:] if text.startswith("#") else text
    if numbered.isdigit():
        index = int(numbered)
        return records[index - 1] if 0 < index <= len(records) else None
    try: wanted = bytes.fromhex(text)
    except ValueError: return None
    return next((item for item in records if item["file_fact_id"] == wanted), None)


def for_message(node, workspace_id, message_id):
    return [item for item in files(node, workspace_id) if item["message_id"] == message_id]


# CLI — the dotted string surface. `feed` remains body-only; message.view adds
# attachment rendering without changing that existing machine-friendly output.
def _send_cli(n, wid, channel, author, body, path, mime_type=None, t=None):
    receipt = send(n, bytes.fromhex(wid), channel.encode(), author.encode(), body.encode(),
                   path, mime_type, int(t) if t is not None else None)
    return "\n".join(("message_id: " + receipt["message_id"].hex(),
                      "file_fact_id: " + receipt["file_fact_id"].hex(),
                      "file_id: " + receipt["file_id"].hex(),
                      "filename: " + receipt["filename"].decode(),
                      "mime: " + receipt["mime_type"].decode(),
                      "blob_bytes: " + str(receipt["blob_bytes"]),
                      "total_chunks: " + str(receipt["total_chunks"])))


def _list_cli(n, wid, limit=None):
    rows = files(n, bytes.fromhex(wid), int(limit or 0))
    lines = ["FILES (%d total):" % len(rows)]
    for index, item in enumerate(rows, 1):
        state = "complete" if item["complete"] else "incomplete"
        pct = 100 if item["total_chunks"] == 0 else \
            item["chunks_received"] * 100 // item["total_chunks"]
        lines.append("%d. %s %s (%d bytes, %d/%d chunks, %d%%)" %
                     (index, state, item["filename"].decode(), item["blob_bytes"],
                      item["chunks_received"], item["total_chunks"], pct))
    return "\n".join(lines)


def _save_cli(n, wid, selector, output_path):
    receipt = save(n, bytes.fromhex(wid), selector, output_path)
    return "\n".join(("file_fact_id: " + receipt["file_fact_id"].hex(),
                      "filename: " + receipt["filename"].decode(),
                      "bytes_written: " + str(receipt["bytes_written"]),
                      "output_path: " + receipt["output_path"]))


CLI = {"send": _send_cli, "list": _list_cli, "save": _save_cli}
