"""facts/content/file.py — a message attachment descriptor and its user
surface. Metadata is ordinary atom vocabulary rather than a nested record. The
member-signed descriptor commits a BLAKE3 root; each content.file_slice carries
a canonical Bao proof against it. Descriptor and slices directly carry the
message death key, so semantic deletion physically purges the attachment."""
import mimetypes, os, tempfile
from blake3 import blake3
import tinyp2p_bao
from kernel import (Atom, Exact, H, NEED, OFFER, Out, REQUIRE, SELF, SUPPRESS,
                    by, encode, fact, fact_id, frame, now, ts_atom, ts_of)
from facts.auth import signature
from facts.store import hydrate

TAG = b"content.file"
ENCODING_CLEAR = b"clear-v1"
FILE_ID_DOMAIN = b"tinyp2p.file.id.v2"
SLICE_BYTES = 256 * 1024
MAX_FILE_BYTES = 10 * 1024 * 1024 * 1024
MAX_FILENAME_BYTES = 255
MAX_MIME_BYTES = 128
FIELD_ROLES = (b"descriptor", b"file_size", b"file_slices", b"file_slice_bytes",
               b"file_encoding", b"file_name", b"file_mime")
PROJECTED_ROLES = (b"file", *FIELD_ROLES)


def _u32(value): return value.to_bytes(4, "big")
def _u64(value): return value.to_bytes(8, "big")


def file_id_for(workspace_id, message_id, root, filename, mime_type):
    return H(frame(FILE_ID_DOMAIN, workspace_id, message_id, root, filename, mime_type))


# SHAPE — each metadata field is a named scalar offer at (file id, root).
def file(workspace_id, message_id, file_id, root, blob_bytes, total_slices,
         filename, mime_type, t, encoding=ENCODING_CLEAR):
    return fact(TAG, ts_atom(t, workspace_id),
                Atom(NEED, b"posted", workspace_id, Exact(message_id), effect=REQUIRE),
                Atom(NEED, b"pk", workspace_id, SELF, effect=REQUIRE),
                Atom(NEED, b"key", workspace_id, Exact(workspace_id), effect=REQUIRE),
                Atom(NEED, b"dead", workspace_id, Exact(message_id), effect=SUPPRESS),
                Atom(OFFER, b"file", workspace_id, Exact(message_id), file_id),
                Atom(OFFER, b"descriptor", file_id, Exact(root)),
                Atom(OFFER, b"file_size", file_id, Exact(root), _u64(blob_bytes)),
                Atom(OFFER, b"file_slices", file_id, Exact(root), _u32(total_slices)),
                Atom(OFFER, b"file_slice_bytes", file_id, Exact(root), _u32(SLICE_BYTES)),
                Atom(OFFER, b"file_encoding", file_id, Exact(root), encoding),
                Atom(OFFER, b"file_name", file_id, Exact(root), filename),
                Atom(OFFER, b"file_mime", file_id, Exact(root), mime_type))


# EXTRACT — durable and shared; attachment descriptors reconcile like messages.
def extract(f): return True, True
from facts.sync.index import settle      # opt in: these facts replicate


# CHECK — exact SHAPE, scalar widths, geometry, text, and content-instance id.
def _canonical(f):
    try:
        listing = next(a for a in f.atoms if a.kind == OFFER and a.role == b"file")
        posted = next(a for a in f.atoms if a.kind == NEED and a.role == b"posted")
        fields = {role: next(a for a in f.atoms if a.kind == OFFER and a.role == role)
                  for role in FIELD_ROLES}
        descriptor = fields[b"descriptor"]
        workspace_id, message_id, file_id, root = (listing.scope, listing.target[1],
                                                    listing.value, descriptor.target[1])
        values = {role: fields[role].value for role in FIELD_ROLES[1:]}
        if len(values[b"file_size"]) != 8 or len(values[b"file_slices"]) != 4 or \
                len(values[b"file_slice_bytes"]) != 4:
            return None
        blob_bytes = int.from_bytes(values[b"file_size"], "big")
        total_slices = int.from_bytes(values[b"file_slices"], "big")
        slice_bytes = int.from_bytes(values[b"file_slice_bytes"], "big")
        if slice_bytes != SLICE_BYTES: return None
        expected = 0 if blob_bytes == 0 else (blob_bytes + slice_bytes - 1) // slice_bytes
        filename, mime_type = values[b"file_name"], values[b"file_mime"]
        filename.decode("utf-8"); mime_type.decode("utf-8")
        valid = (len(workspace_id) == len(message_id) == len(file_id) == len(root) == 32
                 and blob_bytes <= MAX_FILE_BYTES and total_slices == expected
                 and values[b"file_encoding"] == ENCODING_CLEAR
                 and 0 < len(filename) <= MAX_FILENAME_BYTES
                 and len(mime_type) <= MAX_MIME_BYTES
                 and file_id == file_id_for(workspace_id, message_id, root,
                                            filename, mime_type))
        rebuilt = file(workspace_id, message_id, file_id, root, blob_bytes,
                       total_slices, filename, mime_type, ts_of(f),
                       values[b"file_encoding"])
        return (listing, posted, fields) if valid and f == rebuilt else None
    except Exception:
        return None


def check(f): return _canonical(f) is not None


# PROJECT — the descriptor must be signed by the parent message's author.
def project(f, ctx):
    canonical = _canonical(f)
    if canonical is None: return Out("Invalid")
    signer, members = signature.blessed(ctx)
    authors = {row[2].value for row in by(ctx, b"posted")}
    if not signer & {members[a] for a in authors if a in members}: return Out("Invalid")
    return Out(offers=tuple(a for a in f.atoms
                            if a.kind == OFFER and a.role in PROJECTED_ROLES))


# COMMANDS — read and prove the complete source before admitting any graph fact.
def send(node, workspace_id, channel_id, author, body, path, mime_type=None, t=None):
    from facts.content import file_slice, message
    from facts.auth import local_signer_secret

    t = int(now() if t is None else t)
    source_path = os.path.abspath(os.fspath(path))
    if not os.path.isfile(source_path): raise ValueError("file path is not a regular file")
    declared_size = os.path.getsize(source_path)
    if declared_size > MAX_FILE_BYTES: raise ValueError("file exceeds the 10 GiB limit")
    filename = os.path.basename(source_path).encode("utf-8")
    guessed = mimetypes.guess_type(source_path)[0] or "application/octet-stream"
    mime_bytes = guessed if mime_type is None else mime_type
    if isinstance(mime_bytes, str): mime_bytes = mime_bytes.encode("utf-8")
    if not filename or len(filename) > MAX_FILENAME_BYTES or len(mime_bytes) > MAX_MIME_BYTES:
        raise ValueError("filename or MIME type is too long")

    read_bytes = declared_size
    total_slices = 0 if read_bytes == 0 else (read_bytes + SLICE_BYTES - 1) // SLICE_BYTES
    local = local_signer_secret.current(node)
    if not local: raise RuntimeError("no local signer key: run auth.local_signer_secret.keygen first")
    hydrate.demand(node, b"key", workspace_id)
    author_id = next((owner for owner, _, atom in node.watched(b"key", workspace_id)
                      if atom.target == Exact(workspace_id) and atom.value == local[1]), None)
    if author_id is None: raise RuntimeError("local signer is not a workspace member")
    message_fact = message.message(workspace_id, channel_id, author_id, body, t)
    message_id = fact_id(message_fact)

    with tempfile.TemporaryDirectory(prefix="tinyp2p-bao-") as directory, \
            tempfile.TemporaryFile() as spool:
        outboard = os.path.join(directory, "source.obao")
        root = bytes(tinyp2p_bao.prepare_file(source_path, outboard))
        file_id = file_id_for(workspace_id, message_id, root, filename, mime_bytes)
        for index in range(total_slices):
            start = index * SLICE_BYTES
            count = min(SLICE_BYTES, read_bytes - start)
            proof = bytes(tinyp2p_bao.extract_slice(source_path, outboard, start, count))
            verified = file_slice.verified_bytes(proof, root, index, read_bytes, SLICE_BYTES)
            if len(verified) != count: raise RuntimeError("Bao returned a short slice")
            spool.write(len(proof).to_bytes(4, "big")); spool.write(proof)
        if os.path.getsize(source_path) != declared_size:
            raise ValueError("file size changed while proving")

        descriptor_fact = file(workspace_id, message_id, file_id, root, read_bytes,
                               total_slices, filename, mime_bytes, t)
        admitted_message = signature.signed_admit(
            node, workspace_id,
            lambda member_id: message.message(workspace_id, channel_id, member_id, body, t), t)
        if admitted_message != message_id:
            raise RuntimeError("local signer changed while authoring attachment")
        descriptor_id = signature.signed_admit(
            node, workspace_id, lambda _member_id: descriptor_fact, t)

        slice_ids = []; spool.seek(0)
        for index in range(total_slices):
            raw_len = spool.read(4)
            if len(raw_len) != 4: raise RuntimeError("temporary Bao spool is truncated")
            size = int.from_bytes(raw_len, "big"); proof = spool.read(size)
            if len(proof) != size: raise RuntimeError("temporary Bao spool is truncated")
            item = file_slice.file_slice(workspace_id, message_id, file_id, root, index, proof, t)
            fid = node.admit(encode(item))
            if fid is None: raise RuntimeError("locally authored file slice failed admission")
            slice_ids.append(fid)

    return {"message_id": message_id, "file_fact_id": descriptor_id,
            "slice_fact_ids": tuple(slice_ids), "file_id": file_id,
            "filename": filename, "mime_type": mime_bytes, "blob_bytes": read_bytes,
            "total_slices": total_slices}


def save(node, workspace_id, selector, output_path):
    from facts.content import file_slice

    record = resolve(node, workspace_id, selector)
    if record is None: raise ValueError("file selector did not match a visible attachment")
    if record["slices_received"] != record["total_slices"]:
        raise ValueError("file incomplete: have %d/%d slices" %
                         (record["slices_received"], record["total_slices"]))
    proofs = _slices(node, record["file_id"])
    target = os.path.abspath(os.fspath(output_path)); directory = os.path.dirname(target) or "."
    fd, temporary = tempfile.mkstemp(prefix=".tinyp2p-file-", dir=directory)
    try:
        written, hasher = 0, blake3()
        with os.fdopen(fd, "wb") as output:
            for index in range(record["total_slices"]):
                data = file_slice.verified_bytes(proofs[index], record["root"], index,
                                                 record["blob_bytes"], record["slice_bytes"])
                output.write(data); hasher.update(data); written += len(data)
            output.flush(); os.fsync(output.fileno())
        if written != record["blob_bytes"] or hasher.digest() != record["root"]:
            raise ValueError("file root or length mismatch")
        os.replace(temporary, target)
    except BaseException:
        try: os.unlink(temporary)
        except FileNotFoundError: pass
        raise
    return {"file_fact_id": record["file_fact_id"], "filename": record["filename"],
            "bytes_written": record["blob_bytes"], "output_path": target}


# QUERIES — join only promoted descriptor atoms; count unique validated slices.
def _slices(node, file_id):
    hydrate.demand(node, b"slice", file_id)
    out = {}
    for owner, t, atom in sorted(node.watched(b"slice", file_id), key=lambda row: (row[1], row[0])):
        out.setdefault(int.from_bytes(atom.target[1], "big"), atom.value)
    return out


def _descriptor(node, owner, workspace_id, message_id, file_id):
    hydrate.demand(node, b"descriptor", file_id)
    rows = {}
    for role in FIELD_ROLES:
        row = next((item for item in node.watched(role, file_id) if item[0] == owner), None)
        if row is None: return None
        rows[role] = row[2]
    root = rows[b"descriptor"].target[1]
    return {"workspace_id": workspace_id, "message_id": message_id, "file_id": file_id,
            "root": root, "blob_bytes": int.from_bytes(rows[b"file_size"].value, "big"),
            "total_slices": int.from_bytes(rows[b"file_slices"].value, "big"),
            "slice_bytes": int.from_bytes(rows[b"file_slice_bytes"].value, "big"),
            "encoding": rows[b"file_encoding"].value, "filename": rows[b"file_name"].value,
            "mime_type": rows[b"file_mime"].value}


def files(node, workspace_id, limit=0):
    hydrate.demand(node, b"file", workspace_id)
    records = []
    for owner, t, atom in sorted(node.watched(b"file", workspace_id), key=lambda row: (row[1], row[0])):
        item = _descriptor(node, owner, workspace_id, atom.target[1], atom.value)
        if item is None: continue
        proofs = _slices(node, item["file_id"])
        item.update(file_fact_id=owner, created_at=t, slices_received=len(proofs),
                    complete=len(proofs) == item["total_slices"])
        records.append(item)
    return records[:limit] if limit else records


def resolve(node, workspace_id, selector):
    records = files(node, workspace_id)
    text = selector.decode() if isinstance(selector, bytes) else str(selector)
    numbered = text[1:] if text.startswith("#") else text
    if numbered.isdigit():
        index = int(numbered); return records[index - 1] if 0 < index <= len(records) else None
    try: wanted = bytes.fromhex(text)
    except ValueError: return None
    return next((item for item in records if item["file_fact_id"] == wanted), None)


def for_message(node, workspace_id, message_id):
    return [item for item in files(node, workspace_id) if item["message_id"] == message_id]


# CLI — dotted string surface for send, progress, and atomic verified export.
def _send_cli(n, wid, channel, author, body, path, mime_type=None, t=None):
    from facts.content import channel as channels
    workspace_id = bytes.fromhex(wid)
    receipt = send(n, workspace_id, channels.resolve(n, workspace_id, channel),
                   author.encode(), body.encode(),
                   path, mime_type, int(t) if t is not None else None)
    return "\n".join(("message_id: " + receipt["message_id"].hex(),
                      "file_fact_id: " + receipt["file_fact_id"].hex(),
                      "file_id: " + receipt["file_id"].hex(),
                      "filename: " + receipt["filename"].decode(),
                      "mime: " + receipt["mime_type"].decode(),
                      "blob_bytes: " + str(receipt["blob_bytes"]),
                      "total_slices: " + str(receipt["total_slices"])))


def _list_cli(n, wid, limit=None):
    rows = files(n, bytes.fromhex(wid), int(limit or 0)); lines = ["FILES (%d total):" % len(rows)]
    for index, item in enumerate(rows, 1):
        state = "complete" if item["complete"] else "incomplete"
        pct = 100 if item["total_slices"] == 0 else \
            item["slices_received"] * 100 // item["total_slices"]
        lines.append("%d. %s %s (%d bytes, %d/%d slices, %d%%)" %
                     (index, state, item["filename"].decode(), item["blob_bytes"],
                      item["slices_received"], item["total_slices"], pct))
    return "\n".join(lines)


def _save_cli(n, wid, selector, output_path):
    receipt = save(n, bytes.fromhex(wid), selector, output_path)
    return "\n".join(("file_fact_id: " + receipt["file_fact_id"].hex(),
                      "filename: " + receipt["filename"].decode(),
                      "bytes_written: " + str(receipt["bytes_written"]),
                      "output_path: " + receipt["output_path"]))


CLI = {"send": _send_cli, "list": _list_cli, "save": _save_cli}
