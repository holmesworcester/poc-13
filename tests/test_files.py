"""File attachments as descriptor -> outboard -> chunk facts. The tests prove
the real user path, public chunk integrity, partial progress, cold hydration,
and terminal deletion: every attachment fact carries the message death key and
leaves memory, SQLite, and the sync tree when that key validates."""
import os, sys, tempfile
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(HERE)
sys.path[:0] = [ROOT_DIR, HERE, os.path.join(ROOT_DIR, "bin")]

from kernel import Exact, NEED, SUPPRESS, Node, Store, encode, fact_id
from facts import ROOT
from facts.auth import workspace
from facts.content import file, file_chunk, file_outboard, message, message_deletion
from facts.store import hydrate
from facts.sync import index as sync_index
from harness import reboot
from runtime import flush


def _node():
    n = Node(ROOT)
    wid = workspace.create(n, b"acme", 1); n.run()
    return n, wid


def _write(path, size):
    data = bytes(i % 251 for i in range(size))
    with open(path, "wb") as output: output.write(data)
    return data


def _direct_death_key(fact, workspace_id, message_id):
    return any(a.kind == NEED and a.role == b"dead" and a.scope == workspace_id
               and a.target == Exact(message_id) and a.effect == SUPPRESS
               for a in fact.atoms)


def test_send_view_save_roundtrip_and_cold_hydration():
    n, wid = _node()
    with tempfile.TemporaryDirectory() as directory:
        source = os.path.join(directory, "payload.bin")
        payload = _write(source, file.CHUNK_BYTES + 37_979)
        receipt = file.send(n, wid, b"general", b"al", b"see attached", source,
                            "application/x-poc13", 2)
        n.run()

        assert message.feed(n, wid, b"general") == [b"see attached"]
        assert message.view(n, wid, b"general") == [
            "see attached", "  file: payload.bin (300123 bytes, complete)"]
        [row] = file.files(n, wid)
        assert row["chunks_received"] == row["total_chunks"] == 2 and row["complete"]
        assert row["mime_type"] == b"application/x-poc13"
        assert file.resolve(n, wid, "1") == row
        assert file.resolve(n, wid, "#1") == row
        assert file.resolve(n, wid, receipt["file_fact_id"].hex()) == row

        restored = reboot(n)
        [cold] = file.files(restored, wid)
        assert cold["complete"] and cold["file_fact_id"] == receipt["file_fact_id"]
        target = os.path.join(directory, "restored.bin")
        saved = file.save(restored, wid, "#1", target)
        assert saved["bytes_written"] == len(payload)
        assert open(target, "rb").read() == payload


def test_only_valid_chunks_count_and_incomplete_save_is_atomic():
    n, wid = _node()
    parent = message.message(wid, b"general", b"al", b"partial", 2)
    message_id = fact_id(parent)
    file_id = b"\x44" * 32
    parts = [b"a" * file.CHUNK_BYTES, b"b" * 17]
    hashes = [file_outboard.chunk_hash(i, data) for i, data in enumerate(parts)]
    root = file_outboard.root_for(hashes, sum(map(len, parts)))
    descriptor = file.file(wid, message_id, file_id, root, sum(map(len, parts)), 2,
                           b"partial.bin", b"application/octet-stream", 2)
    outboard = file_outboard.outboard(wid, message_id, file_id, root,
                                      sum(map(len, parts)), hashes, 2)
    for item in (parent, descriptor, outboard,
                 file_chunk.chunk(wid, message_id, file_id, 0, parts[0], 2)):
        assert n.admit(encode(item)) is not None
    n.run()

    wrong = file_chunk.chunk(wid, message_id, file_id, 1, b"x" * len(parts[1]), 3)
    extra = file_chunk.chunk(wid, message_id, file_id, 2, b"extra", 3)
    wrong_id = n.admit(encode(wrong)); extra_id = n.admit(encode(extra)); n.run()
    assert n.memo[wrong_id] == "Invalid" and n.memo[extra_id] == "Invalid"
    [row] = file.files(n, wid)
    assert row["chunks_received"] == 1 and row["total_chunks"] == 2

    with tempfile.TemporaryDirectory() as directory:
        target = os.path.join(directory, "must-not-exist.bin")
        try:
            file.save(n, wid, "1", target)
            assert False, "incomplete save succeeded"
        except ValueError as error:
            assert "have 1/2 chunks" in str(error)
        assert not os.path.exists(target)


def test_zero_byte_file_and_sparse_oversize_rejection():
    n, wid = _node()
    with tempfile.TemporaryDirectory() as directory:
        empty = os.path.join(directory, "empty.bin"); open(empty, "wb").close()
        receipt = file.send(n, wid, b"general", b"al", b"empty", empty, None, 2); n.run()
        assert receipt["total_chunks"] == 0
        [row] = file.files(n, wid)
        assert row["complete"] and row["chunks_received"] == row["total_chunks"] == 0
        target = os.path.join(directory, "empty-copy.bin")
        assert file.save(n, wid, "1", target)["bytes_written"] == 0
        assert open(target, "rb").read() == b""

        huge = os.path.join(directory, "huge.bin")
        with open(huge, "wb") as output:
            output.seek(file.MAX_FILE_BYTES); output.write(b"x")
        before = set(n.durable)
        try:
            file.send(n, wid, b"general", b"al", b"too large", huge, None, 3)
            assert False, "oversized file accepted"
        except ValueError as error:
            assert "10 GiB" in str(error)
        assert set(n.durable) == before


def test_message_deletion_physically_purges_the_whole_attachment_tree():
    store, flushed = Store(), set()
    n = Node(ROOT, store)
    wid = workspace.create(n, b"acme", 1); n.run(); flush(n, store, flushed)
    with tempfile.TemporaryDirectory() as directory:
        source = os.path.join(directory, "doomed.bin")
        _write(source, file.CHUNK_BYTES + 11)
        receipt = file.send(n, wid, b"general", b"al", b"doomed", source, None, 2)
        n.run(); flush(n, store, flushed)

    killed = (receipt["message_id"], receipt["file_fact_id"],
              receipt["outboard_fact_id"], *receipt["chunk_fact_ids"])
    old_bytes = {fid: n.durable[fid] for fid in killed}
    for fid in killed[1:]:
        assert _direct_death_key(n.facts[fid], wid, receipt["message_id"])
    assert all(store.fact_bytes(fid) is not None for fid in killed)

    deletion_id = message_deletion.delete(n, wid, receipt["message_id"], 3)
    n.run(); flush(n, store, flushed)
    leaves = set(sync_index.tree(n).fids(b"", b"\xff" * 41))
    for fid in killed:
        assert fid not in n.facts and fid not in n.memo and fid not in n.durable
        assert store.fact_bytes(fid) is None and fid not in leaves and fid not in flushed
    assert deletion_id in n.durable and store.fact_bytes(deletion_id) is not None

    # A laggard can re-ship every old body in any order. The durable death edge
    # wins before Requires, so every re-arrival dies and never reaches disk.
    for fid in reversed(killed):
        assert n.admit(old_bytes[fid]) == fid
    n.run(); flush(n, store, flushed)
    assert all(fid not in n.facts and store.fact_bytes(fid) is None for fid in killed)

    fresh = Node(ROOT, store); hydrate.demand(fresh)
    assert deletion_id in fresh.durable
    assert all(fid not in fresh.facts for fid in killed)


if __name__ == "__main__":
    for test in (test_send_view_save_roundtrip_and_cold_hydration,
                 test_only_valid_chunks_count_and_incomplete_save_is_atomic,
                 test_zero_byte_file_and_sparse_oversize_rejection,
                 test_message_deletion_physically_purges_the_whole_attachment_tree):
        test(); print("ok ", test.__name__)
