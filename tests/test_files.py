"""Poc-10-style file slices: atomized descriptors, self-contained Bao proofs,
cold hydration, verified export, and terminal deletion of every payload byte."""
import os, sys, tempfile
from blake3 import blake3
import tinyp2p_bao
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(HERE)
sys.path[:0] = [ROOT_DIR, HERE, os.path.join(ROOT_DIR, "bin")]

from kernel import Atom, Exact, H, PROVIDE, SUPPRESS_IF, Node, Store, encode, fact
from facts import ROOT
from facts.auth import signature, workspace
from facts.content import channel, file, file_slice, message, message_deletion
from facts.store import hydrate
from facts.sync import index as sync_index
from blobstore import blobs_of
from harness import reboot
from runtime import flush


def _node():
    n = Node(ROOT); wid = workspace.create(n, b"acme", 1); n.run()
    return n, wid, channel.resolve(n, wid, "general")


def _write(path, size):
    data = bytes(i % 251 for i in range(size))
    with open(path, "wb") as output: output.write(data)
    return data


def _proofs(path):
    size = os.path.getsize(path); root = blake3(open(path, "rb").read()).digest()
    with tempfile.TemporaryDirectory() as directory:
        outboard = os.path.join(directory, "source.obao")
        assert bytes(tinyp2p_bao.prepare_file(path, outboard)) == root
        proofs = []
        for index, start in enumerate(range(0, size, file.SLICE_BYTES)):
            count = min(file.SLICE_BYTES, size - start)
            proof = bytes(tinyp2p_bao.extract_slice(path, outboard, start, count))
            assert file_slice.verified_bytes(proof, root, index, size) == \
                open(path, "rb").read()[start:start + count]
            proofs.append(proof)
    return root, proofs


def _direct_death_key(item, workspace_id, message_id):
    return any(a.relationship == SUPPRESS_IF and a.name == b"dead" and a.scope == workspace_id
               and a.target == Exact(message_id) for a in item.atoms)


def test_send_view_save_roundtrip_atomized_descriptor_and_cold_hydration():
    n, wid, channel_id = _node()
    with tempfile.TemporaryDirectory() as directory:
        source = os.path.join(directory, "payload.bin")
        payload = _write(source, file.SLICE_BYTES + 37_979)
        receipt = file.send(n, wid, channel_id, b"al", b"see attached", source,
                            "application/x-tinyp2p", 2); n.run()

        assert message.feed(n, wid, channel_id) == [b"see attached"]
        assert message.view(n, wid, channel_id) == [
            "see attached", "  file: payload.bin (300123 bytes, complete)"]
        [row] = file.files(n, wid)
        assert row["slices_received"] == row["total_slices"] == 2 and row["complete"]
        assert row["mime_type"] == b"application/x-tinyp2p"
        assert file.resolve(n, wid, "1") == file.resolve(n, wid, "#1") == row
        assert file.resolve(n, wid, receipt["file_fact_id"].hex()) == row

        descriptor = n.facts[receipt["file_fact_id"]]
        assert {a.name for a in descriptor.atoms if a.relationship == PROVIDE} >= {
            b"file", b"descriptor", b"file_size", b"file_slices",
            b"file_slice_bytes", b"file_name", b"file_mime"}
        assert {a.name for a in descriptor.atoms if a.relationship != PROVIDE} >= {
            b"posted", b"pk", b"key", b"dead"}
        assert len(descriptor.atoms) == 12
        assert signature.signed(n, wid, receipt["file_fact_id"])
        size_atom = next(a for a in descriptor.atoms if a.name == b"file_size")
        assert int.from_bytes(size_atom.value, "big") == len(payload)

        restored = reboot(n); [cold] = file.files(restored, wid)
        assert cold["complete"] and cold["file_fact_id"] == receipt["file_fact_id"]
        target = os.path.join(directory, "restored.bin")
        assert file.save(restored, wid, "#1", target)["bytes_written"] == len(payload)
        assert open(target, "rb").read() == payload


def test_only_present_verified_blobs_count_and_incomplete_save_is_atomic():
    """The new split: a slice fact NAMES a proof (by cid) and validates on shape
    alone; a slice counts as received only once its blob is present AND Bao-
    verifies against the root. So a corrupt blob and an out-of-range index both
    fail to complete the file, and an incomplete save writes nothing."""
    n, wid, channel_id = _node(); blobs = blobs_of(n)
    with tempfile.TemporaryDirectory() as directory:
        source = os.path.join(directory, "partial.bin")
        _write(source, file.SLICE_BYTES + 17); root, proofs = _proofs(source)
        message_id = message.send(n, wid, channel_id, b"partial", 2)
        file_id = file.file_id_for(wid, message_id, root, b"partial.bin",
                                   b"application/octet-stream")
        descriptor = file.file(wid, message_id, file_id, root, os.path.getsize(source), 2,
                               b"partial.bin", b"application/octet-stream", 2)
        blobs.put(proofs[0])                            # slice 0's blob is present and valid
        first = file_slice.file_slice(wid, message_id, file_id, root, 0, H(proofs[0]), 2)
        descriptor_id = signature.signed_admit(n, wid, lambda _member_id: descriptor, 2)
        first_id = n.admit(encode(first))
        assert descriptor_id is not None and first_id is not None
        n.run()
        assert n.memo[first_id] == "Valid"              # the naming fact validates on shape

        malformed = fact(file_slice.TAG, *first.atoms,
                         Atom(PROVIDE, b"extra", file_id, Exact(b"extra")))
        malformed_id = n.admit(encode(malformed), checked=True); n.run()
        assert n.memo[malformed_id] == "Invalid"        # PROJECT rechecks canonical SHAPE

        corrupted = bytearray(proofs[1]); corrupted[-1] ^= 1
        blobs.put(bytes(corrupted))                      # slice 1's blob is present but corrupt
        wrong = file_slice.file_slice(wid, message_id, file_id, root, 1, H(bytes(corrupted)), 3)
        extra = file_slice.file_slice(wid, message_id, file_id, root, 2, H(proofs[1]), 3)
        wrong_id = n.admit(encode(wrong)); extra_id = n.admit(encode(extra)); n.run()
        assert n.memo[wrong_id] == "Valid"               # names a blob: valid, but the blob won't verify
        assert n.memo[extra_id] == "Invalid"             # index 2 past a 2-slice descriptor: inert
        [row] = file.files(n, wid)
        assert row["slices_received"] == 1 and row["total_slices"] == 2   # corrupt blob does not count

        target = os.path.join(directory, "must-not-exist.bin")
        try:
            file.save(n, wid, "1", target); assert False, "incomplete save succeeded"
        except ValueError as error:
            assert "have 1/2 slices" in str(error)
        assert not os.path.exists(target)


def test_zero_byte_file_and_sparse_oversize_rejection():
    n, wid, channel_id = _node()
    with tempfile.TemporaryDirectory() as directory:
        empty = os.path.join(directory, "empty.bin"); open(empty, "wb").close()
        receipt = file.send(n, wid, channel_id, b"al", b"empty", empty, None, 2); n.run()
        assert receipt["total_slices"] == 0
        [row] = file.files(n, wid)
        assert row["complete"] and row["slices_received"] == row["total_slices"] == 0
        target = os.path.join(directory, "empty-copy.bin")
        assert file.save(n, wid, "1", target)["bytes_written"] == 0
        assert open(target, "rb").read() == b""

        huge = os.path.join(directory, "huge.bin")
        with open(huge, "wb") as output: output.seek(file.MAX_FILE_BYTES); output.write(b"x")
        before = set(n.durable)
        try:
            file.send(n, wid, channel_id, b"al", b"too large", huge, None, 3)
            assert False, "oversized file accepted"
        except ValueError as error:
            assert "10 GiB" in str(error)
        assert set(n.durable) == before


def test_message_deletion_physically_purges_descriptor_and_bao_slices():
    store, flushed = Store(), set(); n = Node(ROOT, store)
    wid = workspace.create(n, b"acme", 1); n.run()
    channel_id = channel.resolve(n, wid, "general"); flush(n, store, flushed)
    with tempfile.TemporaryDirectory() as directory:
        source = os.path.join(directory, "doomed.bin"); _write(source, file.SLICE_BYTES + 11)
        receipt = file.send(n, wid, channel_id, b"al", b"doomed", source, None, 2)
        n.run(); flush(n, store, flushed)

    killed = (receipt["message_id"], receipt["file_fact_id"], *receipt["slice_fact_ids"])
    old_bytes = {fid: n.durable[fid] for fid in killed}
    for fid in killed[1:]: assert _direct_death_key(n.facts[fid], wid, receipt["message_id"])
    assert all(store.fact_bytes(fid) is not None for fid in killed)

    deletion_id = message_deletion.delete(n, wid, receipt["message_id"], 3)
    n.run(); flush(n, store, flushed)
    leaves = set(sync_index.tree(n).fids(b"", b"\xff" * 41))
    for fid in killed:
        assert fid not in n.facts and fid not in n.memo and fid not in n.durable
        assert store.fact_bytes(fid) is None and fid not in leaves and fid not in flushed
    assert deletion_id in n.durable and store.fact_bytes(deletion_id) is not None

    for fid in reversed(killed): assert n.admit(old_bytes[fid]) == fid
    n.run(); flush(n, store, flushed)
    assert all(fid not in n.facts and store.fact_bytes(fid) is None for fid in killed)
    fresh = Node(ROOT, store); hydrate.demand(fresh)
    assert deletion_id in fresh.durable and all(fid not in fresh.facts for fid in killed)


if __name__ == "__main__":
    for test in (test_send_view_save_roundtrip_atomized_descriptor_and_cold_hydration,
                 test_only_valid_bao_slices_count_and_incomplete_save_is_atomic,
                 test_zero_byte_file_and_sparse_oversize_rejection,
                 test_message_deletion_physically_purges_descriptor_and_bao_slices):
        test(); print("ok ", test.__name__)
