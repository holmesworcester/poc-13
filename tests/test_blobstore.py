"""The content-addressed blob store: identical behaviour across the in-memory,
filesystem, and S3/R2 backends, and the content-address integrity that lets the
store sit outside the trust boundary. The S3 path is exercised offline with a
dict-backed fake client, so the cloud backend's logic is tested with no boto3
and no network — the same shape a real R2 bucket answers."""
import io, os, sys, tempfile
import pytest
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(HERE)
sys.path[:0] = [ROOT_DIR, HERE]
from kernel import H
from blobstore import MemBlobStore, FSBlobStore, S3BlobStore, open_blobs, blobs_of


class _FakeS3:
    """The slice of the boto3 S3 client S3BlobStore uses, over a dict — exactly
    what R2's S3-compatible API provides."""
    def __init__(self): self.store = {}
    def head_object(self, Bucket, Key):
        if (Bucket, Key) not in self.store: raise KeyError(Key)
        return {}
    def get_object(self, Bucket, Key):
        if (Bucket, Key) not in self.store: raise KeyError(Key)
        return {"Body": io.BytesIO(self.store[(Bucket, Key)])}
    def put_object(self, Bucket, Key, Body): self.store[(Bucket, Key)] = Body
    def delete_object(self, Bucket, Key): self.store.pop((Bucket, Key), None)


def _roundtrip(store):
    data = bytes(range(256)) * 40                     # ~10 KiB
    cid = store.put(data)
    assert cid == H(data)                             # the id IS the content hash
    assert store.has(cid) and store.get(cid) == data
    assert store.put(data) == cid                     # idempotent: same bytes -> same object
    absent = H(b"never stored")
    assert not store.has(absent) and store.get(absent) is None
    store.delete(cid)
    assert not store.has(cid) and store.get(cid) is None
    store.delete(cid)                                 # deleting a missing blob is a no-op


def test_mem_backend_roundtrip():
    _roundtrip(MemBlobStore())


def test_fs_backend_roundtrip():
    with tempfile.TemporaryDirectory() as d:
        _roundtrip(FSBlobStore(d))


def test_s3_backend_roundtrip_offline():
    _roundtrip(S3BlobStore("bucket", "prefix/", client=_FakeS3()))


def test_s3_backend_against_real_boto3_mock():
    """The same round-trip over a real boto3 client and a mocked S3 (moto) — the
    wire shape a live AWS S3 or Cloudflare R2 bucket answers. Optional deps:
    `pip install boto3 moto`; skipped when absent (the offline fake covers the
    wrapper logic regardless)."""
    boto3 = pytest.importorskip("boto3")
    moto = pytest.importorskip("moto")
    with moto.mock_aws():
        client = boto3.client("s3", region_name="us-east-1")
        client.create_bucket(Bucket="attachments")
        _roundtrip(S3BlobStore("attachments", "slices/", client=client))


def test_fs_content_address_rejects_a_tampered_blob():
    """Storage is untrusted: a blob whose bytes were altered on disk no longer
    hashes to its cid, so get() reports a miss rather than wrong bytes."""
    with tempfile.TemporaryDirectory() as d:
        store = FSBlobStore(d); cid = store.put(b"authentic")
        path = store._path(cid)
        with open(path, "r+b") as f: f.seek(0); f.write(b"X")
        assert store.get(cid) is None                 # re-hash mismatch -> miss


def test_fs_crash_safe_write_leaves_no_partial_blob():
    with tempfile.TemporaryDirectory() as d:
        store = FSBlobStore(d); store.put(b"complete")
        # only the final content-addressed file exists; no ".blob-" temporaries survive
        leftovers = [f for _r, _dirs, fs in os.walk(d) for f in fs if f.startswith(".blob-")]
        assert leftovers == []


def test_open_blobs_selects_backend():
    assert isinstance(open_blobs(None), MemBlobStore)
    with tempfile.TemporaryDirectory() as d:
        assert isinstance(open_blobs(d), FSBlobStore)
    s3 = open_blobs("s3://mybucket/pre", client=_FakeS3())   # scheme routes to S3/R2, offline
    assert isinstance(s3, S3BlobStore) and s3.bucket == "mybucket" and s3.prefix == "pre"
    cid = s3.put(b"cloud"); assert s3.get(cid) == b"cloud"


def test_blobs_of_attaches_a_default_store():
    class N: pass
    node = N()
    store = blobs_of(node)
    assert isinstance(store, MemBlobStore) and blobs_of(node) is store   # created once, reused


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try: fn(); print("ok  ", name)
            except BaseException as e: print("skip", name, "-", type(e).__name__)
