"""blobstore.py — the content-addressed byte store, the one seam that keeps
large payloads out of the fact graph.

A fact family names bytes by their content id (`cid = H(data)`, BLAKE3-256) and
carries only that 32-byte name; the bytes themselves live here. This is the
whole reason attachment slices are not facts: a slice fact carries a cid, the
~205 KiB Bao proof it names is a blob, and the two travel different paths — the
cid rides ordinary sync (small, in the treap), the blob rides a separate
content-addressed fetch (large, out of the reconciliation set).

One interface, three backends: `MemBlobStore` for a bare node (single-process
tests), `FSBlobStore` for a local client (sharded files on disk), `S3BlobStore`
for the cloud (R2/S3, zero-egress direct fetch). The store is outside the trust
boundary exactly like the fact `Store`: `get` re-hashes and returns a miss on any
mismatch, so a corrupt or substituted blob is never a wrong blob. `put` is
content-addressed and idempotent (same bytes -> same cid -> same object), so a
blob offered by two peers dedups for free and deletion is reference-free."""
import os, tempfile
from kernel import H


class MemBlobStore:
    """In-memory content store — the default for a node with no configured
    backend. Everything a real backend does, over a dict."""
    __slots__ = ("d",)
    def __init__(self): self.d = {}
    def has(self, cid): return cid in self.d
    def get(self, cid): return self.d.get(cid)
    def put(self, data): cid = H(data); self.d[cid] = data; return cid
    def delete(self, cid): self.d.pop(cid, None)


class FSBlobStore:
    """Local filesystem store: one file per blob at `root/<hex[:2]>/<hex>`,
    sharded so a directory never holds the whole set. `put` writes a sibling
    temporary, fsyncs, and atomically renames, so a crash mid-write leaves no
    half blob. `get` re-hashes and rejects a mismatch — storage is untrusted."""
    __slots__ = ("root",)
    def __init__(self, root):
        self.root = os.fspath(root); os.makedirs(self.root, exist_ok=True)
    def _path(self, cid):
        h = cid.hex(); return os.path.join(self.root, h[:2], h)
    def has(self, cid): return os.path.exists(self._path(cid))
    def get(self, cid):
        try:
            with open(self._path(cid), "rb") as f: data = f.read()
        except FileNotFoundError: return None
        return data if H(data) == cid else None
    def put(self, data):
        cid = H(data); path = self._path(cid)
        if os.path.exists(path): return cid
        os.makedirs(os.path.dirname(path), exist_ok=True)
        fd, tmp = tempfile.mkstemp(prefix=".blob-", dir=os.path.dirname(path))
        try:
            with os.fdopen(fd, "wb") as f: f.write(data); f.flush(); os.fsync(f.fileno())
            os.replace(tmp, path)
        except BaseException:
            try: os.unlink(tmp)
            except FileNotFoundError: pass
            raise
        return cid
    def delete(self, cid):
        try: os.unlink(self._path(cid))
        except FileNotFoundError: pass


class S3BlobStore:
    """R2/S3 store: one object per blob keyed by its hex cid. Content-addressed
    keys mean every node writes the same object for the same bytes, so a shared
    bucket IS the multi-node blob plane — a cold node reads what any node wrote,
    with no peer transfer and (on R2) no egress bill. Cloudflare R2 is reached
    by pointing boto3 at its S3-compatible `endpoint_url`; plain AWS S3 needs no
    endpoint. `get` re-hashes: the object store is untrusted like every other."""
    __slots__ = ("s3", "bucket", "prefix")
    def __init__(self, bucket, prefix="", client=None, **cfg):
        if client is None:
            import boto3                     # lazy: only a configured cloud node needs it
            client = boto3.client("s3", **cfg)
        self.s3, self.bucket, self.prefix = client, bucket, prefix
    def _key(self, cid): return self.prefix + cid.hex()
    def has(self, cid):
        try: self.s3.head_object(Bucket=self.bucket, Key=self._key(cid)); return True
        except Exception: return False
    def get(self, cid):
        try: data = self.s3.get_object(Bucket=self.bucket, Key=self._key(cid))["Body"].read()
        except Exception: return None
        return data if H(data) == cid else None
    def put(self, data):
        cid = H(data); self.s3.put_object(Bucket=self.bucket, Key=self._key(cid), Body=data)
        return cid
    def delete(self, cid):
        try: self.s3.delete_object(Bucket=self.bucket, Key=self._key(cid))
        except Exception: pass


def open_blobs(spec, **cfg):
    """Pick a backend from a spec string: `None` -> in-memory; `s3://bucket/prefix`
    (or `r2://…`) -> S3/R2 with credentials and `endpoint_url` from `cfg` or the
    environment (`TINYP2P_S3_ENDPOINT` for R2); any other string -> a filesystem
    directory. The one place a deployment chooses local vs cloud storage."""
    if spec is None: return MemBlobStore()
    for scheme in ("s3://", "r2://"):
        if spec.startswith(scheme):
            rest = spec[len(scheme):]; bucket, _, prefix = rest.partition("/")
            endpoint = cfg.pop("endpoint_url", None) or os.environ.get("TINYP2P_S3_ENDPOINT")
            if endpoint: cfg["endpoint_url"] = endpoint
            return S3BlobStore(bucket, prefix, **cfg)
    return FSBlobStore(spec)


def blobs_of(node):
    """The node's attached blob store, or a fresh in-memory one on first use. A
    daemon injects a filesystem or S3 store (`node.blobs = open_blobs(...)`); a
    bare node in a unit test gets memory, so `send`/`save` work with no setup."""
    b = getattr(node, "blobs", None)
    if b is None: b = node.blobs = MemBlobStore()
    return b
