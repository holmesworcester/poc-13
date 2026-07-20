# Cloud Deployment: Store Portability

Status: **mostly notes / design sketch.** The SQLite→ordered-KV reshape below is
still a sketch. The **slices-out-of-the-fact-graph, into a content-addressed blob
store** thread is now **implemented** (see the box just below). Cautious — this
records options and their tradeoffs, not commitments. Companion to
`docs/selective-hydration.md` (the memory work these ideas assume) and a separate
off-repo cloud-cost analysis.

## Implemented: slices are blobs (`blobstore.py`, 2026-07)

The content-addressed blob store landed as the seam this doc sketched:

- `blobstore.py` — one interface (`has/get/put/delete`, `put(data)->cid` with
  `cid = H(data)`), three backends: `MemBlobStore` (a bare node), `FSBlobStore`
  (sharded files, atomic write, verify-on-read), `S3BlobStore` (R2/S3 via boto3,
  `endpoint_url` for R2). `open_blobs(spec)` picks by `s3://…` vs path;
  `blobs_of(node)` attaches one. Store is outside the trust boundary: `get`
  re-hashes and returns a miss on mismatch.
- `content.file_slice` now names `cid = H(proof)` (32 B) instead of carrying the
  ~205 KiB proof. The naming fact still syncs (tiny leaf) and carries the message
  death key; the proof rides a separate fetch, out of the treap/atom-relation/cache.
- `content.file`: `send` puts each proof as a blob; `save`/`files` fetch by cid
  and Bao-verify against the root — a slice counts as *received* only when its
  blob is present **and** verifies (the check moved out of the projector into
  `file._received`). `file.wanted(node, blobs)` = advertised ∧ ¬present.
- `bin/tinyd.py`: a blob leg over the sealed connection (`BLOBREQ`/`BLOBRESP`,
  `--blobs <dir|s3://…>`, default `<db>.blobs/`). Receiver-side window is the only
  flow control; a shared R2 bucket makes the leg a no-op (everything already
  present). Bytes never ride the sync frames.
- **Encryption (done).** The payload is encrypted before Bao under the parent
  message's `file_secret`, so the root/proofs/cids all commit to ciphertext and
  the blob store holds only opaque bytes. The cipher is a per-slice BLAKE3-XOF
  keystream (`crypto.stream_xor`) — equal length (Bao geometry preserved), keyed
  per index (no nonce/seek); integrity rides the signed Bao root, not a per-slice
  tag. The key lives in the message fact (`content.message.file_secret`), derived
  from the author's signer secret so resend is idempotent, so message deletion
  shreds it and a future message-encryption layer covers the file key for free.
  `save` reads the key, Bao-verifies each ciphertext slice, XORs back to plaintext.
- **Blob GC (done).** `content.file.gc` total-hydrates and deletes every stored
  cid no live slice names (the blob analog of `VACUUM`); `blobstore` backends grow
  a `cids()` enumerator. Lazy and non-security-critical — deletion already shredded
  the key, so a lingering ciphertext blob is already unreadable.
- Tests: `tests/test_blobstore.py` (Mem/FS/S3 incl. a real-boto3+moto path, `cids()`,
  and an offline fake), plus the reshaped `test_files.py` (ciphertext + shred + GC
  cases) / `test_file_pair.py`.

**Still future:** encrypting the *message body* itself (the file key already rides
it, so that step encrypts attachments for free); wiring GC into the daemon on a
schedule rather than an operator verb.

Goal: one engine, two deployment contexts — local client and serverless cloud —
with the smallest possible surface difference between them. The lever is the
storage seam. If the durable store is expressed as an **ordered key-value**
interface, the same engine runs over SQLite locally and a cloud KV (DynamoDB /
Cosmos / Firestore, or a Cloudflare Durable-Object SQLite) with only the adapter
changing.

## Possible plan: reshape the SQLite store as an ordered KV

Today `Store` (`kernel.py`) is a relational atoms table read through a coverage
`WHERE` clause. The cloud KVs are partition-key + sort-key ordered stores. They
meet if the local store is modeled the same way:

- **Local:** SQLite `WITHOUT ROWID` tables with `PRIMARY KEY (pk, sk)` — a
  clustered, ordered `(pk, sk)` store. `WHERE pk=? AND sk BETWEEN ? AND ?` is
  exactly a DynamoDB `Query`; `WHERE pk=? AND sk=?` is `GetItem`.
- **Cloud:** DynamoDB (or equivalent) with the *same key encoding*.

Three tables, identical in both contexts:

- **fact spine:** `fid → canonical bytes` (point get). Store the bytes directly
  and re-hash against `fid` on read → keeps "wrong bytes are a miss, never a wrong
  fact" (`kernel.py:299`) without the current regroup/re-encode-from-atom-rows
  step.
- **match index (derived):** `pk=(name‖scope), sk=(lo‖hi‖fid) → fid` — the
  `providers` query (`kernel.py:363`) as a sort-key range scan.
- **sync leaf index (derived):** `pk=workspace, sk=(ts‖fid) → leaf_hash` — the
  reconciliation set. This *is* selective-hydration's **13b** leaf table, now
  just one of the three tables.

`Store` narrows to ~4 ordered-KV methods: `get(pk,sk)`, `query(pk, sk_range)`,
`transact_put(items)`, `delete(pk,sk)`. Engine + fact families are unchanged
across backends; only the adapter differs.

**Known leak (the one non-KV case).** The coverage predicate's
range-Provide-covers-exact-consumer arm (`_COV`, `kernel.py:303`) is `sk.lo ≤ p`
scanned then filtered on `hi ≥ p` — not a clean contiguous range. It works on both
backends (SQLite via `_COV`; DynamoDB via `Query` + `FilterExpression`) but reads
more than a point/range lookup. Most Provides are exact (pure point lookups);
range-Provides are rare (bulk demand / windowed sync). Accept it, or interval-
encode the sort key if it ever bites.

Depends on: nothing hard. Pairs with selective-hydration (the leaf index is 13b).
Transactions: SQLite's single-writer file locally; in the cloud, a KV transaction
plus a per-workspace advisory lock (or serializable isolation) — the turn's
atomicity and the single-writer invariant.

## Related open threads (cautious — not yet worked through)

- **Slices out of the fact graph, into a content-addressed blob store.** Since the
  cloud forces slices out-of-line (object storage, per-object deletion), do the
  same locally instead of carrying two slice code paths: a `BlobStore` seam
  (`get/put/delete/has` by `cid`), **filesystem** locally, **R2** in the cloud.
  The slice fact shrinks to `(index, cid)` where `cid = H(encoded_slice)`; the
  ~205 KB Bao-encoded slice is a blob keyed by `cid`, fetched on request and
  Bao-verified against the signed descriptor root. Bonus: slices never enter the
  decoded-fact cache, which directly removes selective-hydration's "256 KiB slice
  ≈ 512 KiB resident" problem for the slice case (arguably simpler than evicting
  them).
  - **Auth = encryption, not the hash.** Store **ciphertext**; keep the per-blob
    key in the deletable fact. The cid is integrity (Bao proof + content address),
    NOT authorization, and it is not secret (it rides the synced fact graph). With
    ciphertext the blob store needs no read auth (a public R2 bucket serving opaque
    bytes is safe and keeps the direct zero-egress fetch); R2 write-auth is a
    scoped token; p2p reads ride the already-authenticated sealed connection. This
    is Signal's model (encrypt client-side, key delivered E2E, dumb CDN holds
    ciphertext) — NOT hash-only-auth-for-plaintext. BLAKE3 is unguessable, but a
    cid of *plaintext* is *computable* by anyone who knows the content (confirmation
    attack); a cid of *ciphertext* is genuinely opaque. So encrypt, then hash-only
    identification is safe.
  - **Deletion = cryptographic shred + lazy GC.** Key in the deletable fact +
    atomic suppression-purge ⇒ deleting the message shreds the key immediately, so
    the ciphertext blob is inaccessible at once, wherever it sits. GC (reference-
    counted, unlink local / R2 delete) is then pure storage reclamation, best-
    effort/eventual, NOT security-critical — which dissolves the cross-store
    non-atomic-deletion / forward-secrecy worry. Needs per-blob keys stored only in
    the deletable fact.
  - **Multisource fetch = discover/request/receive/suppress (poc-7 pattern).** No
    managed want-list. The want is the *derived* predicate `advertised(cid) ∧
    ¬present(cid)` — `advertised` from the synced descriptor/slice-record facts,
    `present` = `BlobStore.has(cid)`. The request is the projected consequence of
    the un-suppressed want; a slice arriving from ANY source (peer or R2) is
    `put(cid)`, which flips `present` and suppresses the want → outstanding requests
    to other sources cancel (poc-7's "received ids suppress outstanding requests" —
    the bytes are the suppressor). Only imperative residue is the byte transport:
    the current want set implies which GETs are open; flipped `present` opens/aborts
    them. Same mechanism blends p2p offload with R2 fallback; blob store stays dumb.
    **Flow control is receiver-side fetch concurrency ONLY.** Do NOT gate discovery
    / expand a window on backpressure: discovery is cheap (fingerprints + tiny
    cids), the fetch is the expensive part, and gating it forces the responder to
    become window-aware (bilateral-floor coordination — historically buggy, and it
    breaks the stateless-responder principle). Discover the full diff ("download
    everything we need"), hold the cheap want set, drain it through a bounded fetch
    window; sender stays a dumb mirror. Windowing is for *memory residency* (13a),
    never for download pacing — keep them separate.

- **Cloudflare Workers + R2 + Durable-Object SQLite viability.** Composes for
  small/medium workspaces given the selective-hydration memory bound: slices in R2
  (out of the DO entirely), fact graph in DO SQLite (the reshaped ordered KV),
  bounded treap in DO memory, O(1) boot from the leaf-table tail. Blockers: 128 MB
  per-isolate cap **and memory wiped on hibernation** (→ rebuild-on-wake, cheap
  with 13b + a bounded shard), the DO-SQLite-API storage rewrite, and a Rust
  reimplementation (bao/blake3 compile to `wasm32`). Note: **R2's zero-egress is
  available from any compute host** (S3-compatible, egress free everywhere), so
  running the engine *on* CF is warranted only for edge / DO-singleton reasons,
  not to get R2.

- **Age-sharding large workspaces across workers.** For a workspace too large for
  one 128 MB DO, partition the fact set by `ts` range across DOs (hot = recent,
  frequently connected; cold = older, rarely woken, ~$0 idle). This maps natively
  to poc-13's ts-windowed sync — the floor/window (`docs/anchor-sync.md`) *is* the
  shard boundary, and RBSR already partitions by ts range (the treap key is
  `ts‖fid`). Each shard holds a bounded treap. Wrinkle: cross-shard dependencies
  (a recent fact `Require`-ing old auth) — replicate the small shared auth graph
  into every shard so each validates locally. Untested.
