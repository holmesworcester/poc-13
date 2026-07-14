# Kernel cleanup findings

> **Historical dialect:** the findings and snippets below describe the v1
> Need/Offer model as it existed during this audit. The subsequent v2 atom
> simplification replaced `(kind, effect, role, ...)` with the closed
> `(relationship, name, ...)` sum `Provide | Gather | Require | SuppressIf`.
> See [`../DESIGN.md`](../DESIGN.md) for the current design.

## Relationship follow-up (2026-07-14)

The four relationships now share one `Atom` shape. Gather, Require, and
SuppressIf use the same exhaustive resident-and-store match acquisition;
settlement alone differs. The wire header is now `(relationship, target-tag)`,
the SQLite relation stores `relationship` and `name`, and the fact identity
domain is `tinyp2p.fact` — unversioned, because a proof of concept deletes stale
stores rather than migrating them.

The descriptor's `file_encoding` atom went with it. Its only value was
`clear-v1`, `content.file.check` pinned that constant, and the `content.file_slice`
projector then re-tested it against a descriptor that could not have been
admitted holding anything else — a dead check behind a Require that gated on a
fact its five sibling Requires already gated on. Bao commits to whatever bytes a
slice carries, so a future sealed-payload family needs no tag to interpret them.

## Applied (2026-07-05)

Landed as four commits after this survey (kernel.py 525 → 506 lines; two whole
parallel structures — the intake overlay and the leafset — deleted):

- **Items 1, 2, 3, 6, 8, 9** — one id-stable refactor commit: intake overlay
  gone (admit appends straight to `rows`), `leafset` folded into the Skeleton,
  `_present_now`/`_present_shipped` merged onto `_present`, `decode` via
  `unframe`, `pull` N+1 folded into a JOIN, window packing via `struct`.
- **Item 4** — reserved-role invariant enforced at `dec_atom`; the two `_step`
  gating guards dropped; focused test added.
- **Item 7** — atom codec rewritten as one frame sequence (flips every fact id,
  done alone pre-freeze). `test_sigs`' layout-coupled tamper made
  layout-independent.

Deferred, with reasons: **item 5** is subsumed by item 7. **Item 10** kept —
the `test_sql_pull_mirrors_covers` mirror documents the coverage relation well.
**Items 11, 12** deferred to the residency/sync split, which reshapes that
kernel↔runtime↔tinyd boundary anyway. **Items 13, 14** are boundary rules
(sync policy stays out of runtime; frame crypto stays a daemon callback) —
respected, nothing to change.

---

Read-only survey of `kernel.py` (524 lines), 2026-07-05. Ranked by payoff.
TinyP2P is pre-freeze, so format-changing items are in scope (fact ids may
change; DESIGN.md's "version-free forever" line applies from freeze, not now).
Nothing here has been applied. Estimated total: 50–70 lines off the kernel and
two whole parallel structures deleted, with items 4 and 7 the only ones that
change observable behavior (7 changes fact ids; 4 rejects facts that currently
sneak past the reserved-role rule).

## Engine (Node)

### 1. Delete the `intake` overlay (~12 lines)

`admit` appends new rows to `self.intake`; `_bucket` transparently chains
`rows ∪ intake`; `turn()` flushes intake into rows with its own comment saying
the flush "changes no result". Nothing inside or outside the kernel
distinguishes the two tables (grep confirms: no users of `intake` or `_bucket`
outside `kernel.py`). If `admit` appends straight to `self.rows`:

- `intake` dies,
- `_bucket` dies (callers use `self.rows.get(k, ())` directly),
- the flush loop at the end of `turn()` dies,
- Reap's cleanup in `_promote` scrubs one table instead of two.

Verify with the full test suite; if something does depend on the overlay it
will show as an ordering difference in `derived()` comparisons
(test_invites, test_skeleton, bench both assert bit-identical derived state).

### 2. Delete `leafset` — it duplicates `Skeleton.h` (~8 lines)

`self.leafset` maps `(ts, fid) -> leaf hash`; `self.tree.h` maps
`ts8be + fid -> the same hash`. The keys are bijective and `_leafset_update`
maintains both in lockstep. Keep the Skeleton as the single reconciliation
set:

- derive `old` in `_leafset_update` from `self.tree.h.get(kb)`,
- maintain `leaf_xor` off the same insert/remove,
- delete `self.leafset`.

External users: `leaf_xor` is read by `bin/tinyd.py` and `tests/test_sync.py` —
keep it. `leafset` itself is only read by `test_sync.py::leaves()`
(`set(n.leafset)`), which can read `tree` keys instead (or keep a one-line
property that adapts `tree.h` keys back to `(ts, fid)` tuples).

### 3. Merge `_present_now` / `_present_shipped` (~6 lines)

Both write transient rows into one clean-twin slot and wake each offer. One
helper covers both:

```python
def _present(self, role, scope, rows):
    self.clean[(role, scope)] = rows
    for _, _, off in rows: self._wake(off)
```

`_present_now` and `_present_shipped` become one-line row builders (or inline
into `turn`).

### 4. Enforce the reserved-role invariant at decode; drop the `_step` guards

The docs (kernel.py:149–153) say reserved NUL-prefixed roles are always WATCH
and can never be family-authored, but `dec_atom` doesn't enforce it. Today a
fact carrying `REQUIRE` on `b"\x00summary"` decodes fine, dodges both gating
checks in `_step` (they skip `RESERVED` roles), and still receives engine
answers in ctx; a NUL-role OFFER decodes fine too. One check in `dec_atom`:

```python
if a.role[:1] == b"\x00" and (a.kind, a.effect) != (NEED, WATCH):
    raise ValueError("reserved role")
```

closes the gap and makes both `n.role not in RESERVED` guards in `_step`
deletable — the invariant is checked once at the boundary instead of
re-checked (incompletely) at use. Behavior change: facts violating the
documented rule become inert misses instead of half-working.

The later graph-provenance work adds one narrow exception in the v2 grammar:
`remote`, `bare`, and `connection` may be `SuppressIf`, always at
`origin@SELF`; `connection` may also be Gathered there. All other reserved
names remain Gather-only, and reserved Provides remain impossible to decode.

## dec_atom / the codec

### 5. Let the re-encode check do the parsing work (~4 lines)

`dec_atom` ends with `enc_atom(a) != b -> reject`, which is already the whole
canonicality authority. So:

- `if i != len(b)` is redundant — trailing junk re-encodes shorter and fails
  the equality check anyway.
- The three-way target branch collapses to table-driven:

```python
tt = b[i]; i += 1
parts = []
for _ in range((1, 0, 2)[tt]): p, i = _rd(b, i); parts.append(p)
tgt = (tt, *parts)
```

Parse leniently, validate by re-encoding. (Superseded by item 7 if taken.)

### 6. `decode()` should use `unframe` (~3 lines)

`decode` hand-rolls exactly the loop `unframe` exists for:

```python
def decode(b):
    tag, *encs = unframe(b)   # ValueError on empty/truncated as before
    if any(x >= y for x, y in zip(encs, encs[1:])): raise ValueError("unsorted/dup")
    return Fact(tag, tuple(dec_atom(e) for e in encs))
```

(Guard the empty case: `unframe(b"")` returns `[]`, so the unpack raises —
acceptable, `admit` catches Exception; or add an explicit check.)

### 7. RECOMMENDED (pre-freeze): one byte discipline — atom as a frame sequence (~8 more lines)

The atom encoding currently mixes two disciplines: length-framing AND an
ad-hoc layout of raw tag bytes and a value-presence flag. Encode the whole
atom as one frame sequence instead:

```python
def enc_atom(a):
    return frame(bytes([a.kind, a.effect, a.target[0]]), a.role, a.scope,
                 *a.target[1:], *([] if a.value is None else [a.value]))

def dec_atom(b):
    hdr, role, scope, *rest = unframe(b)
    kind, eff, tt = hdr
    n = (1, 0, 2)[tt]                      # target part count; IndexError on bad tt is fine
    a = Atom(kind, role, scope, (tt, *rest[:n]),
             rest[n] if len(rest) > n else None, eff)
    if enc_atom(a) != b: raise ValueError("non-canonical atom")
    # ... tag-range checks (and item 4's reserved-role check) ...
    return a
```

- `dec_atom` drops from ~15 lines to ~8 and the codec has exactly one byte
  discipline (frames all the way down; `frame`/`unframe` become the codec).
- Injectivity holds: `value=b""` is one empty tail frame vs `None` = no frame;
  extra/misplaced frames fail the re-encode check.
- Cost: **every fact id changes.** Pre-freeze this is fine; do it before any
  durable store or peer matters, and in one commit so no mixed-id state exists.

## Store

### 8. `pull()` is an N+1 query (~4 lines)

The result loop runs a `SELECT bytes` plus a hot-INSERT per fid. Fold the
bytes fetch into the main query and batch the hot marks:

```python
rows = self.db.execute(sql.replace("ts, fid FROM atoms",
    "ts, atoms.fid, bytes FROM atoms JOIN facts ON facts.fid = atoms.fid"),
    args).fetchall()
self.db.executemany("INSERT OR IGNORE INTO hot VALUES(?)", [(r[1],) for r in rows])
return [r[2] for r in rows]
```

(Written as a real SQL string, not the `.replace` sketch — that's just to show
the shape. `SELECT DISTINCT` semantics preserved since bytes is functionally
dependent on fid.)

### 9. Hand-rolled byte packing is `struct` (~5 lines)

`window` / `_window` / `_t8` are `struct` one-liners:

```python
import struct
window  = lambda lo=0, hi=2**64-1, budget=2**32-1, order=0: struct.pack("<QQIB", lo, hi, budget, order)
_window = lambda v: struct.unpack("<QQIB", v)
WINDOW_LEN = struct.calcsize("<QQIB")   # 21
_t8     = lambda t: struct.pack(">Q", t)
```

### 10. Optional / judgment call: delete the SQL mirror of `covers`

The coverage relation exists twice: `covers()` (the spec) and the `pull()`
WHERE clause (the implementation), held together by a mirror test. Selecting
on `(role, scope)` plus the ts window only, then filtering candidates with
`covers()` in Python, gives one source of truth and deletes the trickiest SQL
in the file. Cost: more candidate rows scanned per pull (all offers at the
role+scope key, not just target-covering ones) — irrelevant at poc scale, and
`match_ix(role, scope, lo, ts)` still prunes most of it. Counter-argument:
the mirror test documents the relation well. Decide by taste.

## Kernel / runtime / tinyd overlap

### 11. Make host signals an explicit runtime responsibility

`Node.turn(now=None, shipped=(), bound=64)` currently knows about two host
signals: the OS clock and the wire flush report. That makes the kernel's drain
primitive overlap with `bin/runtime.py`'s `cycle()`, whose job is already
"present host inputs, then step the engine".

After item 3's shared `_present(...)` helper, consider splitting the API:

```python
node.present(rows)       # or present_now(now_ms) / present_shipped(fids)
node.turn(bound=BOUND)   # engine drain only
```

Keep `now_need`, `shipped_need`, `summary_need`, and `resident_need` in the
kernel if they are part of the fact language. Move the host-cycle sequencing
into `runtime.cycle()`. That gives the boundary one clear shape:

- kernel: canonical bytes, admission, matching, derived state, engine stepping;
- runtime: one socket-free host cycle, including transient host feedback;
- tinyd: sockets, select, request/response I/O, and callbacks.

Tests: `tests/test_clock.py` should still prove time does not persist across
replay, and `tests/test_runtime.py` should own the shipped/reap sequencing.

### 12. Move `to_ship` pruning out of `tinyd.py`

`bin/tinyd.py` currently performs runtime bookkeeping around lines 153-178:

```python
cycle(node, inbox, now_ms(), to_ship, BOUND)
to_ship &= {o for o, _, _ in outbox(node)}
fired = pump(..., to_ship)
to_ship |= fired
```

That is not socket policy; it is the outbox lifecycle. Give `bin/runtime.py` a
small helper that owns "present previously fired owners, prune owners that
reaped, pump new rows, return next pending shipped set". Then `tinyd.py` can stay
closer to:

```python
cycle(...)
flush(...)
to_ship = pump_cycle(...)
```

The important contract stays the same: `pump()` fires owners best-effort when
the daemon accepts the bytes for delivery; `shipped@wire` is a local flush report,
not a remote ack. Add or adjust `tests/test_runtime.py` cases for burn-down,
no-route parking, and backpressure/refused delivery.

### 13. Keep sync policy out of `runtime.py`

The `leaf_xor` guard in `tinyd.py` is sync policy:

```python
if node.leaf_xor != synced.get(cid):
    sync.open_round(node, cid, lo)
```

Do not move that into runtime. Either leave it in `tinyd.py` as daemon policy, or
eventually make cadence/sync facts own it. `runtime.py` should remain the generic
socket-free host turn: admit inbox, present transient feedback, expose/pump
validated outbox rows.

### 14. Keep frame crypto as daemon callbacks, not kernel state

The current `pump()` callback shape is good: runtime resolves validated
send/ship rows into inner fact bytes, while `tinyd.py` supplies `route` and
`deliver` callbacks that query connection/frame families for routing and sealing.
Do not push socket buffers, frame packing, or AEAD wrappers into the kernel.
That would reduce apparent daemon LOC at the cost of making the engine know
transport details.

## Not worth doing

- `memo` verdict strings -> enum: strings are more readable in test output.
- `owned` -> derive from `clean`: would trade a small dict for scans of every
  clean bucket per promote.
- `_deps.clear()` on every admit: coarse but O(1); lazy rebuild is fine at
  poc scale.
- `slices` rebuild-by-comprehension in `_promote`: O(slices) per promote,
  fine at poc scale, and the LWW rule reads clearly as written.

## Suggested order

1. Land items 1-3 and 5-6, 8-9 as pure refactors. Keep the full suite green
   throughout; fact ids stay stable.
2. Land item 4 with a focused reserved-role test. This is a small behavior
   change: malformed reserved-role facts become inert misses.
3. Land items 11-12 with `tests/test_runtime.py` covering shipped/reap
   burn-down, no-route parking, and refused delivery. `tinyd.py` should lose
   lifecycle bookkeeping, not socket behavior.
4. Treat item 13 as a boundary rule while editing: sync policy stays in
   sync/cadence or `tinyd.py`, not in runtime.
5. Do item 7 last and alone, since it flips every fact id. Re-run the full
   suite plus bench's replay-divergence assertions after it.
6. Commit the completed work on this same worktree branch before handoff or
   review.
