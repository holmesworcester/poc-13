# Daemon / sync / connection transition — implementation plan

> **Superseded in part (branch fault-in):** the store hook, hydration windows,
> `missing_needs`, `Store.pull/all`, `Node.replay`, and `runtime.load` no longer
> exist. Matching faults from the persisted atom relation at step time, and boot
> is one total `store.hydrate` fact. References below describe main as it was.

Executable plan for reshaping the daemon, sync, and connection model into the declarative
form we settled on. Optimising for **readability, simplicity, low LOC**. This doc is the
source of truth: current-state inventory, concrete code for every change, per-milestone
file edits and tests, then the design rationale ("why") at the end.

Legend: `[C]` = worked out and concrete, safe to type; `[V]` = verify against the code
while implementing (a mechanic I reasoned through but haven't run).

---

## 1. Current-state inventory (grounded)

**kernel.py** (~516 lines, read in full):
- `Skeleton` (237-330): radix Merkle trie over 40-byte `(ts‖fid)` keys. `label(prefix)`
  (290) = my fingerprint for a range; `emit(prefix, floor)` (303) = claim tuples
  (`("fp",child,label)` per child, or `("lst",pfx)`+`("has",kb)` at a leaf), floor-clipped.
  `gather`, gather/insert/remove all O(depth).
- `Node`: `admit` (358, idempotent by fid, runs family `check`, extract→durable, clears
  `deps`), `turn(now,shipped,bound)` (427), `_step` (441), `_promote` (470),
  `_leafset_update` (457, leaf iff `durable ∧ shareable ∧ memo∈{Valid,Suppressed}`, hash =
  `H(frame(fid, ts, H(bytes)))`, keeps `leafset`+`leaf_xor`+`tree`), `_present_now` (410),
  `_present_shipped` (419), `valid_offers` (385, clean twin), `offers_for` (379, asserted),
  `validated_deps` (389, uses `offers_for` = **asserted** REQUIRE+SUPPRESS edges),
  `missing_needs` (398), `watched` (502).
- `Store` (174): sqlite `facts(fid,bytes)` + derived `atoms` index + TEMP `hot`; `pull`
  (208) answers a need from the index, windowed for WATCH (214), exhaustive for gating.
  WAL + busy_timeout (186-188).
- Reserved needs today: `now_need`/`now_of` (124-126), `shipped_need` (134). Presented via
  `_present_*` writing one clean-twin slot and waking `needs_for`.

**facts/sync/__init__.py**: `SCOPE = Router({b"compare":compare, b"reply":reply}, depth=1)`.
**facts/sync/compare.py** (~120): the current bundled compare — `initiate`/`answer_of`/
`respond` are COMMANDS the daemon calls (reads `node.tree` directly); `project` is inert;
`_wants` = `missing_needs` as `need` atoms; `leaves`/`closure`/`myfp` queries.
**facts/sync/reply.py**: volatile courier — `answer(node,cid,dest,t,lo)` calls
`compare.answer_of`, admits a `reply` fact that offers `send`/`ship@outbox`, Reaps on
shipped. `open_round`.

**bin/cond.py** (~243): single-threaded select loop. `serve` (45, CLI verb inline),
`_admit_bare` (201), `_admit_frame` (206, peeks `frame_cid`, `conn.route(cid)→secret`,
`frames.open_frame`, admits inners, **calls `sreply.answer(node,fid,cid,...)` for
compares** — the sync reaction we delete), `_pump_data` (220, reads `watched(send/ship,
outbox)`, groups by owner, `conn.route`, `frames.pack`+`seal`, `enqueue` into `p["out"]`
up to `OUTCAP`, adds owner to `to_ship`). Cadence markers `redial/compared/active/synced`,
`CADENCE`, `QUIET` (108, 171-186). `next(...)`/select timeout fixed `0.05`.
**bin/con.py**: `load`/`flush`; `proxy` (daemon mode); `main` — **daemonless
crash-and-demand branch** at 40-49 (open Store cold, run verb, flush) when no `.sock`.
**facts/outbox/send.py**: the one-shot courier pattern to copy — `send(dest,payload,t)`
offers `send@outbox@Exact(dest)`, `shipped_need`, `project` Reaps on `by(ctx,shipped)`.
**facts/connection/frame.py**: wire-only queries `pack/seal/open_frame/frame_cid/unframe`,
inert project, no commands. `frames.seal(blob,cid,secret,nonce)`.

---

## 2. Kernel changes (concrete)

Five small, additive changes. Everything else is families.

### 2.1 Rename `validated_deps` → `deps` `[C]`

Mechanical. `self.deps` the memo already exists (350); the method `validated_deps` (389)
and `missing_needs` (403) and `compare.closure` reference it. Rename the *method* to
`deps(self, fid)`; update `missing_needs` and `compare.closure`. Add a docstring: "direct
REQUIRE+SUPPRESS edge owners from `offers_for` — **structural/asserted**, not
validity-gated; validity is decided in `_step`." Add a transitive helper on Node:

```python
def closure(self, fid, out=None):          # transitive deps (requires + suppressors), incl fid
    out = out or set()
    if fid in out: return out
    out.add(fid)
    for d in self.deps(fid): self.closure(d, out)
    return out
```
(moves `compare.closure` into the kernel so the summary affordance can use it.) `[C]`

### 2.2 Engine-answered-need dispatch in `_step` `[C]`

Reserved needs are answered from the engine's indexes and injected into ctx, exactly the
way `store.pull` already answers needs from the durable index. Add one dispatcher and call
it where ctx is built (kernel.py:453):

```python
SUM_ROLE, RES_ROLE = b"\x00summary", b"\x00resident"   # reserved, cannot collide with families

def _answer(self, n):                      # engine-answered reserved needs; else the clean twin
    if n.role == SUM_ROLE: return self._summary_rows(n)
    if n.role == RES_ROLE: return self._resident_rows(n)
    return self.valid_offers(n)
# in _step, replace the ctx line:
ctx = {n: self._answer(n) for n in ns if n.effect in (REQUIRE, WATCH)}
```

Rows are shaped like clean-twin rows `(owner, ts, atom)` so `by(ctx, role)` works.
Reserved needs are WATCH (never gate), so the SUPPRESS/REQUIRE precedence above (448-451)
is unaffected — but guard those two lines to skip reserved roles so a `summary` need is
never treated as a gate: `... for n in ns if n.effect==SUPPRESS and n.role not in RESERVED`.
`[V]` (check the precedence lines don't accidentally gate on reserved needs).

### 2.3 `summary@prefix` `[C]/[V]`

Answers a `summary` need with my label for the range, my children (to descend) or my
leaves + their closure-ids (to advertise). `n = Atom(NEED, SUM_ROLE, SC, Exact(prefix),
value=floor_key, WATCH)`.

```python
CLOSURE_CAP = 4096    # generous safety valve on UNIQUE closure ids per summary (>> a leaf list)

def _summary_rows(self, n):
    pfx = n.target[1]; floor = n.value or b""
    R = lambda a: (_SUM, 0, a)                      # _SUM: a sentinel owner, like _NOW
    rows = [R(Atom(OFFER, b"fp", SC, Exact(pfx), self.tree.label(pfx)))]   # my label for the range
    seen = set()                                    # ONE visited-set across all leaves → union closure, deduped
    for c in self.tree.emit(pfx, floor):
        if c[0] == "fp":
            rows.append(R(Atom(OFFER, b"fp", SC, Exact(c[1]), c[2])))      # a child fingerprint
        elif c[0] == "has":
            self.closure(c[1][8:], seen)            # accumulate; the shared spine is added once, not per leaf
    for d in list(seen)[:CLOSURE_CAP]:              # leaves + their deduped deps; each id once
        if d in self.facts:
            rows.append(R(Atom(OFFER, b"has", SC, Exact(_kb(ts_of(self.facts[d]), d)))))
    return rows
```

- **Cross-leaf dedup is here, not just on the wire.** `closure(fid, seen)` (§2.1) shares
  one `seen` set across every leaf, so `seen` is the range's *deduped union closure* (spine
  once). The leaves are in `seen` too (closure includes the fid), so they're advertised in
  the same loop — no separate leaf emission. The outbox stays a second dedup layer for
  ids repeated across *different* summaries. `[C]`
- **The cap is generous** (`>> |leaves|`) — a safety valve, not a normal path; after dedup
  `seen` is the range's unique reachable set, which at a small leaf node is small. **On
  overflow** (a pathological deep/wide closure), the un-advertised deps are covered by the
  parked-leaf `missing_needs` backstop (§4.5) — the one place the rare inference path still
  fires. Don't hard-truncate-and-lose without that backstop, or a leaf could land Valid
  (its fingerprint matches once the leaf itself arrives) while a below-window dep never
  gets pulled. `[V]`
- SC is a fixed sync scope (`b"sync"`); rows are read only by the compare projector, so
  scope is cosmetic. `emit`'s `("lst", pfx)` marker is ignored; `("has", kb)` carries a
  leaf. `[V]`

### 2.4 `resident@id` `[C]`

```python
def _resident_rows(self, n):
    fid = n.target[1]
    return [(_RES, 0, Atom(OFFER, b"resident", b"sync", Exact(fid)))] if fid in self.durable else []
```
A `have` handler declares `Atom(NEED, RES_ROLE, b"sync", Exact(id), WATCH)`; empty ctx ⇒ I
lack it ⇒ emit `need`. `[C]`

---

## 3. Runtime: `cycle` + `pump` (concrete)

New tiny module `bin/runtime.py`, importable by tests and the daemon.

```python
# runtime.py  [C except pump's socket-fill detail V]
def cycle(node, inbox, now_ms, shipped):        # in -> turn -> quiescence
    for src, b in inbox: node.admit(b)          # src tag currently unused; kept for priority later
    while node.frontier: node.turn(now_ms, shipped, BOUND); shipped = ()
    return node

def outbox(node):                               # OUT is model state, not a return value of cycle
    return node.watched(b"send", b"outbox") + node.watched(b"ship", b"outbox")

def pump(node, route, fill):                    # returns fired owner-fids; route=conn.route, fill=socket writer
    fired = set(); rows = {}
    for o, _, a in outbox(node): rows.setdefault(o, []).append(a)
    for o, atoms in rows.items():
        cid = atoms[0].target[1]; r = route(node, cid)
        if not r: continue                      # no session yet: offer stands (park)
        addr, secret = r
        inners = [a.value if a.role == b"send" else None for a in atoms]  # send=inline; ship resolved below
        inners = _resolve(node, atoms)          # send bytes + ship ids -> durable bytes
        for blob in frames.pack(_dedup(inners)):
            if fill(addr, secret and _seal(blob, cid, secret) or blob):   # seal iff secret, else bare
                fired.add(o)
    return fired                                # -> next cycle's `shipped`
```

- `pump` is the M2 shape: **pull-to-fill**, no `OUTCAP` backlog. `fill(addr, bytes)` writes
  as much as the socket takes; **owners fire best-effort on enqueue to the socket buffer**,
  *not* on confirmed drain (§7.4 — the outbound path tolerates loss up to admit). The
  partial tail stays in the daemon's per-link buffer for *efficiency* (finish the write
  later), independent of the now-reaped owner; a socket death loses it and sync re-emits.
  `[C]`
- `_dedup(inners)` collapses byte-identical frames (the closure-id `have` flood). `[C]`
- `seal iff secret` unifies bare handshake and sealed data through one door (M3). `[C]`

Daemon loop becomes: gather inbox (open frames via `frames.open_frame` — still a query) →
`cycle` → `pump` → feed `fired` as next `shipped` → schedule via `wake@`. `[C]`

---

## 4. Sync families (full schemas)

New `facts/sync/{compare,have,need,cadence}.py`; delete the old `compare.answer_of/respond`
and `reply.py`. **Routing key = `cid`** (the connection-fact id, symmetric — both sides
admit the same connection bytes, so both call it `cid`). Each frame carries `cid`; each
handler reads it and targets its response `send`/`ship` offers at `Exact(cid)`; the pump
routes by `conn.route(cid)`. **This is what deletes the daemon's `sreply.answer` reaction.**

### 4.1 `compare` `[C/V]`

```python
TAG = b"sync.compare"; SC = b"sync"
def compare(cid, pfx, floor, fp):
    return fact(TAG, ts_atom(0, SC),
        Atom(OFFER, b"cid",  SC, Exact(cid)),
        Atom(OFFER, b"pfx",  SC, Exact(pfx), _t8(floor)),
        Atom(OFFER, b"peer", SC, Exact(pfx), fp),                     # sender's fingerprint; b"" for a bare root
        Atom(NEED,  SUM_ROLE, SC, Exact(pfx), _fkey(floor), WATCH),   # engine delivers my summary
        shipped_need)                                                # courier: reap when my sends flush
def extract(f): return False, False
def project(f, ctx, sl):
    if by(ctx, b"shipped"): return Out("Reap")
    cid  = _val(f, b"cid"); pfx = _tgt(f, b"pfx"); floor = _floorval(f); peer = _val(f, b"peer")
    S = by(ctx, SUM_ROLE)
    mine = next((a.value for _,_,a in S if a.role==b"fp" and a.target[1]==pfx), Skeleton.EMPTY)
    out  = []
    if peer and peer == mine:                                        # match → prune
        return Out()
    kids  = [(a.target[1], a.value) for _,_,a in S if a.role==b"fp" and a.target[1]!=pfx]
    haves = [a.target[1] for _,_,a in S if a.role==b"has"]           # leaves + closure ids
    if kids:                                                          # internal → descend
        for cp, lbl in kids:
            out.append(_send(cid, encode(compare(cid, cp, floor, lbl))))
    else:                                                             # leaf → advertise haves
        for kb in haves:
            out.append(_send(cid, encode(have(cid, kb[8:]))))         # have carries the fid
    return Out(offers=tuple(out))
```
- `_send(cid, bytes) = Atom(OFFER, b"send", b"outbox", Exact(cid), bytes)`.
- Descent is symmetric: each `compare` carries the sender's fp; the receiver checks vs its
  own label and emits *its* children. Converges at leaves where both dump `have`s. `[V]`
- A bare root (peer==b"") never matches, so it always emits my children/haves — the first
  real fingerprints. Cadence sends bare roots. `[C]`

### 4.2 `have` `[C]`

```python
TAG = b"sync.have"; SC = b"sync"
def have(cid, fid):
    return fact(TAG, ts_atom(0, SC),
        Atom(OFFER, b"cid", SC, Exact(cid)),
        Atom(OFFER, b"id",  SC, Exact(fid)),
        Atom(NEED,  RES_ROLE, SC, Exact(fid), WATCH),   # do I hold it?
        shipped_need)
def extract(f): return False, False
def project(f, ctx, sl):
    if by(ctx, b"shipped"): return Out("Reap")
    if by(ctx, RES_ROLE):   return Out("Reap")          # I already hold it: nothing to do, vanish
    cid = _val(f, b"cid"); fid = _tgt(f, b"id")
    return Out(offers=(_send(cid, encode(need(cid, fid))),))
```
Content-minimal (`cid`+`id` only) so duplicate advertisements are byte-identical → outbox
dedupes. `[C]`

### 4.3 `need` `[C]`

```python
TAG = b"sync.need"; SC = b"sync"
def need(cid, fid):
    return fact(TAG, ts_atom(0, SC),
        Atom(OFFER, b"cid", SC, Exact(cid)),
        Atom(OFFER, b"id",  SC, Exact(fid)),
        shipped_need)
def extract(f): return False, False
def project(f, ctx, sl):
    if by(ctx, b"shipped"): return Out("Reap")
    cid = _val(f, b"cid"); fid = _tgt(f, b"id")
    return Out(offers=(Atom(OFFER, b"ship", b"outbox", Exact(cid), frame(fid)),))
```
Ships one fact by id (the pump resolves id → durable bytes). Deps are *not* shipped here —
each was advertised as its own `have` and pulled as its own `need`. `[C]`

### 4.4 `cadence` `[C]` — see §6-of-rationale; volatile, per (cid, tier), `wake@` scheme.

Schema/handler already worked out (kept in the rationale section below). Emits a **bare
root** `compare(cid, root_pfx, floor, b"")` per period; no `active@cid` settle-guard;
optional fp-changed slice. Teardown via `SUPPRESS closed@cid`.

### 4.5 Deletions `[C]`

- `facts/sync/compare.py`: delete `initiate`, `answer_of`, `respond`, `_wants`, `_atoms`,
  the `need`-atom path, and the inert `project`. Keep `leaves`/`closure` only if still
  referenced (closure moves to kernel §2.1). The file becomes just the new `compare`
  family above.
- `facts/sync/reply.py`: **delete entirely** (couriering is now each frame's own `send`
  offer + `shipped_need`).
- `facts/sync/__init__.py`: `Router({b"compare":compare, b"have":have, b"need":need,
  b"cadence":cadence}, depth=1)`.
- `missing_needs` (kernel): keep the method (cheap, harmless), but it's no longer wired
  into sync. It may serve as a rare local backstop; not on the hot path.

---

## 5. Daemon: the new loop (concrete)

`bin/cond.py` `main` loop, replacing 78-195 + helpers:

```python
inbox = []
for src in read_sockets(reads):                 # each ready socket
    for kind, body in messages(src):
        if kind == BARE:   inbox.append((src, body))            # handshake fact: admit as-is
        elif kind == SEALED:
            r = conn.route(node, frames.frame_cid(body))
            blob = r and frames.open_frame(body, r[1])          # daemon opens (query), holds no policy
            for inner in (blob and frames.unframe(blob) or []): inbox.append((src, inner))
cycle(node, inbox, now_ms(), tuple(to_ship))
to_ship = pump(node, conn.route, fill_socket)                    # fired owners -> next shipped
# respond seam stays for the handshake only (connection fact -> ship its bytes); NO sync reaction
for rid in arrived_requests: ... conn.respond ... enqueue(BARE, _enc(node, cid))
select_timeout = next_wake(node, now_ms())                       # earliest wake@; replaces 0.05 poll
```

Deletions: `_admit_frame`'s `sreply.answer` call (206-218 collapses to "open + admit
inners"), `_pump_data` (replaced by `pump`), `OUTCAP` staging, `to_ship` as an ack set
(now just "fired last cycle"), `redial/compared/active/synced`, `CADENCE`, `QUIET`. The
handshake `respond` seam stays (it's connection, not sync). `[V]` (handshake still needs
the daemon to author the connection fact and ship its bytes — that's M3, not M6.)

---

## 6. Milestones (files · changes · tests)

Each leaves the suite green. Order: M1–M5 (in/out), M6 (sync), M7 (cadence).

**M1 — `runtime.py` seam.** New `bin/runtime.py` with `cycle`/`outbox`/`pump` (pump still
staging to `p["out"]` initially — behavior-preserving). Rewire `cond.py` to call them.
`tests/test_runtime.py`: build a `Node(ROOT)`, admit two `outbox.send` facts via `cycle`,
assert `outbox(node)` shows two `send` rows, `cycle(node, [], now, [fid1,fid2])`, assert
both reaped. *No sockets.* Files: `bin/runtime.py` (+), `bin/cond.py` (~). LOC ~neutral.

**M2 — offers-as-queue.** `pump` → pull-to-fill (delete `OUTCAP` staging + `p["out"]`
backlog, keep partial-write tail); `to_ship`=fired; add `_dedup`. `tests/test_runtime.py`:
+ burn-down (offers reap as fired) and a backpressure case (fill returns False → offer
stays, no crash). Files: `bin/runtime.py`, `bin/cond.py`. LOC −.

**M3 — unify OUT door.** `conn.respond` authors a volatile courier emitting
`send@outbox@Exact(addr)`; `pump` seals-iff-secret (bare when `route` has no secret).
Delete the bespoke `enqueue(BARE, _enc(...))` branch. `tests/test_handshake.py` (existing,
adapt): a handshake and a sync frame both leave via `pump`; handshake bare, sync sealed.
Files: `facts/connection/connection.py`, `bin/cond.py`. LOC −.

**M4 — drop daemonless.** `bin/con.py` `main`: if no `.sock`, `sys.exit("no daemon")` —
delete the Store/Node crash-and-demand branch (40-49). Drop `busy_timeout` reliance in
`kernel.Store` (keep WAL). Adapt any test that ran verbs daemonless to spin a daemon or use
`Node(ROOT)` directly. Files: `bin/con.py`, `kernel.py`. LOC −.

**M5 — document the boundary.** Headers in `cond.py` (two doors, authors-nothing-outbound,
crypto-as-queries), `frame.py` (why daemon-opened), `connection.py` (admit-in + ship-out).
Docs only.

**M6 — decomposed sync (the big one).**
- kernel: §2.1 rename + `closure`; §2.2 `_answer` dispatch; §2.3 `summary`; §2.4 `resident`.
- families: new `compare`/`have`/`need` (§4.1-4.3); delete `answer_of/respond/reply`;
  update `sync/__init__.py`.
- daemon: delete the `sreply.answer` reaction (§5).
- `tests/test_sync.py` (rewrite around the new families):
  - `test_equal_sets_zero_frames`: two equal nodes, a bare root → root fp matches → prune,
    no `have`/`need`/`ship`.
  - `test_one_fact_diff`: b lacks one leaf → converges; b ends with exactly that fact.
    Assert **O(depth)**: frame count ≤ ~depth·k.
  - `test_deep_below_window_chain_one_round`: a recent fact whose below-floor closure is a
    depth-D chain; assert b acquires the whole chain in **O(1) descent rounds** (all dep
    `have`s advertised at the leaf, all pulled together) — the key win over the old pull.
  - `test_suppressor_rides_closure`: b gets a message + its below-floor deletion via the
    same `have` advertisement; `feed` empty on b.
  - `test_two_workspaces_walled`: authorized prefix clip; b never receives the other ws.
  - `test_convergence_with_dup_frames`: replay/duplicate `compare`/`have`/`need` → still
    converges once (content-addressing), no round state.
- Files: `kernel.py`, `facts/sync/{compare,have,need,__init__}.py`, `bin/cond.py`,
  `facts/sync/reply.py` (−). LOC: roughly flat (three tiny families ≈ old bundled one +
  reply, minus `answer_of` complexity; kernel +~40).

**M7 — cadence as facts.**
- `runtime`/`cond`: `next_wake(node, now_ms)` = earliest `wake@clock` deadline − now →
  select timeout; delete `CADENCE`/`redial`/`compared`/`active`/`synced`.
- `facts/sync/cadence.py` (§4.4): volatile per-(cid,tier); `now_need(0)` + `wake@` + slice
  deadline + `SUPPRESS closed@cid`; daemon admits the `TIERS` on connect (staggered).
- `tests/test_cadence.py`: on connect, roots fire narrow→wide in stagger order; each
  re-arms at its period (drive `turn(now=…)` forward); earliest `wake@` computed right;
  `closed@cid` reaps all tier facts (offers gone); volatile → dropped on a fresh `Node`.
- Files: `facts/sync/cadence.py` (+), `facts/sync/__init__.py`, `bin/cond.py`,
  `bin/runtime.py`. LOC: + small (one family), − the daemon markers.

---

## 7. Open questions / risks (resolve while building)

1. **Symmetric vs initiator-led descent** `[V]`. §4.1 has both sides descend
   independently (each `compare` carries the sender's fp). Confirm this converges without
   frame blow-up; if it doubles frames unpleasantly, make the responder-only side split
   (carry a "you-asked" flag). Test `test_one_fact_diff` frame count is the check.
2. **`summary` closure walk** `[mostly C]`. Resolved by cross-leaf dedup in `_summary_rows`
   (one shared visited-set → the range's *deduped union* closure, spine once), so the naive
   "sum of every leaf's closure" cost never arises — `seen` is the range's unique reachable
   set, small at a leaf node. `CLOSURE_CAP` is a *generous* safety valve on unique ids;
   overflow (rare) falls back to the parked-leaf `missing_needs` backstop — the one spot the
   inference path still fires. `[V]`: pick `CLOSURE_CAP`; confirm the backstop actually
   covers an overflowed dep (else a leaf can go Valid with a below-window dep unpulled).
3. **Reserved-need precedence guard** `[V]`. Ensure `_step`'s SUPPRESS/REQUIRE lines never
   treat `SUM_ROLE`/`RES_ROLE` needs as gates (they're WATCH, but double-check the filter).
4. **Partial-write in `pump`** `[resolved — relaxed]`. We do **not** need the exact "fire
   only when fully drained" contract. **The outbound path tolerates loss up until the
   receiver admits** — a dropped or truncated frame is healed by the next cadence re-descend
   (and a truncated frame just fails `aead_open`, so the receiver drops it whole, never
   mis-admits). So `pump` **fires an owner best-effort when it hands the frame to the socket
   buffer**; the tail is held only for efficiency; a socket death loses the in-flight frame,
   the fired owner is already reaped, and the still-mismatched fingerprint re-emits it next
   round. The one hard rule: **no dropping after admit** (admitted facts are gated and
   flushed to the store). Test: a fake socket accepting N bytes → owners fire, offers reap,
   bytes finish across iterations; a mid-write close drops the frame without corrupting node
   state.
5. **`have`/`need` fact volume** `[C, mitigated]`. Single-id frames = many volatile facts;
   they reap immediately and the wire is packed+deduped. If in-memory churn bites, batch
   `have`/`need` into id-lists (handler loops; no logic change).
6. **cid symmetry** `[confirmed — grounded in the poc-10 port]`. `facts/connection/
   connection.py` (poc-10 tag-49 `create_connection`): the connection fact's **id is the
   cid**; `respond()` is deterministic (ephemeral + seal-nonce = `keyed_hash(esk, …,
   request_id)`) and its SHAPE is "deterministic given (env, request_id): both sides build
   identical bytes" — responder authors, initiator admits the *identical* bytes ⇒ same fact
   ⇒ same cid. The fact's bytes are identical but its projected `connection@SELF =
   frame(peer_ep, peer_addr)` is **side-specific**: `project` computes the peer as *the
   other side* from whichever keys are resident (lines 103-108), so `route(cid)` (line 168)
   resolves per-side to that side's peer addr + shared secret. My §4 (offers at
   `Exact(cid)`, pump `conn.route(cid)`) is exactly `_pump_data` today (cond.py:227); the
   only addition — sync frames *carry* cid so the responder targets `Exact(cid)` back — is
   the `cid` atom in `compare`/`have`/`need`. **Confirmed in poc-10** (`create_connection.rs`,
   `author.rs` `deterministic_responder_output`, `send_facts_on_connection.rs`): cid =
   `BLAKE3` of the deterministic responder-authored connection fact; the initiator admits
   the *identical* bytes (same id). One precision to keep: the actual socket routing is **by
   address**, not by cid — cid is a *handle*. `route(cid)` reads the connection row (which
   carries *both* return addresses) and picks the peer's addr by comparing the local
   endpoint to `from/to_endpoint`, plus `connection_secret` for sealing. poc-13's `route`
   (line 168) + side-specific `project` already do exactly this, so §4's `Exact(cid)` offers
   → `conn.route(cid)` → (peer addr, secret) is the poc-10 shape. End-to-end check still
   belongs in `test_handshake`.

---

## 8. Design rationale (the "why")

### Architecture — three layers, one boundary
Kernel (generic; keys/prefixes/edges + engine-answered index needs), runtime
(`cycle`/`pump`, testable), daemon (I/O + cadence). **IN** = `node.admit(bytes)` only.
**OUT** = read `watched(send/ship,outbox)`, **seal-if-secret** via `frames.seal` query,
ship; `shipped→Reap` (fired, not acked; sync heals loss). Daemon authors nothing outbound.
**Frame (bulk-transport) crypto** is a family *query* the daemon calls (`frames.seal/open` —
frames are volatile wire-only, decided from the real `frame.py`). This is *not* a blanket
"no crypto in projectors": **handshake crypto** (`request`/`connection` opening their
X25519 envelopes, verifying signatures, deriving `conn_secret`) and **signature
verification** live in projectors, because those are *durable facts* on the normal
admit→project path and the crypto *is* their validity. The rule is "don't turn a volatile
wire wrapper into a fact just to project its crypto," not "no crypto in projectors."

### Sync — dep-aware negentropy, decomposed
Leaves = durable ∧ shareable ∧ Valid|Suppressed, keyed `workspace‖ts‖fid`, content-hashed
(immutable), **valid-only** (Parked/pre-position rejected). Three families:
`compare(range,fp)` (single-range descent, split-k on mismatch, deterministic split),
`have(id)` (advertise), `need(id)` (request). Dep completion = **advertise the full
transitive closure-ids with the leaves; pull by id**. This is convergent (request only
ids we've vouched for — a closed retrieval, not a search into the void) and it **dissolves
the require/suppress split** (a suppressor is just a closure-id we advertised, so the peer
pulls it by id — no push, no negative-inference). Outbox dedup makes the closure flood
cheap; keep `have`/`need` id-only so dupes are byte-identical.

### No rounds
Content-addressing collapses overlap/duplicates; convergence = fingerprint match; retry =
next cadence root re-descends the still-differing ranges; rate = cadence period. Delete
round state. **Cost — overlap under latency:** if the response is slower than the period,
overlapping descents waste (bounded) work; mitigate by pacing period > RTT·depth, the
fp-changed slice (idle), or an optional `activity@cid` debounce (a marker, not rounds).

### Suppression / removed user
A deletion `D` is its own leaf and sits in its target's closure, so it rides the same
advertisement; `M`'s leaf never moves (content-hashed). Local SUPPRESS eval is exhaustive
(never windowed) → a persisted suppressor always bites; unseen ones don't (seen-only
guarantee). Removed user = **ts-anchored authority**: message suppresses on
`removal@U@[0,M.ts]` (later removal keeps old messages, kills post-removal ones) + requires
a permanent grant; "is U removed?" is a ts-agnostic render check; `R` propagates as an
ordinary recent leaf.

### Cadence — volatile facts (re-created on reconnect)
`wake@clock@Exact(deadline)` alarms drive the select timeout; the projector re-arms
(advance a slice deadline + emit next `wake@`); `SUPPRESS closed@cid` is teardown. One
`sync.cadence` per (cid, tier); `TIERS` narrow+frequent … wide+rare with a stagger for the
initial cascade; volatile → reconnect refreshes authorized prefixes for free.

### Multi-workspace / hydrate asymmetry / declarative line
Leaf key carries the workspace prefix; the root `compare` names the connection's
authorized prefixes; kernel stays workspace-blind; closure stays in-workspace. Sync is
valid-only; **hydration is relationship-based** (`store.pull` regardless of validity —
local pull-to-validate). Facts+cadence are for **provable liveness/coverage**;
**data-driven ranking** (closest/fastest peer, top-K) is a query → imperative daemon over
the peer table, never atoms.

---

## 9. What we are explicitly NOT doing
- Not *frame*-crypto in projectors / frames-as-db-facts — frame seal/open is daemon-called
  queries (volatile wire-only; lower LOC). **Scoped to the transport frame only:**
  handshake open/verify (`request`/`connection`) and signature verification stay in
  projectors — durable facts whose crypto is their validity.
- Not admission-based sync inclusion (valid-only; hydration stays relationship-based).
- Not an always-full/floor-0 suppressor domain (seen-only via closure advertisement).
- Not `missing_needs` inference-pull for deps (advertise-closure-ids + pull-by-id;
  `missing_needs` remains only as a possible rare local backstop).
- Not durable cadence (volatile, re-created on reconnect).
- Not round bookkeeping (content-addressing + fp-convergence + cadence re-emit).
- Not ranking/selection in facts (that's a query).

---

## 10. Further work (deferred, seams left open)

### 10.1 Residency / sync separation (sync everything, hydrate a subset)
Today the sync set = validated leaves = stepped = resident, so hydrating only recent
messages syncs only recent. But a leaf hash is `H(fid‖ts‖H(bytes))` — bytes-only,
independent of a fact's offers/context, and identical for Valid vs Suppressed. So
the two coupled things separate cleanly:
- **Skeleton = the sync index.** `(ts,fid) -> leafhash`, ~72 B/fact (72 MB for 1M),
  the *full* set; already body-independent as of the RBSR rewrite. RBSR reconciles
  over this alone — no fact bodies needed. Persist it so cold facts stay in sync
  without being re-stepped.
- **Residency = the hydration set.** Bodies + offers + slices, materialised only for
  the recent window + active dependency closure; `Store.pull` on demand (to render,
  or to ship a fact a peer asks for).
Mechanism (declarative): a `hydrate` window fact whose offer every content fact
WATCHes; the projector reads it to choose materialisation DEPTH (emit render/index
offers in-window, stay lean out-of-window). This governs residency, NOT sync
membership — the Skeleton keeps the leaf regardless, so shedding an old body never
drops it from reconciliation, and a suppressor arriving for a shed fact does not
desync (same leaf hash). Constraint: first-validation needs dep *content* (project
reads ctx values), so validate once (hydrating the dep closure transiently) then
shed; "stay in sync without staying materialised" — yes. Companion affordance:
expose Skeleton membership as a `validated@id` need (sibling of `resident@id`/
`summary@range`) so a fact whose validity depends only on dep *existence* can
validate cold, against the Skeleton, with no materialisation. `extract`'s
`shareable` bit stays the sync axis; the hydrate window is an orthogonal residency
axis.

### 10.2 Count-augmented balanced tree for the Skeleton
The RBSR Skeleton uses a sorted list: correct, minimal, optimal *wire* cost, but
insert is O(n) and a range fingerprint is O(range) (so `_summary_rows` re-hashes a
matched range's partition — bounded by the `leaf_xor` cadence guard, but real).
Production swaps in a treap with deterministic priority = hash(key) (order-
independent shape) augmented with (count, subtree-hash): O(log n) insert/remove, and
split/merge gives an O(log n) non-homomorphic range fingerprint + order-statistic
count-split, killing the re-hash. Same protocol, same frames.
