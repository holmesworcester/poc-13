# Selective Hydration and Memory-Bounded Residency

Status: design. No code yet. Consolidates the iOS-memory / notification-picker
thread. Companion to `DESIGN.md` (Hydration, Runtime State) and
`docs/anchor-sync.md` (the floor).

These are POC exercises: **there is no backwards-compat or migration
obligation.** Any change here that alters a fact's canonical bytes just means a
fresh database — which is exactly what the schema guard at `kernel.py:317-318`
already fails closed on. Nothing below carries an old format alongside a new
one; where the encoding changes, it changes outright.

## 1. The problem, and why poc-7's levers don't transfer

Target: stay under a hard memory budget (iOS ~24 MB) while participating in a
workspace whose durable set is far larger, and while receiving file
attachments whose slices are 256 KiB each.

In poc-7 the memory levers were (a) central persistence and (b) range-limited
sync — the latter worked *because* the in-memory sync structure was
proportional to items, so bounding range bounded memory. **That equivalence is
gone in poc-13.** Measured here:

| Structure | Cost per fact | Holds content? |
|---|---|---|
| kernel resident set (`kernel.py:431-437`) | **~1.7 KB + 2× payload** | yes, twice |
| sync treap + leaf set (`facts/sync/index.py:46`) | ~350 B | **no** — `key → leaf hash` only |

The payload is held twice: `self.durable` keeps full canonical bytes
(`kernel.py:431`) and `self.facts` keeps a decoded `Fact` whose `Atom.value`
slices do not alias them. A 256 KiB Bao slice is ~512 KiB resident; one 10 MB
attachment ≈ the entire budget. Range-limiting sync would save ~350 B/fact and
touch none of this. **The sync index is not the problem; the decoded-fact cache
is.**

## 2. The real coupling, and the two-pin model

The old version of this doc stated the target as `resident ⊆ advertised ⊆
durable`. **That was wrong in both directions.** The serve path shows why:

- the leaf rule keys on `node.durable`, not on the decoded cache
  (`index.py:198`): `should = after is not None and fid in node.durable`;
- the leaf hash is `H(node.durable[fid])` (`index.py:203`), and the treap is
  content-free (~350 B/leaf);
- serving a *pulled* id faults its fact in only **transiently** — a `need`
  Gathers `leaf@sync/Exact(fid)` per requested id (`need.py:23,44`), which the
  fault leg satisfies, and the fact can evict again after the round.

So **advertising needs durability, not residency.** Today `advertised =
resident` looks true only because total-demand boot hydrates every durable
fact; the coupling is really `durable ≈ resident` (we never evict) sitting on
top of `advertised ⊆ durable` (the actual rule). Break the first and the second
still holds.

That reframes residency as **two independent pins that pin to different storage
tiers**, plus a transient working set — exactly the intuition of "protect
must-display UI content; let sync keep its own range; evict everything else":

**Display pin — the residency root.** UI-owned. Members are the facts that must
render *now*: messages around the scroll position, the channel list, the member
list. Keyed by *access*, arbitrary, jumps on scroll/channel-switch, spans
families (a visible message + its reactions + a thumbnail). Small — O(a
screenful). Must be **decoded in memory** (you render from `Fact`, not bytes),
so the evictor may never reclaim a pinned member. It is **resident but not
advertised**: you hold a scrolled-to old message to draw it, but you do not add
it to the treap, so you neither invite peers to sync it nor promise to serve it.
(This is the earlier "don't reply to unhydrated ranges to avoid inviting
sharing forever," made precise: `resident ⊄ advertised`.)

**Sync pin — the durability + advertisement root.** Protocol-owned. Members are
the advertised window `[floor, HI)` (or, with `facts.tag`/`facts.ts` filtering,
a union of windows). Keyed by *time* (and optionally family), a clean suffix,
predictable, potentially **large**. Because advertising keys on `durable` + the
treap register, the sync pin pins its members to **disk + the ~350 B/leaf
treap**, *not* the decoded cache. Its *size* costs disk + ~350 B/leaf, never the
1.7 KB + 2× payload. It is **advertised but not (permanently) resident** — the
memory win: `advertised ⊄ resident`.

**Corrected containment.**
- `advertised ⊆ durable` — always (leaf rule); the correctness floor.
- Among *durable* facts, `resident` is an independent cache that **overlaps
  advertised freely, neither containing the other.**
- Volatile session facts (`compare`/`need`/`cadence`, `extract → False`) are a
  third class: small, resident-only, never durable, never advertised — reaped,
  not evicted.

**Residency budget.** `resident = display-pin ∪ sync-register ∪
transient-fault-set`; everything else in `self.facts` is evictable. The
transient set is bounded by `max |closure(fact)|` (judging one fact drags its
backward closure in, then it may evict). The window can grow to the whole
workspace without moving that bound — the large set pins to disk, the small set
to RAM. **That is why an arbitrary memory limit "just works":** the two pins
pin to different tiers, and the evictor is a watermark over `self.facts` that
reclaims non-root LRU down to budget, with the pins as GC roots.

**One modeling caveat.** Expressing the display pin *as a fact* is fine, but its
effect — *exempt from eviction* — is **not a verdict and not a relationship.** A
pin that `Require`d its targets would *fault them in* (backward wake); that is
fault-*in*, not fault-*protection*. Eviction is a cache operation **below** the
verdict lattice. So the pin is the **evictor's root set** — a set of fids, or a
`(tag, ts-range, scope)` predicate, that the fault-out pass treats as
non-evictable — which may be *sourced* from a fact's atoms but must stay out of
the confluence algebra (that is what keeps §5 intact). The UI rewrites the root
set as the viewport moves; dropped roots become evictable.

## 3. The two missing primitives

Each pin needs one primitive the kernel lacks today.

**Fault-out (serves the residency budget).** `_fault` (`kernel.py:572-584`)
pulls cold facts in; there is no memory-pressure eviction. The one path named
`_evict` (`kernel.py:639-659`) is semantic *deletion* — it drops `durable`,
calls `store.delete` (`kernel.py:371`), and retracts the leaf. No LRU, no
watermark, no size accounting. Fault-out must be a **different** operation:
drop `self.facts[fid]`, its asserted rows, and its memo, while leaving
`durable`, the store row, **and the treap leaf** intact — otherwise eviction
would silently unadvertise the sync pin.

**Forward waking for deletion (makes the sync pin safe to evict).** `_wake`
(`kernel.py:597-599`) fans out through `consumers_for` (`kernel.py:510-512`),
which reads the *resident* consumer index; the store is consulted only in
`_fault`, only on the *stepped fact's own* consumers. So a `Provide` can never
reach a cold fact — DESIGN.md:385-387 states it as intent: *"Provides never
wake cold facts."* Consequence: a suppressor's arrival cannot reach a **cold
target**, so deletion does not delete cold facts. This holds today only because
total-demand boot keeps every target resident; the moment the sync pin evicts
its window, cold targets become common and "deletion deletes immediately"
silently becomes indefinite retention of content we promised to destroy. This
is the load-bearing gate for everything else (§7).

## 4. Changelist (deduped)

Grouped by dependency. Item numbers are stable from the discussion thread.

### A — safe, independent, no encoding change, no confluence risk
- **#1 `files()` over-hydrates.** `file.py:236` calls `_slices()` per file just
  to compute `slices_received`, so `file list` materializes every attachment
  byte in the workspace; `resolve()`/`save()` route through it, and `save()`
  builds the whole proof dict before writing. The count is an *existence*
  aggregate; needs a store-side count door (the first small crossing of
  "store answers existence"). `save()` should stream per-index.
- **#3 unbounded `memo`.** `index.py:222,239` — keyed by peer-supplied
  `(lo,hi,floor)`, cleared only on set movement. Needs a cap/LRU.
- **#4 unbounded below-floor closure.** A nonempty floor activates
  `index.py:230-234`; `seen` is unbounded, `CLOSURE_CAP` truncates only the
  *wire blob* (`index.py:235`), and `node.closure` is recursive. **Prerequisite
  for 13a** — the bilateral floor is what first sets a nonempty floor in
  production.

### B — honest deletion (the gate)
- **#9 forward SuppressIf fault leg.** A mirror of `_fault` restricted to
  `SuppressIf` addresses: when a fact Provides at a death-key address, fault the
  cold *consumers* covering it. Confluence argument in §5.
- **#10 death-key flatness as a family obligation.** #9 is complete iff every
  fact that dies with a root object names that object *directly* in its
  `SuppressIf` target (`file_slice.py:27` carries `Exact(message_id)`, not
  `Exact(file_id)`, though the slice Requires the descriptor). Today this holds
  by convention and two docstrings. Make it a stated obligation (F4) with a test
  per shareable family: a SuppressIf target names a root object, never a derived
  fid.

### C — ts becomes a fact field (one schema change, no fork, no migration)
Supersedes the old "#7 ts into the atom target" and "#8 class byte prefix."
Both existed only to smuggle sortable axes into the atom match index; a fact
field plus the `facts` table's existing columns do it more directly.
- **ts is a `Fact` field, not a `PROVIDE` atom.** Today `ts_atom`
  (`kernel.py:143`) is a `PROVIDE b"ts"` that **nothing ever Gathers** — a dead
  row in every fact's provides bucket, read only structurally by `ts_of`
  (`kernel.py:144-146`). Promote it: `Fact(type_tag, ts, atoms)`,
  `fact(tag, ts, *atoms)`, ts framed into the canonical bytes (so it is still
  authenticated and part of `fact_id`, `kernel.py:134`), `ts_of(f)` becomes
  `f.ts`, settlement stamps `f.ts` (replacing `ts_of(f)` at `kernel.py:621`),
  and `ts_atom` is deleted with its callers passing ts to `fact()`.
- **Store: a `ts` column on the `facts` table** (`kernel.py:312`,
  `facts(fid, tag)` → `facts(fid, tag, ts)`), not the atoms table. `add()`
  writes it; `_mk`/`fact_bytes` reconstruct it.
- **Time-windowed hydration** is then a new store door —
  `SELECT fid FROM facts WHERE ts BETWEEN ? AND ?` + `CREATE INDEX facts_ts` —
  *not* an atom-target range query. It faults in only `[t0,t1)`, which is what
  makes boot cheap and warms a cold cache without the total Gather.
- **Family-selective hydration** ("messages, not files") is a filter on
  **`facts.tag`, which already exists**: `... WHERE tag GLOB 'content.message*'
  AND ts BETWEEN ? AND ?`. No class byte; the fact already carries its class as
  a column.
- Payoff: **economical** (one fewer Atom/fact resident, one fewer atoms-table
  row, one fewer wire frame, no dead `(b"ts", scope)` bucket entry) and **more
  logical** (ts is fact metadata already privileged by settlement — the one
  PROVIDE read structurally rather than matched, i.e. already the exception to
  "everything is an atom"; the field makes the exception honest). Every fid
  changes → fresh database.
- **Independent of the memory work.** Time-windowed *advertising* needs no
  schema change (the floor is already a suffix over the treap key `ts‖fid`,
  `index.py:168`). This group is the enabler for time-windowed *hydration/boot*
  and for *family*-selective windowing — not a prerequisite for eviction.

### D — eviction chain (depends on B, benefits from C)
- **#11 `checked` becomes a cache.** `kernel.py:577-581` is monotone only
  because nothing ever leaves; its soundness note ("rows enter the store only
  downstream of admission, so a new row's owner is already resident") is exactly
  what eviction falsifies. Evict → forget the relevant `checked` keys so the
  fault leg can re-pull.
- **#12 fault-out.** The residency-budget primitive from §3. Evict **Valid,
  never Parked** (a parked fact waits on an arrival it cannot see; evicted, it
  never re-steps → never Valid → never a leaf). Must **not** touch `durable` or
  the treap leaf (that is deletion, not eviction). LRU naturally pins the auth
  graph (every message Requires `key@workspace`, `file.py:39`). Bounded below by
  `max |closure(fact)|` (§8).

### Payoff (falls out of D)
- **Notification picker** is just a family: `extract → True`, no `sync_leaf`
  import → durable but never replicated (replication is already opt-in, one
  import per shareable family). The projector fires on arrival with the closure
  resident, emits the notification with its payload, and the fact faults out.
  Same verify-then-drop shape as Bao slices. Works as a durable family even
  before #12; #12 is what makes it *save* memory.
- **Arbitrary memory limits "just work"** above `max |closure(fact)|`.

### Dropped
- **#6 (fault SuppressIf first, short-circuit).** Withdrawn. The resident-
  suppressor short-circuit already exists at `kernel.py:553-554`, and once #9
  routes deletions through it, purge-under-pressure faults nothing backward
  (each dying fact settles SUPPRESSED at 553 with no closure pull). The only
  case #6 improved — a dead fact pulled before its tombstone during boot — is
  rare under selective hydration and not worth making the fault leg order-
  dependent (which would trade the one-line confluence argument in §5 for a
  case analysis). Keep the uniform fault pass.

## 5. Why the forward SuppressIf leg (#9) preserves confluence

The engine's correctness rests on **confluence**: the quiescent state is
independent of arrival and step order. Today suppression is confluent *only*
under total-demand boot, and selective hydration breaks that. #9 restores it.

**The asymmetry today.** Backward faulting handles "target steps, finds cold
suppressor" — DESIGN.md:381-382, *"absence is only trusted after the key is
checked — a cold suppressor bites on its target's own step."* There is no dual
for "suppressor steps, finds cold target," because the design assumes targets
are resident. So the discovery of a (suppressor, target) pairing is order-
dependent: it happens iff the target is or becomes resident. Under selective
hydration a target can stay cold forever while its suppressor is resident →
the pairing is missed → the deleted fact survives. **That is a confluence
violation the current code hides by never evicting.**

**The fix restores symmetry.** With a forward leg, either arrival order
discovers the pairing:
- target resident first → its step faults the suppressor backward (existing);
- suppressor resident first → its Provide faults the target forward (new).

Both reach the same quiescent verdict (SUPPRESSED). Order no longer matters —
that *is* confluence.

**Why it stays bounded (no forward cascade).** Restrict the leg to `SuppressIf`
addresses only. Death keys are per-object (`Atom(SUPPRESS_IF, b"dead",
workspace_id, Exact(message_id))`), so a `dead` Provide's cold-consumer set is
exactly the deletion closure — message, descriptor, slices, reactions — one
indexed SELECT, flat. Contrast `Require`, whose targets are per-workspace
(`Exact(workspace_id)`), which is *why* a forward leg over Require would be
unbounded. A suppressor names its target; a dependency does not name its
dependents — so the forward leg is cheap precisely where it is mandatory. (This
is also why the display pin cannot be a `Require`: forward-waking a
per-workspace Require target is the unbounded case we are avoiding.)

**Why one hop, not a wave.** A forward-faulted target T, once resident, steps —
but the suppressor that pulled it is resident, so `kernel.py:553-554` fires and
T settles SUPPRESSED with **no backward fault**. T pulls nothing further. The
forward wave is exactly suppressor → direct targets, each dead-ending at
SUPPRESSED.

**Why `checked` stays a sound memo forward.** Same monotonicity as backward: a
SuppressIf-covering Provide row enters the store only downstream of admission,
so forward memoization never goes stale for the same reason backward does. (It
interacts with #11: eviction is the one thing that breaks monotonicity in
either direction, which is why #11 makes `checked` a cache rather than a
permanent set.)

## 6. Certificate safety: bilateral floor, not silent abstention

Tempting shortcut: "just don't reply to unhydrated ranges." It **forges the
certificate.** If `compare.project` (`compare.py:85`) silently skips a range,
that range never enters `out`; if the ranges it *did* answer all matched, it
falls to `compare.py:118-119` and sends an all-`done` reply, which the peer
folds as `conf = sent` (`cadence.py:96-97`), and `cadence.synced` returns True
(`cadence.py:120-128`) — a *proof* of agreement over a range never examined,
re-certified every anchor period. Omission is invisible to a mechanism that
counts only the claims that were made. (Worse than "inviting sharing": a false-
empty claim makes us actively **pull** — `compare.py:106-107` accumulates every
id the peer advertised that we lack into one batched `need`, `compare.py:114`.)

The declared alternative is already built: the **floor**. It rides in every
compare (`compare.py:55`), re-threads through replies (`compare.py:90`), clips
the answerer (`index.py:218`), keys the cadence tick (`cadence.py:83`), and
`synced` is already floor-scoped (`cadence.py:120`). It is dead only because
`TIERS` hardcodes `b""` (`cadence.py:113`). The one gap: a responder answers at
the *opener's* floor, not its own. Fix = `floor = max(theirs, mine)` in
`compare.project`, re-thread the raised value (~3 lines, no new wire vocab).
The certificate then honestly means *"we agree over `[max(floorA,floorB),
HI)`"* — no lie, no flood, round completes, `synced` stays meaningful, peer
knows why.

**Axis note (with the §4-C schema in hand).** The floor is a suffix over
`ts‖fid` — it expresses "since T" and nothing else. *"Exclude files"* is a hole
in the *middle* of the key space, which no floor describes; with ts and class
now columns on the `facts` table, that is a `WHERE tag GLOB … AND ts BETWEEN …`
hydration predicate (§4-C), **not** a sync-range primitive. And *"messages
unrelated to a notification"* is not a sync question at all — it is a residency
policy answered by #12 / the display pin, not by any range.

## 7. Ordering: deletion is the gate

Even though this doc is the chosen first deliverable, the recommended first
*code* step is **B, not A.** Everything downstream of selective hydration
assumes deletion reaches cold facts; without #9/#10, turning on eviction or
windowing means retaining deleted content. Critical path to memory-bounded
residency:

```
#4  (bound the below-floor closure)  ─┐
#9 + #10 (honest deletion on cold facts) ─┬─→ #11 (checked as cache) ─→ #12 (fault-out) ─→ picker, arbitrary limits
                          └─ (13a needs #4)
```

A (#1, #3) is genuine but independent cleanup and can land anytime. C (the
ts-field schema change) is **orthogonal to the memory work** — required only for
time-windowed *hydration/boot* and for *family*-selective windowing, not for
eviction or for time-windowed *advertising* (the floor already rides the treap
key). Land it when you want cheap boot or "messages not files," on its own
schedule.

## 8. Decision: two target profiles (13a interim, 13b destination)

The remaining fork is **how far `advertised` decouples from `resident`** — i.e.,
how the two pins of §2 are realized.

**13a — bilateral floor (phone profile).** The sync pin *is* the window:
`advertised = window [floor, HI)`, held as disk + treap; the decoded cache is
the display pin plus a transient fault set. Evict outside the union; the
bilateral floor (§6) means you also don't *claim* outside the window, so the
certificate stays honest. Memory O(display pin + max closure). Ships after
#4 + §6 plumbing + B; §4-C only if you want cheap boot or to exclude files
within the window. Limitation: coverage still equals the *durable* window — a
cold node still advertises nothing outside what it has persisted, so this does
**not** serve the always-on relay / cloud case. Fine for a single-user phone.

**13b — persisted leaf table (relay profile).** Persist `ts‖fid → leaf_hash` in
SQLite, written by the settle hook that already sees every verdict, torn down by
the `_evict` path that already calls `store.delete`. Then `advertised = all of
disk`, and *both* pins shrink: the sync register no longer has to be resident
(read the tail of the leaf table), and the decoded cache is pure LRU. Full
participation at bounded memory, plus fast-open (read the tail) and O(1) boot
(vs the measured 3.16 s full hydrate). This crosses `kernel.py:299` — *"the
store answers existence, never standing"* — defensibly reframed as the sync
family persisting *its own* register, the *"real (sqlite) index"* that
`facts/store/__init__.py:1-2` has promised as a later wave all along. The
separate cloud-deployment analysis reaches the same conclusion from the server
side (sync-coverage-==-residency as *the* blocker), which is corroboration
worth noting.

**Recommendation.** They are not either/or: 13a is a strict prefix of 13b and
its bilateral-floor plumbing survives into it. Ship **13a** for the iOS memory
bound; treat **13b** as the destination that additionally unlocks relay/cloud.
Do **B (honest deletion) first regardless**, since both profiles evict and both
are unsafe without it.

## 9. Unenforced invariants to watch

- **Death-key flatness (#10)** — nothing enforces it today; a family that names
  a derived fid in a SuppressIf target silently defeats #9's forward SELECT.
- **`checked` monotonicity (#11)** — the memo's soundness note assumes nothing
  leaves memory; eviction is the sole violator, so #11 must land with #12, not
  after.
- **Evict Valid only, never Parked (#12)** — a parked fact is precisely one
  waiting on an arrival it cannot see while cold.
- **Fault-out must not retract the leaf (#12 vs #9)** — eviction drops the
  decoded fact but keeps `durable` + the treap leaf; only semantic deletion
  retracts. If fault-out reused `_evict`'s observer path it would silently
  unadvertise the sync pin (turning eviction into a false "I don't have it").
- **The below-floor closure (#4)** — the switch you flip to *save* memory (a
  nonempty floor) currently opens an unbounded-memory path; fix before 13a.
- **Display pin is not a relationship** — sourcing it from a fact is fine, but
  it must feed the evictor's root set, never `Require`/`SuppressIf`, or it
  re-enters the confluence algebra (and, as a Require, triggers the unbounded
  forward-wake §5 avoids).
- **ts scope drop (§4-C)** — `ts_atom` carries a `scope` that nothing reads
  (`ts_of` ignores it, nothing Gathers `b"ts"`); confirm no family leans on it
  for identity disambiguation before removing it (the real scoping atoms already
  carry `workspace_id`, so this should be a no-op — but it is in every fact's
  canonical bytes today).
