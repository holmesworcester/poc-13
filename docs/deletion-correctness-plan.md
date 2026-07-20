# Deletion Correctness → Memory Limiting — Implementation Plan

Status: plan. PR-shaped companion to `docs/selective-hydration.md` (design).
Order per direction: land the deletion-correctness batch on master first, then
the memory-limiting batch on top of it.

## 0. What the audit changed about the scope

Reading the real families and running a probe against the real corpus moved two
assumptions from the design doc:

1. **Flatness (#10) already holds.** Every content family that must die with a
   message names the message *directly*:
   - `message.py:24` — `SUPPRESS_IF dead@wid/SELF` (stored as `Exact(message_id)`)
   - `reaction.py:20`, `file.py:40`, `file_slice.py:27` — `SUPPRESS_IF dead@wid/Exact(message_id)`

   and `message_deletion.py:18` fires `PROVIDE dead@wid/Exact(target_id)`. So a
   deletion already fans out to the message + its reactions + file + slices in
   one flat, indexed match; no family names a derived fid (a slice names the
   `message_id`, never the `file_id`/descriptor it Requires). **#10 is a
   lock-in — a written obligation + tests — not a fix.**

2. **Deletion is already correct under total-demand boot.** With every target
   resident (the only boot path today, `hydrate.demand(node)` with no key), a
   deletion's `dead` Provide reaches all targets through the existing wake /
   backward-fault legs. Even a *selective* `msg` hydrate stays correct, because
   a hydrated message's own step backward-faults its tombstone: **the target
   pulls its own death.** Verified: `test_hydrate.py:58`
   (`test_suppression_across_the_cold_boundary`) hydrates `msg` and mid2 is
   purged.

The gap (#9) is therefore *latent*: it appears only when a target is
durable-but-cold **and not itself hydrated**, which today never happens but is
exactly the eviction/windowing regime. Consequence for staging: the master
batch is **not** a behavior change under current operation. It (a) lands #9 as a
forward leg that is a **strict no-op under total demand**, so the deletion gate
is already in place and provably inert before any eviction code exists, and (b)
locks flatness + closure with tests so the memory batch cannot regress them.

## 1. The gap, as one confirmed-RED test

The backward leg is tested (`test_hydrate.py:195`,
`test_a_cold_suppressor_bites_without_a_demand`): a live target's own step
faults its cold suppressor in. The **forward dual has no code and no test**.
Probe (real signed workspace; a peer holds mid2 + its deletion on disk, then
hydrates only the suppressor address `b"dead"`, never `b"msg"`):

```
deletion validated & resident: True
mid2 hydrated:                  False
mid2 STILL ON DISK:             True   ← a valid deletion did not reach the cold target
```

That is the RED. #9 turns it GREEN.

---

## Batch M1 — deletion correctness (master)

Three small edits + tests. No behavior change under total demand.

### M1.1 `Store.suppressors` — the forward existence query
Mirror of `providers` (`kernel.py:363-369`) with `relationship=SUPPRESS_IF`.
`_COV` is symmetric in the point/range sense, so the same clause serves the
reversed direction:

```python
def suppressors(self, provide):      # existence: who SuppressIfs over this validated address
    return [r[0] for r in self.db.execute(
        "SELECT DISTINCT fid FROM atoms WHERE relationship=? AND name=? AND scope=?" + self._COV,
        (SUPPRESS_IF, provide.name, provide.scope, *provide.target,
         provide.target[0] == provide.target[1], provide.target[0]))]
```

Indexed by the existing `match_ix (relationship, name, scope, ex, lo)`.

### M1.2 `Node._fault_suppressors` — the forward leg
Next to `_fault` (`kernel.py:572`):

```python
def _fault_suppressors(self, provide):
    """Forward leg: a newly-valid Provide faults in the cold facts whose
    SuppressIf covers it, so a suppressor (a deletion) reaches a durable-but-
    cold target. Restricted to SuppressIf — a suppressor names its target, so
    the covered set is flat/per-object; that is the same reason a forward leg
    over Require would be unbounded (a dependency does not name its dependents)."""
    if not self.store or _ALL_KEY in self.checked: return
    k = (SUPPRESS_IF, provide.name, provide.scope, provide.target)   # 4-tuple: never
    if k in self.checked: return                                     # collides a backward key
    self.checked.add(k)
    for o in self.store.suppressors(provide):
        if o not in self.facts and (b := self.store.fact_bytes(o)):
            self.admit(b, checked=True)          # its own step re-derives Suppressed (kernel.py:553)
```

Hook in `_settle`, immediately before the wake fanout (`kernel.py:635`):

```python
        for r in set(new) - set(old):        # forward suppression leg: a newly-valid
            self._fault_suppressors(r.atom)  # Provide reaches its cold SuppressIf consumers
        for r in set(old) ^ set(new):        # (existing) wake fanout
            self._wake(r.atom, fid)
```

**Why the memo is sound forward** (same argument as backward, `kernel.py:441`).
The leg only needs to catch consumers that are cold-durable *when the Provide is
published*. A consumer that becomes durable *later* is caught by its own step
(it backward-faults its `dead` address and finds the resident Provide). A
consumer that is already *resident* is caught by the existing `_wake`. So the
store pull is a one-time thing per Provide address → memoizable in `checked`
(which #11 later turns into a cache — see M2).

**Why it is a no-op today.** Under total demand `_ALL_KEY ∈ checked` guards it
off entirely. Even on a *selective* path (`feed`), the leg fires on the
deletion's Provide but finds every target already resident (`o not in
self.facts` is false), so it admits nothing. The forward pull is non-empty only
when a target is durable **and** cold **and** covered by a just-published
SuppressIf — the empty set in every current test.

### M1.3 Tests (`tests/test_hydrate.py`, `tests/test_relationships.py`)
- **`test_a_cold_target_is_purged_when_only_the_deletion_hydrates`** — the RED
  above. Build a store holding a message + its deletion (snapshot durable
  *before* the delete, as the probe does), `hydrate.demand(peer, b"dead", wid)`,
  assert `store.fact_bytes(mid) is None`. RED before M1.2, GREEN after.
- **`test_suppressors_mirrors_kernel_covers`** — property mirror, dual of
  `test_fault_fixpoint_mirrors_kernel_covers` (`test_hydrate.py:297`):
  `set(store.suppressors(p))` equals the pure-Python set of durable facts whose
  materialized SuppressIf `covers` p.
- **`test_deletion_closure_is_flat`** (#10 lock-in) — author message + reaction
  + file + slices, delete the message, assert every dependent is purged from
  memory *and* disk, and (static) assert each dependent's `dead` SuppressIf
  target equals `Exact(message_id)` (or SELF for the message) — never a derived
  fid. This is F4 as an executable check, per shareable family.
- **Regression**: the full existing suite stays green (no behavior change under
  total demand). This is the acceptance signal that M1 is safe on master.

### M1.4 The F4 obligation (docs)
Add to `DESIGN.md` (Relationships / suppression closure): *"A fact that must not
outlive object O carries `SUPPRESS_IF dead@workspace/Exact(O_id)` where O_id is
the id of a fact a deletion targets directly — never the id of an intermediate
fact it merely Requires. The forward SuppressIf leg (`_fault_suppressors`)
depends on this flatness: it faults exactly the facts that name O, in one
indexed match."* `test_deletion_closure_is_flat` enforces it.

### Acceptance for M1
1. Existing suite green (proves inert under total demand).
2. New forward test green (proves the gate works cold).
3. Mirror + flatness tests green (proves the query and the obligation).

Land as one PR titled "deletion reaches cold targets (forward SuppressIf leg)."

### Known cost + optional follow-up
`_fault_suppressors` runs one indexed `SUPPRESS_IF` SELECT per *distinct
Provide address*, memoized once. Most addresses (`msg@wid/channel_id`,
`posted@wid/mid`) have no suppressors and return empty; only `dead` addresses
match. That is one wasted empty SELECT per distinct non-`dead` address over a
session — fine for the POC. If it ever matters, add a family-registered set of
"suppressor-targeted" Provide names (same seam as `observe()`/`answer()`) and
fire the leg only for those. **Not in the first cut** — it couples the kernel to
family names and the uniform version is correct and simple.

---

## Batch M2 — memory limiting (after M1 is on master)

Full design in `docs/selective-hydration.md`. Order and the two couplings that
bind it to M1:

1. **#4 bound the below-floor closure** (`index.py:230-234`) — the switch that
   *saves* memory currently opens an unbounded path; fix before any windowing.
2. **#11 `checked` becomes a cache** (`kernel.py:577-581`) — eviction breaks the
   monotonicity both fault legs rely on. **Coupling to M1:** eviction must clear
   *both* the backward key `(name, scope, target)` **and** the forward key
   `(SUPPRESS_IF, name, scope, target)` for the affected addresses, or a
   re-arriving fact won't re-pull.
3. **#12 fault-out** (new, `kernel.py`) — evict Valid-never-Parked from
   `self.facts` + asserted rows + memo, LRU under a watermark. **Coupling to
   M1/advertising:** fault-out must **not** touch `durable` and must **not**
   retract the treap leaf (that is `_evict`/deletion). If it reused `_evict`'s
   observer path it would silently unadvertise the sync pin — turning eviction
   into a false "I don't have it." This is the `resident ⊄ advertised`
   invariant made operational.
4. **Payoff**: the notification picker (a durable, non-replicated family) and
   "arbitrary memory limits just work" above `max |closure(fact)|`.
5. **Profiles**: ship **13a** (bilateral floor, phone) as a strict prefix of
   **13b** (persisted leaf table, relay/cloud). §6/§8 of the design doc.

The ts-as-field schema change (design doc §4-C) is **orthogonal** — needed only
for time-windowed *hydration/boot* and family-selective windowing, not for
eviction. Land it on its own schedule (every fid changes → fresh database).

---

## Deferred design decisions (not blocking either batch)

- **Channel deletion** is unbuilt (`channel.py` has no death key, no
  `channel_deletion` family). If added, it is a *second flat death axis*:
  messages carry `SUPPRESS_IF dead@wid/Exact(channel_id)` in addition to their
  own, and #9's forward leg handles each Provide address independently — no
  cascade, no new machinery. Flatness (#10) extends to it verbatim.
- **Retention purge** — `retention_policy.py` records the window but "the purge
  machinery is a later family." When built, it authors death keys for
  over-window facts and rides the same #9 leg.
- **Treap range by channel/class (Willow-style)** — the treap key is `ts‖fid`
  today (time-only); `type_tag` is already a dotted namespace and a `facts`
  column, and `scope` already carries the channel/container. Whether to *prefix
  the treap key* by channel (making "sync this channel since T" one range) vs.
  keep sync 1-D and do multi-dimensional selection in the `facts`-table
  hydration query is a phase-2+ decision. Note the split: the **store hydration
  index** can be freely multi-dimensional (any `WHERE` over columns); the **sync
  reconciliation key** must stay linear (one prefix, or adopt Willow's 3-D range
  structure — a sync-core change, not a key tweak). Revisit with the Willow data
  model (namespace × subspace × path × time) if capability-scoped multi-dim sync
  becomes a goal.
