# Timing RBSR rounds with facts only

**Problem.** Assume the daemon/host provides an RBSR index for free — a range-fingerprint
structure over the `(ts, FactId)` leaf set (poc-13's `kernel.Treap`: O(log n) range
fingerprints, O(1) whole-set change detection), surfaced to the fact layer through the
reserved summary need. Given that index, **how can RBSR sync use facts only to
*efficiently time rounds*** — decide when to open a reconciliation round — with no
round-timing or dedup state living in the daemon?

This note states the problem precisely, records what is built, and lays out the tradeoffs
for what remains, including the options that are ruled out and the exact kernel fact each
one dies on.

## What "efficiently" means — three requirements

1. **Silence when converged.** A pair with equal sets must fall silent: no rounds, no
   frames, once there is nothing to reconcile.
2. **O(n) catch-up, not O(n²).** A fresh or lagging peer pulling `n` facts must cost O(n)
   wire, not O(n²) — no re-descend/re-ship explosion while the diff is large.
3. **Timing in facts.** The decision of *when* to open a round is a fact concern. The
   daemon holds no sync policy; it performs transport and presents the index.

## The split of responsibilities

**The host/daemon provides** (taken as given here):

- the **RBSR index** — range fingerprints and count-splits, answered into a projector's
  `ctx` via the reserved `summary` need;
- **transport** — dial, seal, ship, and the per-connection socket;
- **host transients** — `now@clock` (the OS clock) and `shipped@wire` (flush reports),
  presented into the turn.

**Facts provide** the reconciliation itself (`sync.compare`, `sync.need`) and the
**cadence** that times rounds (`sync.cadence`).

**The kernel constraints that bound every option below:**

- **Projectors are pure** — they emit computed offers and *never author facts*. Only the
  host admits. So any state that depends on *observing the wire* cannot originate in a
  projector.
- **There are only three wake sources** — `now` (every turn once a deadline passes),
  `shipped@SELF`, and ordinary offer-coverage (a matching offer being presented). There is
  **no "fact X arrived" wake**: the reserved `resident`/`summary` needs are *demand-pull*
  (answered at project time), and `missing_needs` is *daemon-polled*.
- **Slices are bounded per-fact memory** — a promote clears a fact's own slices and re-adds
  only what its `slice_delta` names, so accumulating O(n) state in slices costs O(n) per
  update = O(n²).

## A round needs three memories

To time rounds without waste, a peer must remember three things per connection. *Where each
can live* is the entire design question.

| # | memory | prevents | size |
|---|---|---|---|
| 1 | **round** — "a round is open at fingerprint F toward P" | redundant re-opens (requirement 1: silence) | **bounded** — one hash per (peer, tier) |
| 2 | **in-flight** — "I asked P for range R; the answer is in flight" | re-asking before the answer lands | O(open ranges) |
| 3 | **shipped** — "I already shipped leaf X to P" | re-shipping on a re-descend | **O(n)** — one per shipped fact |

Today the daemon's per-connection `sent` set collapses memories 1 and 3 into one
content-hash set (cleared on socket break). The goal is to move what *can* move into facts.

## What content-addressing buys — and where it stops

Every compare frame is **content-addressed**: its bytes are `encode(compare(cid, claims,
floor))`, `claims` is a pure function of the leaf set, and `ts` is pinned to `0`. So *the
same round state produces byte-identical bytes → the same hash*. Re-emissions are therefore
**dedup-able by content** everywhere.

The catch is the word *outlives*. A volatile courier reaps the instant it ships (Watches
`shipped@SELF` → `Reap`), leaving no trace:

```
cadence fires → bytes B, hash H(B) → shipped → REAP (body evicted, no trace)
   ... next period ...
cadence fires → recomputes the SAME B → without a memory of H(B), it re-ships.
```

So dedup is whatever holds *"I already sent H(B) to P"* **across the frame's own reaping**.
That memory is:

- **bounded for the round/opener** (one hash) → it *fits in a fact slice*;
- **O(n) for the shipped leaves** → it does *not* fit in a fact (see the two walls below).

This is the whole fault line: bounded round-lifecycle memory can be fact-native; unbounded
per-fid wire memory cannot.

## What is built: memory 1 — the opener self-limits in the cadence fact

(`origin/fact-native-sync`, commit `5f2925a`.)

`sync.cadence` is a long-lived fact (one per connection/tier), so it can hold its own memory
in a slice. `cadence.project` now:

- keeps its last-shipped root-compare hash in a slice keyed `(b"sent", cid, floor)`;
- re-opens a round **only when its domain split actually moved** since the last ship
  (compare `H(bytes)` to the slice) — otherwise it stays **idempotently silent**;
- carries both the tick and sent slices forward on *every* branch. This matters: the clock
  (`now_need` is an unbounded deadline watch) wakes the fact every turn, and a promote
  clears the fact's own slices — so the old not-due branch dropped the tick slice and
  re-fired the opener *each turn*, which the daemon dedup then had to absorb. With the
  slices preserved the fact fires **at most once per period** and only on real movement.

This is requirement 3 for the *round* memory: round timing now lives in a fact, exactly as
"the first compare, persisted as a memory of round."

## Measured: round timing is the load-bearing piece

Fresh-peer catch-up, source wire bytes, memory-1 in place, daemon dedup toggled off vs on:

| n | memory-1 **+ daemon dedup** | memory-1 **alone** |
|---|---|---|
| 8k | 3.92 MiB | 3.93 MiB |
| 16k | — | 8.40 MiB |
| 32k | — | 12.69 MiB |
| 64k | **39.16 MiB (deterministic)** | **39.19 / 71.04 / 72.17 MiB (3 trials)** |

Two conclusions:

- **Memory-1 alone already satisfies requirement 2.** Dropping the daemon dedup is O(n) with
  a *constant-factor* cost, not O(n²) — the opener self-limit is what kills the quadratic
  re-descend explosion. So *round timing* was the load-bearing fact-native concern.
- **The daemon dedup's remaining value is a constant factor + determinism.** With it, the
  wire is a tight ~39 MiB every run. Without it, the wire is timing-dependent (39–72 MiB):
  best case matches when answers land before the next re-descend, worst case ~1.8× when
  re-descends outrun answers. Its value is a *worst-case bound*, not average bytes.

So requirement 2 is really "kill the O(n²)" (done, by facts) plus an optional "bound the
constant factor and remove timing variance" (memories 2/3).

## Options for memories 2/3 (in-flight / shipped)

| option | what it is | cost / risk |
|---|---|---|
| **A. Role split** (keep the daemon `sent` set) | Facts own the round lifecycle (memory-1); the daemon owns per-session wire dedup as transport state. | Lowest, data-backed. The `sent` set is ~10 lines and deterministic. |
| **B. Adaptive cadence backoff** | The asker's cadence lengthens its period while a catch-up is in flight (its split is still moving fast), so answers land before the next re-descend → fewer re-asks/re-ships. Fact-native, slice-based, **no new family, no per-fid state**. Attacks the re-ship *race* directly instead of remembering the sends. | Medium — a timing knob to tune, but far less state than a per-fid map. |
| **C. Host-authored in-flight tracker** | The daemon admits a tiny tracking fact per ship; a `sync.inflight` fact re-checks on the clock and suppresses re-asks. "Everything is a fact," all the way. | High — daemon logic in a fact costume, O(n) admits, and clock/TTL timing (the shape that has gone unstable before). Likely matches at best. |

## Ruled out — with the exact kernel fact each dies on

- **Persist-until-converged compares** (a diverging compare stays resident and idempotent
  until it re-projects to converged) — *no convergence wake*: nothing re-wakes a compare when
  the set fills, so it can never detect convergence to reap → residue → fails the no-residue
  invariant (`test_sync.py:116`).
- **Pure-fact asker-side `sync.pending` marker** — *projectors can't author facts*: only the
  host observes the wire, so a projector cannot record "I asked for R."
- **Reify the `sent` set as a fact** (`sync.shipped(cid)` accumulating shipped ids) — *slices
  can't accumulate*: O(n) ids in a slice is O(n²) (cleared-and-replaced per promote); one
  fact per id is O(n) facts.
- **Round-lease** (prior attempt) — a volatile, TTL-timed lease on the opener re-fired on
  both peers; the *source* opened O(n) rounds. Superseded by memory-1 (content-addressed,
  keyed on the source's stable fp → one open, idempotent re-opens).
- **Receiver-admission dedup** (prior attempt) — deduping on the receiver leaves the source's
  bytes already spent; measured worse, and persisting compares broke the no-residue
  invariant. The dedup must be at the *send* boundary.

## The shape of the answer

> **Bounded round-lifecycle memory → a fact (the cadence slice). Unbounded per-fid wire
> memory → the daemon set.**

All sends are deterministic and all dedup-able by content; the split is purely about *how
much* memory each needs and whether a fact can afford to hold it. The opener can (one hash);
the O(n) shipped-leaf set cannot. Memory-1 moves the part that fits — round *timing* — into
facts, which is also the part that was carrying the O(n²). Whether to also chase the constant
factor decides between **A** (stop here; the daemon owns wire dedup) and **B** (make the
asker stop re-asking in-flight ranges, so the O(n) memory is never needed in the first
place).
