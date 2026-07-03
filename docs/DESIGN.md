# The Atom Model — poc-13 Design

This document describes the protocol. It descends from poc-12's design of
record (`~/poc-12/docs/DESIGN.md`), where the semantics were proven in
Rust/Verus. poc-13 changes the goal, not the protocol: conciseness over
proofs, tests over theorems, and a fact contract that closes the gap between
the kernel and real commands, queries, and a CLI. Where a protocol question
isn't answered here, the poc-12 document is the reference; where the two
disagree on poc-13 structure, this document wins.

The central idea is unchanged: facts are the unit of identity and sync,
atoms are the unit of matching, and the needs/offers language IS the fact
language.

## Key Points

- A fact is a canonical atom set plus a type tag. `FactId` names that
  complete canonical object; an atom alone has no identity.
- Atoms are asserted until their owner fact validates. Asserted atoms are
  dirty discovery data; only validated offers justify projection state,
  effects, or another fact's validity.
- The runtime has one durable authority: the flushed canonical facts (the
  dumb file). Everything else — validity, the clean twin, slices, the
  frontier — is derived and rebuilt by replay.
- Needs have three effects: `require` gates validity, `watch` only
  wakes/reprojects, `suppress` flips the owner to Suppressed. Precedence:
  Suppress > Require(Park) > Resolve.
- Admission is idempotent and content-addressed; wrong bytes are a miss,
  never a wrong fact.
- Queues, effects, sync, clocks, content, and retention are fact families,
  not engine primitives. The kernel owns identity, admission, matching, and
  the turn loop — nothing else.
- Projectors ARE the routers: the kernel runs one root projector, and a
  router is just a projector that dispatches on type-tag segments.
- Every fact family is one file with one fixed six-part contract: SHAPE,
  EXTRACT, PROJECT, COMMANDS, QUERIES, CLI.

## Canonical Data

### Atom

```text
Atom { kind: Need|Offer, effect: None|Require|Watch|Suppress,
       role, scope, target: Exact(bytes)|SELF|Range{lo,hi}, value? }
```

`effect` is meaningful only on needs and must be `None` on offers. `role`,
`scope`, and `target` form the match address; `value` is not read by core
matching. Values are small; large payloads are content facts.

`SELF` means "this fact's eventual `FactId`" and is legal only in canonical
fact atoms — the stored fact keeps `SELF` so identity never contains its own
hash. Every derived row materializes: `SELF` is rewritten to the owner id
wherever core derives rows from canonical atoms. `SELF` never participates
in matching directly.

Atoms are embedded in their fact — there is no shared atom table, because an
atom alone has no identity and a table would mint one. Structural sharing in
memory (derived rows referencing the fact's frozen atoms) is an
implementation detail, as would be any future interning cache.

### Fact and Identity

A fact is a type tag plus a strictly increasing, duplicate-free sequence of
atoms, ordered byte-lexicographically on the canonical atom encoding.

`‖` means length-framed concatenation (each field prefixed with its 4-byte
LE length). Each atom contributes its own framed canonical byte form.

```text
FactId = H("poc13.fact.v1" ‖ type_tag ‖ atoms)
```

`H` is 32-byte BLAKE2b standing in for BLAKE3-256. The encoding is one fixed
self-delimiting byte form, version-free forever; the domain string is the
only dialect marker. Strict decode rejects malformed encodings, unsorted or
duplicate atoms, and trailing bytes — anything that does not re-encode
byte-identically.

A fact never embeds its own `FactId`. Hash references in values or targets
must name already-existing facts, so the hash-reference graph is acyclic by
construction.

Every durable/shareable fact carries one canonical timestamp atom
`Offer(role="ts", scope=family_scope, target=SELF, value=u64le)` — the
reconciliation sort key and a retention input, never an authority proof.
A fact without one promotes rows at `ts = 0`.

Signatures are specified in the poc-12 design (embedded sig atoms verified
at admission; detached signatures as ordinary facts) and are not yet in this
kernel; the admission gate is where the embedded check will land.

## Extraction and Durability

Extraction is content-pure — `(durable, shareable)` from the fact's own
bytes only — decided at admission, never by validation, and routed through
the same router tree as projection. Durable facts flush before they can be
forgotten; volatile facts vanish on restart. Unknown tags default to
Durable + LocalOnly + Parked.

## Runtime State

Durable: the dumb file — length-framed canonical fact bytes, append-only,
no schema, no versioning. Its content is exactly the durable fact set.

Ephemeral, all rebuilt by replay: resident facts, the asserted match index
and intake overlay, the validity memo (`Unknown|Parked|Valid|Invalid|
Suppressed`), the validated offer set (the clean twin, rows stamped
`(owner, ts, atom)` with engine-stamped provenance), read-model slices
(last-write-wins by `(ts, owner)`), and the frontier.

Replay is the whole crash story: derived state is a pure, order-independent
function of the durable fact set. Storage loss shrinks the set — it costs
completeness, never coherence. Storage is outside the trust boundary;
bytes enter through checked loads, and wrong bytes are a miss.

When the dumb file stops being enough, the upgrades are independent and
deferrable, and none change the kernel or the file's meaning: a daemon to
amortize replay, compaction to reclaim purged facts (rewrite the file from
the surviving durable set), and a real durable index (e.g. SQLite as an
untrusted cache) when facts outgrow RAM.

## Turn Semantics

A host turn has three phases.

**Host in.** Admission: strict-decode candidate bytes; recompute `FactId`
(reject on mismatch if requested by id); run extraction; early-return if
already admitted; otherwise store the fact, stamp its materialized atoms
into the intake overlay, put its id on the frontier, and flush if durable.
Failed gates are inert.

**Engine drain.** Drain the frontier to a bound (overflow parks, never
drops). For each owner: check suppressors, then requires, against the clean
twin; build `Context<Validated>` from matching validated offers; call the
routed projector `project(fact, ctx, slice) -> Out(verdict, offers,
slice_delta)`; replace the owner's prior output atomically (owner-scoped:
never both old and new visible); restamp promoted offers with engine
provenance regardless of projector claims; wake every owner whose needs
match a changed offer, over index ∪ intake.

**Host out.** The host drains validated offers at keys it watches, performs
external work, and admits facts reporting what happened. Host code never
mutates validated state.

## Need Effects

**Require** — positive dependency. No valid matching offer: the owner is
Parked (keeps asserted atoms, wakes later, promotes nothing). **Watch** —
non-blocking subscription: never gates validity, only reprojects when
matching valid offers appear or change; queues and recurring work live
here. **Suppress** — negative dependency: a valid matching offer flips the
owner to Suppressed and its output is removed by owner-scoped replacement;
durable asserted atoms remain until retention purges the fact.

Precedence: Suppress > Require(Park) > Resolve.

Stratification is a family obligation: `Require` edges are positive,
`Suppress` edges negative, `Watch` edges don't participate; a fact may not
depend on its own validity through any path containing a negative edge. A
family that could create such a cycle must reject the shape or define a
local total-order break.

Suppression closure is family discipline too: every fact that must die with
a target carries the target's death keys directly (as `Suppress` needs).
There is no consumer demotion cascade.

## Matching

```text
need.role == offer.role  ∧  need.scope == offer.scope
∧  target_covers(offer.target, need.target)
```

`target_covers` is exact equality, or a range offer covering an exact need
key byte-lexicographically (inclusive). Needs are exact in the kernel. The
match index is bidirectional (need→offer for dependencies, offer→need for
wakes) and every query in both directions runs over index ∪ intake — the
overlay is transparent, and flushing moves rows without changing any
result.

## Routing: Projectors Are the Routers

The kernel runs one root projector. A `Router` is a projector that
dispatches on the next type-tag segment and delegates whole; extraction
routes through the same tree, and so does the dotted api/CLI namespace
(`chat.note.send` resolves through the same routes as the `chat.note` tag).
Routers narrow inputs and cannot widen a delegate's context; delegation
must equal the delegate run alone. Unknown tags fall out as
Durable + LocalOnly + Parked with no special casing.

## The Fact Contract

Every fact family is one file, `facts/<scope>/<fact>.py`, with six parts,
always in this order, enforced by a source-contract test:

- **SHAPE** — constructors returning canonical `Fact`s. The only place
  atoms are chosen. This is the whole codec story: the kernel's one
  canonical encoding covers every family, so there are no per-family byte
  formats. A family that wants a private format inside a value is a signal
  the atom vocabulary is missing something.
- **EXTRACT** — content-pure `(durable, shareable)`.
- **PROJECT** — the only place the family's meaning lives: validity,
  promoted offers, slice deltas. Pure function of `(fact, ctx, slice)`;
  never touches the node.
- **COMMANDS** — local authoring: `(node, params) -> fact id`. Build a
  fact, admit it, stop. Commands may call queries to choose parameters and
  write only through admission. Anything multi-step or retryable is more
  facts (the outbox pattern), not a fancier command.
- **QUERIES** — observations: `(node, params) -> data`, read only from
  validated state (the clean twin, slices, watched keys) — never asserted
  rows, never authority for anything.
- **CLI** — the string boundary: a `CLI = {verb: fn}` dict mapping names to
  thin wrappers over COMMANDS/QUERIES that coerce strings in and out.
  Exposure is deliberate; verbs, not helpers.

The module itself is the Python API — `facts.chat.note.send(node, ...)` —
and scope `__init__.py` files are router-only tables of contents.

## The CLI

`bin/con.py`: `con <db> <scope.fact.verb> [args...]`. Resolve the verb path
through the root router, replay the dumb file, run the verb, append new
durable facts. Every invocation is a crash-and-replay, so black-box tests
exercise the replay story constantly and for free.

## Family Specs Not Yet Implemented

These are protocol, specified fully in the poc-12 design; they land as fact
families without kernel changes (hydration adds one engine-answered need):

- **Hydration** — explicit demand over the durable index in `(ts, FactId)`
  order, budgeted by primary hit; a delivered hit is never partial — it
  carries its full validation unit (backward Require closure plus valid or
  candidate suppressors and their closures).
- **Content** — descriptor/outboard/chunk facts with
  `chunk -> outboard -> descriptor -> anchor` arrows; anchors never require
  chunks; validity is public over ciphertext; the tree shares the
  descriptor's death keys.
- **Sync** — reconciles facts, never atoms; range-fingerprint compare over
  `(ts, FactId)` leaves of validated|suppressed, shareable, durable facts;
  dep-aware shipping so suppressors travel (no resurrection); sync's own
  facts are LocalOnly and excluded from their own reconciliation set.
- **Retention and purge** — timestamp order alone never purges: pins,
  retained closures, and live suppressor targets all hold facts; purge plus
  dumb-file compaction reclaims space.
- **Drivers** — clock, connection, local input as host-authored fact
  families; the event source reading the OS is outside the boundary.

## Testing

Tests replace theorems by mirroring their quantifiers: where the poc-12
proof says "for all fact streams," a test shuffles admission orders and
asserts bit-identical derived state; where it says "for all bytes," a test
feeds mutated frames and asserts misses, never wrong validations. The
source-contract test keeps every fact file in the six-part shape. Black-box
tests drive `bin/con.py` end to end, one process per command, replaying the
dumb file every time.
