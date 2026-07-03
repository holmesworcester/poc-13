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
  dumb table). Everything else — validity, the clean twin, slices, the
  frontier — is derived and rebuilt by replay.
- Replay is demand-driven (hydration): a stepped fact's needs pull their
  cold matches resident; needs pull, offers never wake cold facts. Gating
  pulls are exhaustive; Watch pulls may carry a window and budget.
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

Signatures are detached facts (`auth.signature`): an ordinary fact offering
`b"pk"` (the signer's public key) and `b"sig"` at a target fact's id, carrying a
real Ed25519 signature. It self-checks at the admission gate over exactly the
32-byte target id — the id IS the whole canonical fact, so signing the id
covers everything, and wrong math is a falsy check: an inert miss, never a bad
fact. A signed fact Requires the `b"pk"` offer at its own id, so it only
validates once its signature lands — and the signer key is now in the
projector's context. The gate proves only that SOME key signed; binding that
key to workspace authority is a value-compare in the target's PROJECT (see
Authority). Verification runs exactly once, at first admission; replay loads
from the trusted durable file with the check skipped — those bytes passed
already. Tampering with the local file is a local-integrity problem, not a
protocol one: bytes from outside enter only through the gate.

## Authority

A signature proves a key signed a fact; authority proves that key was allowed
to. The `auth` families make membership a chain that every fact climbs, by
value-compare, to one root — closing the gap where any key could mint a member.

The root is a key, and the `auth.workspace` id is a pure function of its name so
it cannot carry one; `auth.founder` is the separate root fact. It declares the
founder pk (`b"root"`) and Requires its own signature by that same pk — you only
root a key you hold. `workspace.create` emits it alongside the workspace, so the
creator founds the space. (Pinning is trust-on-first-use: a keyless workspace id
can't forbid a rival `founder` fact, but a member validates only against a root
it sees, and legitimately-invited members chain to the founder whose key signed
their invite — a rival root roots only its own disjoint tree. This is the one
deliberate deviation from poc-10, where the workspace id embeds the founder key.)

The chain is one binding, applied per family: **the pk that signed a fact must
equal a pk the authority chain blessed.** Each fact Requires its own `b"pk"`
(who signed me) and Requires or Watches the offers that carry the blessed pk;
PROJECT intersects the two value sets and returns `Out("Invalid")` on no match —
a real refusal, distinct from parking on a not-yet-arrived signature.

- `auth.user_invite` blesses a fresh invite pk (`b"invite"` at its own id); valid
  iff signed by the founder root or an existing member key (`b"key"`, the
  rendezvous where every member offers its own key). The invite secret is the
  link, carried out-of-band.
- `auth.user` is membership *and* invite acceptance in one fact: it offers the
  member's own pk, and is valid iff its signer equals either the founder root
  (the founder self-joins) or the one invite it names by id (a joiner signs the
  membership with the invite key; the invite blessed that key). From then on the
  member signs with their own key, now a blessed `b"key"`.
- `auth.admin` grants admin to a named member; valid iff signed by the founder
  root (only the founder grants admin — the simplest honest rule).
- `auth.device_invite` / `auth.device` are the same two shapes for endpoints: a
  member blesses a device key; the device joins by signing with it.

Because each fact Requires its blesser, the sync closure ships the whole chain
with any fact it authorizes, and a peer re-derives every verdict itself.

## Extraction and Durability

Extraction is content-pure — `(durable, shareable)` from the fact's own
bytes only — decided at admission, never by validation, and routed through
the same router tree as projection. Durable facts flush before they can be
forgotten; volatile facts vanish on restart. Unknown tags default to
Durable + LocalOnly + Parked.

## Runtime State

Durable: the dumb table — sqlite `facts(fid, bytes)`, canonical fact bytes
and nothing else, no schema beyond id → bytes, no versioning. Its content is
exactly the durable fact set. Beside it, `atoms` is a derived match index
(one materialized offer row per atom, rebuildable from `facts`), and a TEMP
`hot` table is the session's delivered set — sqlite's TEMP scoping is the
durable/ephemeral boundary stated as schema.

Ephemeral, all rebuilt by replay: resident facts, the asserted match index
and intake overlay, the validity memo (`Unknown|Parked|Valid|Invalid|
Suppressed`), the validated offer set (the clean twin, rows stamped
`(owner, ts, atom)` with engine-stamped provenance), read-model slices
(last-write-wins by `(ts, owner)`), and the frontier.

Replay is the whole crash story: derived state is a pure, order-independent
function of the durable fact set. Storage loss shrinks the set — it costs
completeness, never coherence. Storage is outside the trust boundary;
bytes enter through checked loads, and wrong bytes are a miss.

With a `Store` — the durable index of cold facts (persisted, not resident)
under their materialized offer keys — replay is demand-driven (see
Hydration): a session admits nothing at boot and pays only for what its
facts and queries ask about. Full replay is the degenerate case.

When one process at a time stops being enough, `bin/cond.py` is a daemon
that owns the db exclusively and amortizes replay: it loads once, then runs
the three-phase host turn in a single-threaded select loop — client verbs
over a unix socket at `<db>.sock`, peers over TCP. The wire carries one
message type only, length-framed canonical fact bytes — mostly
`connection.frame` bundles; what to ship is decided by the sync family (see
Sync), driven from host out. Backpressure is the frontier's rule at the
socket — overflow parks, never drops: bounded admits per turn, a bounded
per-peer outbox whose overflow stays unsent until a later turn, and
select-gated non-blocking writes so a slow or absent peer never blocks the
loop. The daemon full-loads, deliberately: sync's fingerprints must cover
the whole durable set, so a partially-hydrated node must never initiate
compare rounds; a demand-driven daemon waits on the sync family knowing how
to ship from the store rather than from residency. Still deferrable:
compaction (purge is `DELETE`; `VACUUM` reclaims the bytes).

## Turn Semantics

A host turn has three phases.

**Host in.** Admission: strict-decode candidate bytes; recompute `FactId`
(reject on mismatch if requested by id); run extraction; early-return if
already admitted; otherwise store the fact, stamp its materialized atoms
into the intake overlay, put its id on the frontier, and flush if durable.
Failed gates are inert.

**Engine drain.** Drain the frontier to a bound (overflow parks, never
drops). For each owner: first, if a store is attached, pull each need's
cold matches resident through ordinary (checked) admission — hydration's
whole engine hook; then check suppressors, then requires, against the clean
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

`target_covers` is exact equality, a range offer covering an exact need
key byte-lexicographically (inclusive), or symmetrically a range need
covering an exact offer key — bulk demand is ordinary matching. Range never
matches range, and `SELF` never matches. The match index is bidirectional
(need→offer for dependencies, offer→need for wakes) and every query in both
directions runs over index ∪ intake — the overlay is transparent, and
flushing moves rows without changing any result.

## Hydration

One rule: **when a resident fact steps, each of its needs pulls its cold
matches resident, through ordinary checked admission**. Pulled facts land on
the frontier; when they step, their needs pull in turn — the frontier is the
spider, and residency grows to the demand fixpoint. The demanding fact parks
and wakes through normal fanout; there is no rehydrate path, and idempotent
admission is the visited set. Demand flows backward through needs only:
offers never wake cold facts (a fact that wants waking while cold is
standing demand — a family obligation to stay resident, a later wave).

Soundness fixes the asymmetry between effects. `Require` and `Suppress`
pulls are exhaustive — a missed offer could change a verdict (a cold
tombstone would resurrect its target). `Watch` pulls honor a window riding
in the need's value — `(ts_lo, ts_hi, budget, order)`, engine-owned bytes
never read by matching — because Watch never gates. Need values belong to
the engine: a source-contract test keeps every family SHAPE from
constructing a valued need (`store.hydrate` is the single exemption). Budget counts primary
hits in `(ts, FactId)` order; each hit's own pulls complete its validation
unit uncounted, so a delivered hit is never partial. Budget is an
amortization knob, never a semantic limit: the store pops delivered facts
(per-fact dedup), so paging — re-demand from the last delivered ts,
inclusive — reaches exactly the state one unbudgeted pull reaches.

Bulk demand is the `store.hydrate` family: a volatile fact with one Watch
need (typically a range target), authored by queries before they read.
Queries may author volatile demand and drain; they still never author
durable facts. A durable hydrate fact is a pin (later wave, with standing
demand). The store itself is outside the trust boundary — an untrusted
index; every pull re-enters through checked admission, so a wrong or
corrupt db row is a miss, never a wrong fact. It is sqlite: the pull is one
indexed SELECT whose WHERE clause is the atom coverage relation, and a
property test pins that clause to kernel `covers` (the spec) over random
target shapes. The remaining unification — the resident match rows
themselves in TEMP tables, one matcher for hot and cold — is open.

## Routing: Projectors Are the Routers

The kernel runs one root projector. A `Router` is a projector that
dispatches on the next type-tag segment and delegates whole; extraction
routes through the same tree, and so does the dotted api/CLI namespace
(`content.message.send` resolves through the same routes as the
`content.message` tag).
Routers narrow inputs and cannot widen a delegate's context; delegation
must equal the delegate run alone. Unknown tags fall out as
Durable + LocalOnly + Parked with no special casing.

## The Fact Contract

Every fact family is one file, `facts/<scope>/<fact>.py`, with six required
parts (plus an optional CHECK between EXTRACT and PROJECT), always in this
order, enforced by a source-contract test:

- **SHAPE** — constructors returning canonical `Fact`s. The only place
  atoms are chosen. This is the whole codec story: the kernel's one
  canonical encoding covers every family, so there are no per-family byte
  formats. A family that wants a private format inside a value is a signal
  the atom vocabulary is missing something.
- **EXTRACT** — content-pure `(durable, shareable)`.
- **CHECK** — optional, self-verification at the admission gate; pure
  function of the fact's own bytes; runs once, never on replay.
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

The module itself is the Python API — `facts.content.message.send(node, ...)` —
and scope `__init__.py` files are router-only tables of contents.

## The CLI

`bin/con.py`: `con <db> <scope.fact.verb> [args...]`. Resolve the verb path
through the root router, open the db cold, run the verb, flush new durable
facts in one transaction. Every invocation is a crash-and-demand — hydration
pulls only what the verb's facts and queries ask about — so black-box tests
exercise the demand-driven replay story constantly and for free.

If a daemon owns the db, con proxies instead of replaying: `<db>.sock`
accepts, the verb path and args go out as one framed request, one framed
`+ok`/`-err` reply comes back (new durable facts hit the file before the
reply). Otherwise the crash-and-replay path is unchanged — the daemon only
amortizes it.

## Sync

Sync reconciles facts, never atoms, and lives entirely in `facts/sync/` — no
kernel change. A leaf is `(ts, FactId) -> H(FactId ‖ ts ‖ H(bytes))` for every
fact that is durable, shareable, and `Valid|Suppressed`; suppressed facts stay
in the set, which is how deletions reconcile. A range fingerprint is the hash
of its leaf-hashes plus a count, so rebuilding it from the durable set is
order-independent. Reconciliation is a compare over half-open `[lo, hi)` ranges
of the composite key `ts‖FactId`: a range whose fingerprints match emits
nothing; a small range (≤4 keys on the sender's side) is sent as a complete
leaf list; any larger mismatch splits at the item-count median and recurses. A
one-fact difference over a hundred facts settles in a logarithmic number of
compare frames, not a push-all scan.

Shipping is dependency-aware: when an id must travel it goes with its
`closure` — the backward Require ancestors plus the suppressors of everything
in the closure (and theirs), transitively. So a tombstone rides along with the
fact it kills and the fact arrives already Suppressed: no resurrection window.
The receiver admits every shipped frame through the normal gate (the
replay-only `checked` path is never used for peer input).

The split of labor is crisp. `leaves`, the range fingerprint, `closure`, and
`answer_of` (an admitted peer compare's answer: sub-range compares, `want`
pulls, and the closure ship list) are QUERIES — pure reads of the engine,
authority for nothing. The send side is the `sync.reply` family: a reply fact
carries the answer's compare frame as a `send` offer and its shipments as
by-reference `ship` offers (fact ids, resolved against the durable set at
send time) at the host-watched outbox keys; when the daemon reports the flush
(`shipped@SELF`, see The Clock) the reply reaps, leaving no residue — even
sync's own frames ride the one send path. A compare
frame crossing the wire IS a fact — the transport keeps its single message
type. Compare and reply facts extract to `(False, False)`: volatile, so replay
never resurrects session state, and unshareable, so they are excluded from the
very leaves they reconcile.

Sync is roundless (poc-10's `maintain_sync` model): there is no round or
session state anywhere. The daemon sends a fresh root compare to each live
peer on a process-local cadence — damped while that peer's own compares are
mid-flight, and deferred while the frontier is still draining, so a receiver
mid-catch-up stops churning the sender with a new compare every turn. A lost
frame needs no retry bookkeeping; the next cadence compare repairs it.
Freshness does not wait for the cadence: at quiescence, leaves that newly
entered the set ride a live-tail reply straight to every peer except the one
they arrived from (measured on bench 5c, a fresh message against a 5000-fact
backlog: ~3.6s riding the reconcile, ~0.7s tailed). Every peer link is
full-duplex, and reconciliation is what a fact authored on one side rides to
reach the others.

## Connections

Peer sessions are facts too — the transport is a fact family, not an engine
primitive — living in `facts/connection/`. There is no kernel change.

**Sessions as facts.** A `connection.request` (durable, LocalOnly) names an
address to dial; the daemon watches its valid `peer` offers and dials each, and
recurrence is liveness — a dropped socket redials while the request stays valid.
A `connection.close` suppresses a request through the death key the request
carries, so a closed peer stays closed across restart; both are LocalOnly because
a node's dial list is its own config, never a fact to sync. `--peer` flags are
bootstrap sugar: the daemon authors one request each, through the normal gate, at
startup. A `connection.connection` (volatile, LocalOnly) is the daemon's record
of a live peer, authored host-out from a verified hello, and dies with the process.

**Hello binds a session to an identity key.** On connect each side ships a
`connection.hello`: its identity public key, advertised listen address, a coarse
time bucket, and an Ed25519 signature over `H(pk ‖ addr ‖ bucket)`, verified once
at the admission gate (CHECK), so a tampered hello is an inert miss. It proves the
sender holds the private key for `pk` and binds that key to the address for the
signed epoch. The honest limits, stated plainly: stdlib has no DH or encryption,
so confidentiality and forward secrecy are out of scope, and there is no session
nonce — a captured hello is replayable, and the daemon does not gate on the bucket
(a freshness window would be a one-line receiver check). Trust on first use: the
receiver records the peer key; whether it is a workspace-authorized member/device
key is a query-side value-compare (the `auth` column of
`connection.connection.peers`), never a hard Require — two fresh nodes still talk,
matching Authority's stance.

**Frame bundles are ephemeral transport.** A `connection.frame` bundle is
volatile and unshareable exactly like a sync compare — never stored, never in
leaves, excluded from the reconciliation it carries. Its one value packs many
length-framed canonical fact bytes; the sync driver's shipments ride bundles (a
few KiB each) instead of one fact per wire frame. A receiver unpacks a bundle and
admits each inner fact through the normal gate, a bounded batch per turn — a
corrupt inner is a per-fact miss that never poisons its siblings, and the wrapper
itself is never admitted. Bundling, paired with the deferred-round rule above,
turns a bulk catch-up from hundreds of leaf-rescanning compare rounds into a
handful: on the measured 5000-fact catch-up it is roughly a 10x lift in both
facts/s and MB/s.

## The Clock and the Flush Report

Time is not a fact family: it is the one input the host reads from the OS and
hands to the turn. `kernel.turn(now)` presents `now` as a single transient
offer at the NOW key; a time-waiting fact carries a Watch need over
[deadline, ∞) (`now_need`), and when now reaches its deadline the offer falls
in range and wakes it. There are no tick facts, so nothing accumulates;
matching stays ordinary (a plain Range need over a plain offer); and durable
derived state never depends on `now`, so replay with any `now` rebuilds it
identically. The daemon just reads the clock each loop and passes it to the
turn — it never sleeps *for* a deadline, because a time-need that comes due
while it is blocked in `select()` is simply serviced on the next wake.

The flush report is the clock's sibling — the other host signal handed to the
turn. Just as the host hands in `now`, it hands back the ids of the
host-watched offers it flushed to the socket: `kernel.turn(now, shipped)`
presents each as a transient offer at the SHIPPED key, waking any sender that
Watches `shipped@SELF`. A one-shot sender (an `outbox.send`, a `sync.reply`)
answers by returning the terminal **Reap** verdict, on which the engine evicts
the fact whole — offers, memo, and match rows — so a busy session leaves no
drained-send residue. Reap is the only verdict that *removes* a fact (Suppress
merely neutralizes and keeps a tombstone); it is safe precisely because these
senders are volatile and host-watched, so nothing gates on their offers — an
invariant the engine asserts before evicting. The daemon re-presents an
unacked `shipped` until its sender acts (a bounded drain never drops the
report) and drives no retirement itself: the policy — reap, or re-arm a retry
— lives in the family, never in the pump. Persistence is the same shape
inverted: the host's other completion set, `flushed`, tracks which durable
facts have reached the db, but a durable fact must *survive*, so it is written
by `con.flush` and never reaped.

Recurrence is central but the onus is on one party: everything that must
happen repeats, and the repeating side drives it. The initiator's durable
request re-dials on a process-local cadence; the responder answers each
arrival with no cadence of its own. Sync compares repeat the same way. This
operational repetition — which peer to talk to, and how often — stays
process-local in the daemon (as poc-10 keeps it); the facts carry only policy
(what to offer, when to stop), never socket schedules.

## Family Specs Not Yet Implemented

These are protocol, specified fully in the poc-12 design; they land as fact
families without kernel changes:

- **Content** — descriptor/outboard/chunk facts with
  `chunk -> outboard -> descriptor -> anchor` arrows; anchors never require
  chunks; validity is public over ciphertext; the tree shares the
  descriptor's death keys.
- **Retention and purge** — timestamp order alone never purges: pins,
  retained closures, and live suppressor targets all hold facts; purge is
  `DELETE` over the db, and `VACUUM` reclaims space.
- **Drivers** — local input as a host-authored fact family; the event source
  reading the OS is outside the boundary. (The connection driver is built —
  see Connections; time is a turn primitive — see The Clock.)

## Testing

Tests replace theorems by mirroring their quantifiers: where the poc-12
proof says "for all fact streams," a test shuffles admission orders and
asserts bit-identical derived state; where it says "for all bytes," a test
feeds mutated frames and asserts misses, never wrong validations. The
source-contract test keeps every fact file in the six-part shape. Black-box
tests drive `bin/con.py` end to end, one process per command, hydrating
from the db every time. Hydration tests assert the demand theorem:
every resident fact's verdict equals full replay's, under shuffled file
orders, with and without budgets.
