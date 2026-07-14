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

The document is in two parts. **Part I is the kernel** — identity, admission,
matching, the turn loop, and the host surfaces around them. **Part II is
fact-level design** — the families that make the protocol (authority, sync,
connections, and the rest). The kernel gives every family the same machine;
a family is replaceable without a kernel change, and that boundary is the
design.

## Key Points

- A fact is a canonical atom set plus a type tag. `FactId` names that
  complete canonical object; an atom alone has no identity.
- Atoms are asserted until their owner fact validates. Asserted atoms are
  dirty discovery data; only validated offers justify projection state,
  effects, or another fact's validity.
- The runtime has one durable authority: the persisted atom relation (one
  row per atom of every durable fact; canonical bytes are derived, never
  stored). Everything else — validity, the clean twin, the frontier —
  is derived and rebuilt on demand.
- Matching looks to the persisted relation: when a resident fact steps,
  each of its need keys is checked once against the store and the cold
  owners fault in through ordinary admission — needs fault, offers never
  wake cold facts. Boot is the degenerate demand: one total hydrate fact.
- The store answers existence, never standing: it can say who offers at a
  key and hand back reconstructed bytes; verdicts are computed only in the
  engine, over the resident set. Standing is never persisted; intrinsic
  validity (signatures, canonical form) is persisted exactly once — as
  existence in the store, transferred on read by the re-hash.
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

# Part I — The Kernel

## Canonical Data

### Atom

```text
Atom { kind: Need|Offer, effect: None|Require|Watch|Suppress,
       role, scope, target: Exact(bytes)|SELF|Range{lo,hi}, value? }
       # wire grammar; in memory a target is a span (lo, hi) — a point is
       # lo == hi — and SELF until materialization rewrites it to the owner
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

`H` is BLAKE3-256 (32 bytes, via the `blake3` package). The encoding is one fixed
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

## Extraction and Durability

Extraction is content-pure — `(durable, shareable)` from the fact's own
bytes only — decided at admission, never by validation, and routed through
the same router tree as projection. Durable facts flush before they can be
forgotten; volatile facts vanish on restart. Unknown tags default to
Durable + LocalOnly + Parked.

## Runtime State

Durable: the persisted atom relation — sqlite `atoms`, one row per atom of
every durable fact (both kinds, canonical columns plus match columns
materialized with SELF rewritten to the owner id), beside a two-column
`facts(fid, tag)` spine. There is no bytes column: a read regroups a fid's
rows, rebuilds, re-encodes, and re-hashes, so rows that no longer add up to
their fid are a miss, never a wrong fact. One write door (`add`, downstream
of admission) makes existence the persisted certificate: intrinsic checks
ran once at first admission, and the re-hash transfers them, so a faulted
fact re-enters checked and a boot re-verifies nothing.

Ephemeral, all rebuilt by replay: resident facts, the asserted match index
and intake overlay, the validity memo (`Unknown|Parked|Valid|Invalid|
Suppressed`), the validated offer set (the clean twin, rows stamped
`(owner, ts, atom)` with engine-stamped provenance), the frontier, and the
sync leaf set with its skeleton (see Sync). A family that needs a register
(last-write-wins, a timer's memory) reads it off its own validated offers —
there is no second read-model.

The crash story is one fact: derived state is a pure, order-independent
function of the durable set, and a fresh node over the same store rebuilds
it by admitting a single total hydrate demand. There is no load and no
replay path. Storage loss shrinks the set — it costs completeness, never
coherence. Storage is outside the trust boundary; faulted bytes re-enter
through checked admission, and wrong rows are a miss.

With a `Store` attached, a session admits nothing at boot and pays only for
what its facts and queries ask about (see Hydration); the total demand is
the degenerate case that faults everything.

When one process at a time stops being enough, `bin/cond.py` is a daemon
that owns the db exclusively and boots COLD: it loads nothing and decides
no residency policy. Residency is demanded — a verb's queries fault their
keys, and hydration at any scale is a client verb (`store.hydrate.pull`
with no key faults everything: the operator's first verb on a full
replica). It runs
the three-phase host turn in a single-threaded select loop — client verbs
over a unix socket at `<db>.sock`, peers over TCP. Its reusable core is
`bin/runtime.py`, a socket-free seam: `cycle` admits an inbox of fact bytes
and drains one bounded turn presenting the wire's flush reports; `pump`
groups the validated `send`/`ship` offers by owner, resolves each route and
its ship-ids, and hands the frames to a `deliver` callback. The wire's only
payload is length-framed canonical fact bytes under a one-byte discriminator:
a bare handshake fact before a session key exists, a sealed `connection.frame`
after. There is **one out door** — the daemon reads the outbox offers and
`deliver` seals iff the route yields a session secret, else sends bare — so
the handshake response and a sync frame leave the same way. It authors nothing
outbound. The outbound path tolerates loss up until the receiver admits: a
frame is fired best-effort when handed to the socket buffer (bounded admits
per turn, select-gated non-blocking writes), and a dropped or truncated frame
is healed by the next cadence re-descend, never mis-admitted (it fails
`aead_open`). Sync reconciles the RESIDENT set, and the daemon never decides coverage:
the operator's total pull makes RBSR fingerprints cover the whole durable
set; a partially-hydrated node reconciles only what it holds resident
(coverage-clipped claims over partial replicas are a later wave). Still deferrable:
compaction (purge is `DELETE`; `VACUUM` reclaims the bytes).

## Turn Semantics

A host turn has three phases.

**Host in.** Admission: strict-decode candidate bytes; recompute `FactId`
(reject on mismatch if requested by id); early-return if already admitted;
otherwise run the CHECK gate and extraction, store the fact, stamp its
materialized atoms into the intake overlay, put its id on the frontier, and
flush if durable. Failed gates are inert.

**Engine drain.** Drain the frontier to a bound (overflow parks, never
drops). For each owner: first, if a store is attached, the fault leg checks each
of its need keys once against the persisted relation and admits the cold
owners (checked admission — the bytes passed the gate once); then check
suppressors, then requires, against the clean twin; build `Context<Validated>` from matching validated offers; call the
routed projector `project(fact, ctx) -> Out(verdict, offers)`; replace
the owner's prior output atomically (owner-scoped:
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
owner to Suppressed, its output is removed by owner-scoped replacement, and
the verdict is terminal: the kernel purges the fact whole — resident body,
asserted rows, durable bytes on disk. Deletion is immediate and real. What
suppression keeps is the RELATIONSHIP, never the husk: the suppressor and
the death key it matches are durable facts, so a purged fact that re-arrives
(a laggard peer re-ships it) re-derives Suppressed and dies on arrival.

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

One rule: **when a resident fact steps, each of its need keys is checked
once against the persisted relation, and every cold owner offering at that
key is admitted** (the fault leg). Faulted facts land on the frontier; when
they step, their needs fault in turn — the step loop is the spider, and
residency grows to the demand fixpoint. All three effects fault alike:
`Require` finds its dependency, `Suppress` finds its tombstone (absence is
only ever trusted after the key is checked — a cold suppressor bites on its
target's own step, never waiting for the right demand), `Watch` finds its
subjects. Verdicts are exact at quiescence; a fact may transiently judge
before its faults land and is re-woken by normal fanout, exactly as a
late-arriving wire fact re-judges it. Demand flows backward through needs
only: offers never wake cold facts (a fact that wants waking while cold is
standing demand — a pin, a later wave).

The per-key check is memoized (`Node.checked`), and the memo never goes
stale because existence is monotone: rows enter the store only downstream
of admission (flush), so a new row's owner is already resident. The one
reserved key `\x00all` — the total demand — is read by the store as "every
fact you hold"; once it is checked, faulting is over for the session, since
nothing cold can appear behind it. The only mutation that breaks
monotonicity is `delete` + re-add (repair, purge): the caller's discipline
is `Node.refault()` — forget the memos, re-step every resident fact.

The store is outside the trust boundary — every faulted fact re-enters
through admission, its bytes re-derived from rows and re-hashed against the
fid it claims, so a wrong or corrupt row is a miss, never a wrong fact.
Matching-side it is two indexed SELECTs: `owners(need)` (whose WHERE clause
is the atom coverage relation, property-pinned to kernel `covers`) and
`fact_bytes(fid)`. Windows, budgets, and delivery order died with the store
spider: a demand is a key, drained whole; bounded working sets come from
demanding bounded keys.

## Routing: Projectors Are the Routers

The kernel runs one root projector. A `Router` is a projector that
dispatches on the next type-tag segment and delegates whole; extraction
routes through the same tree, and so does the dotted api/CLI namespace
(`content.message.send` resolves through the same routes as the
`content.message` tag).
Routers narrow inputs and cannot widen a delegate's context; delegation
must equal the delegate run alone. Unknown tags fall out as
Durable + LocalOnly + Parked with no special casing.

## The Clock and the Flush Report

Time is not a fact family: it is the one input the host reads from the OS and
hands to the turn. `kernel.turn(now)` presents `now` as a single transient
offer at the NOW key; a time-waiting fact carries a Watch need over
[deadline, ∞) (`now_need`), and when now reaches its deadline the offer falls
in range and wakes it. There are no tick facts, so nothing accumulates;
matching stays ordinary (a plain Range need over a plain offer); and durable
derived state never depends on `now`, so a reboot at any `now` rebuilds it
identically. The daemon reads the clock each loop and passes it to the turn;
a `wake@clock` alarm — a cadence fact's next boundary — sets its `select`
timeout via `runtime.next_wake`, so it sleeps exactly until the earliest
deadline and services a due time-need on that wake.

The flush report is the clock's sibling — the other host signal handed to the
turn. Just as the host hands in `now`, it hands back the ids of the
host-watched offers it flushed to the socket: `kernel.turn(now, shipped)`
presents each as a transient offer at the SHIPPED key, waking any sender that
Watches `shipped@SELF`. A one-shot sender (an `outbox.send`, a `sync.need`)
answers by returning the terminal **Reap** verdict, on which the engine evicts
the fact whole — offers, memo, and match rows — so a busy session leaves no
drained-send residue. Reap and Suppressed are both terminal evictions; they
differ in cause and guard. Reap is family-chosen with no durable cause, so it
is safe only leafward — nothing may gate on the reaped offers, an invariant
the engine asserts before evicting. Suppression is kernel-derived from a
durable edge, so it is deliberately unguarded: withdrawing offers others gate
on is the point (dependents park, or die by their own death key), and the
verdict re-derives on any re-arrival because its cause outlives the fact. The daemon re-presents an
unacked `shipped` until its sender acts (a bounded drain never drops the
report) and drives no retirement itself: the policy — reap, or re-arm a retry
— lives in the family, never in the pump. Persistence is the same shape
inverted: the host's other completion set, `flushed`, tracks which durable
facts have reached the db, but a durable fact must *survive*, so it is written
by `con.flush` and never reaped.

Recurrence is central but the onus is on one party: everything that must
happen repeats, and the repeating side drives it. Sync's periodic re-descend
is a `sync.cadence` fact (see Sync) — its `wake@clock` alarm drives the
schedule, not a daemon marker. The initiator's durable request still re-dials
on a process-local cadence, and the responder answers each arrival with no
cadence of its own; that socket-level redial backoff — which address to dial,
and how often — stays process-local in the daemon (as poc-10 keeps it), the
one operational repetition the facts do not carry.

## The CLI

`bin/con.py`: `con <db> <scope.fact.verb> [args...]`. It is a thin client:
resolve nothing locally, just proxy to the daemon that owns the db. `<db>.sock`
accepts, the verb path and args go out as one framed request, one framed
`+ok`/`-err` reply comes back (new durable facts hit the file before the
reply). With no daemon reachable it exits with a message — the daemon is the
only writer, which keeps the single-owner story simple (the earlier cold
crash-and-demand path is gone). The daemon boots cold; a verb's queries
demand the keys they read, and after an operator's `store.hydrate.pull`
every later demand is a no-op behind the checked total.

# Part II — Fact Families

Everything below is fact-level design: families under `facts/<scope>/`, one
file each, built on Part I. The contract comes first because it is the
boundary the kernel holds every family to.

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
- **PROJECT** — the only place the family's meaning lives: validity and
  promoted offers. Pure function of `(fact, ctx)`; never touches the node.
- **COMMANDS** — local authoring: `(node, params) -> fact id`. Build a
  fact, admit it, stop. Commands may call queries to choose parameters and
  write only through admission. Anything multi-step or retryable is more
  facts (the outbox pattern), not a fancier command.
- **QUERIES** — observations: `(node, params) -> data`, read only from
  validated state (the clean twin, watched keys) — never asserted
  rows, never authority for anything.
- **CLI** — the string boundary: a `CLI = {verb: fn}` dict mapping names to
  thin wrappers over COMMANDS/QUERIES that coerce strings in and out.
  Exposure is deliberate; verbs, not helpers.

The module itself is the Python API — `facts.content.message.send(node, ...)` —
and scope `__init__.py` files are router-only tables of contents.

## Signatures

Signatures are detached facts (`auth.signature`): an ordinary fact offering
`b"pk"` (the signer's public key) and `b"sig"` at a target fact's id, carrying a
real Ed25519 signature. It self-checks at the admission gate over exactly the
32-byte target id — the id IS the whole canonical fact, so signing the id
covers everything, and wrong math is a falsy check: an inert miss, never a bad
fact. A signed fact Requires the `b"pk"` offer at its own id, so it only
validates once its signature lands — and the signer key is now in the
projector's context. The gate proves only that SOME key signed; binding that
key to workspace authority is a value-compare in the target's PROJECT (see
Authority). Verification runs exactly once, at first admission; a faulted fact re-enters
with the check skipped — existence in the store is the certificate, and the
re-hash on reconstruction transfers it. Tampering with the local file is a local-integrity problem, not a
protocol one: bytes from outside enter only through the gate.

## Authority

A signature proves a key signed a fact; authority proves that key was allowed
to. The `auth` families make membership a chain that every fact climbs, by
value-compare, to one root — closing the gap where any key could mint a member.

The root is a key embedded in the workspace fact itself (poc-10's shape: the
workspace carries `public_key`; there is no separate founder fact). Two things
gate `auth.workspace`'s validity, so it is never self-trusting: a `pk`
self-signature by that root key (you only found a workspace with the key you
hold), and a LOCAL `workspace_accepted` offer from `auth.invite_accepted` — a
workspace fact received over sync is inert until THIS node accepted an invite
to it, or created it. That local acceptance is the trust anchor: a rival
workspace fact can arrive over sync, but it validates on no node that wasn't
invited into it. The root private key is ephemeral to `workspace.create`: it
signs the workspace, the first invite, and the bootstrap admin, then is
dropped — never a durable fact. The creator then joins through that first
invite like any other member; there is no founder special-case in the DAG.

The chain is one binding, applied per family: **the pk that signed a fact must
equal a pk the authority chain blessed.** Each fact Requires its own `b"pk"`
(who signed me) and Requires or Watches the offers that carry the blessed pk;
PROJECT intersects the two value sets and returns `Out("Invalid")` on no match —
a real refusal, distinct from parking on a not-yet-arrived signature.

- `auth.user_invite` blesses a fresh invite pk (`b"invite"` at its own id);
  valid iff signed by the workspace root (`b"root"`, the workspace's own offer)
  or an existing member key (`b"key"`, the rendezvous where every member offers
  its own key). The invite secret is the link, carried out-of-band; the inviter
  retains the bootstrap context as its own `invite_accepted`.
- `auth.user` is membership: it offers the member's name and own pk, and is
  valid iff its signer equals the pk blessed by the one invite it names by id —
  a joiner signs the membership with the invite key from the link, and the
  invite vouches for the member key the fact carries. From then on the member
  signs with their own key, now a blessed `b"key"`.
- `auth.invite_accepted` is the local-only acceptance record: it never syncs,
  gates the workspace as above, and carries the replayable bootstrap context
  (the invite secret keyed by its `bootstrap_hash`, the inviter's address and
  endpoint) — so it doubles as the bootstrap-reconnect source. Both the creator
  (self-accepting the first invite) and every joiner author one.
- `auth.admin` grants admin to a named member; it Requires that membership (a
  grant can never outrun the member it elevates) and is valid iff signed by the
  workspace root — the bootstrap admin `create` authors. Admin-to-admin
  delegation, poc-10 style, is a follow-up.
- `auth.device_invite` / `auth.device` are the same two shapes for endpoints: a
  member blesses a device key; the device joins by signing with it.

Because each fact Requires its blesser, any fact's authority chain is
reachable through its Require edges, and a peer re-derives every verdict
itself — a dep rides sync as one of its dependents' closure ids, advertised
in the range's id list and pulled by id (see Sync).

## Demand: store.hydrate

Hydration is just a fact. A demand is the `store.hydrate` family: a
volatile fact with one value-free Watch need, authored by queries before
they read — and the engine answers it exactly the way it answers every
need, through the fault leg (Hydration, Part I): the family adds no
machinery, it only names a key. The total demand (the reserved `\x00all`
key) is the whole boot story — and the daemon itself doesn't even author
it: it boots cold, and `con <db> store.hydrate.pull` (one verb, one fact)
makes a full replica. Queries may author volatile demand and drain; they still never
author durable facts. A durable hydrate fact is a pin (later wave, with
standing demand).

## Sync

Sync reconciles facts, never atoms — and the whole of it, set included, lives
in `facts/sync/`. The kernel's contribution is two GENERIC seams, not state:
the settle hook (a family that declares `settle()` sees every verdict its
facts settle to — including `Suppressed` and `Parked`, which never reach
`project()` — and maintains derived group state in its shared register) and
`answer()` (a family claims a reserved role and serves the need from its own
index). A family opts its facts into replication with one line — `from
facts.sync.index import settle` — and `facts/sync/index.py` folds each
verdict into the leaf set: `(ts, FactId) -> leaf hash` over every fact that is
durable, shareable, and `Valid`, held in a treap in the `b"sync"` register,
plus `ver`, a monotonic counter (never a hash) a host can cheaply poll for
"my set moved" (bench and the sync tests do; the daemon today relies on the
cadence alone). What replicates is thus a FAMILY decision, made identically
on every peer because every peer runs the same family code over the same
fact. Deletions reconcile through what DOES replicate: the deletion fact is
a durable leaf, its target is purged everywhere it lands, and a laggard peer
re-shipping the purged fact costs one admission that dies on arrival. The
hook rides promotion, not projection, because the MINUS side needs the
verdict: a leaf that settles Suppressed or Parked never reaches its
projector. Replay needs no second path: hydration re-steps every durable
fact and each re-promotion re-inserts its leaf. A
leaf hash is `H(FactId ‖ ts ‖ H(bytes))` — bytes-only, so the tree stores only
`key -> leaf hash`, never fact bodies. That body-independence is the seam for a
later residency/sync split (sync the full leaf set, hydrate a recent subset).

**Range-based set reconciliation (RBSR; Meyer & Scherer, rbsr_nonhomomorphic).**
The reconciliation set is a treap (`facts/sync/index.py`) — a search tree on the `ts‖FactId` key
AND a heap on a priority (the leaf hash), so the tree SHAPE is a function of the
set alone (history-independence) and two peers holding the same set build the same
tree. Each node caches its subtree size and a Merkle label
`H(left ‖ leaf hash ‖ right)`. A key range `[lo, hi)` is summarised by its CLAMPED
label — the label of the tree with all out-of-range items discarded — computed by
walking only the two boundary spines, `O(log n)`. Clamping-invariance makes that
label a canonical function of the in-range SET (independent of tree shape and of
out-of-range items), so two peers agree using an ORDINARY hash — no homomorphic or
XOR/sum fold. A range whose fingerprints differ is split into `B` sub-ranges of
EQUAL COUNT (an order-statistic `select` over the subtree counts), NOT by key
prefix — so fanout is the chosen `B` and depth is `log_B(n)` regardless of key
distribution. A range of `<= T` leaves is listed by id rather than fingerprinted,
which ends the recursion — and lets an empty peer pull, since it lists its (empty)
set and the peer then advertises what to send. (A maliciously degenerate set costs
`O(n)` local compute to fingerprint; the paper shows communication, roundtrips, and
censorship-resistance stay immune.)

**One bundled family, `compare`.** A compare fact carries a set of claims over
ranges — `fp` (a range fingerprint) or `ids` (a small range's complete id
list) — and, paired with each claim, a reserved `summary@range` need. Whoever
admits the compare has the engine answer each summary with its OWN view of that
range: its fingerprint, and its claims (the `B`-way split, or the id list
expanded to the range's dependency closure). The projector reconciles each
claim — a matching fingerprint prunes; a mismatch emits my claims for the range
(descend by count, or my id list if small on my side); a peer id list naming
ids I lack emits one batched `need` that ships them. Bundled: one compare is a
whole message, so matched sub-ranges prune wholesale and a one-fact diff over
100k facts settles in ~9 messages. No rounds and no daemon reaction: every
response is a projector offer at the connection's outbox key, and a dropped
frame just re-descends next cadence.

Windowing is the domain's lower bound: the root claim covers `[floor, HI)`, and
every sub-range is within it. The floor IS the retention horizon; poc-13 has no
retention/purge yet (Further Work), so the daemon passes `b""` and the domain
is the whole durable-shareable set.

Dependency-awareness rides the id lists, never a send-time walk. When a small
range is listed, the engine expands each leaf to its transitive dependency
closure (the Require/suppressor ancestry over the `deps` memo, `closure()` in
the kernel) — so a below-floor dependency is advertised as one of the range's
closure ids and pulled by id like any other, convergent because a peer only
ever requests ids the other side vouched for. The receiver admits every shipped
fact through the normal gate (the own-store `checked` path is never used for
peer input).

The split of labor: `compare`/`need` are volatile families (extract
`(False, False)`), so a reboot never resurrects session state and they are
excluded from the very leaves they reconcile; a frame crossing the wire IS a
fact, so facts stay the wire's only payload. `need` ships requested facts by
reference (fact ids resolved against the durable set at send time) at the
host-watched outbox keys, reaping on the flush (`shipped@SELF`, see The Clock).
The affordance seam — `summary@range` and `resident@id` — is answered into
ctx exactly as validated offers are, so the families read a peer's view
uniformly; `resident` by the engine from the durable set, `summary` by the
index family itself through `answer()` (the engine dispatches the reserved
role to its registered answerer — the kernel never reads the treap).

**Cadence is a fact, not a daemon marker.** A `sync.cadence` fact per
(connection, tier) Watches the clock and opens a fresh round once per period
(emitting my domain claims); its own self-Watched `tick` offer — re-emitted
by every branch that saw a clock, or the memory is lost — remembers the last
boundary, so it fires at most once per period though the clock re-wakes it
every turn. It offers a
`wake@clock` alarm at its next boundary, which `runtime.next_wake` reads for the
select timeout — an idle daemon sleeps until the next boundary, not on a fixed
poll. A `closed@conn` Suppress tears it down; being volatile, a reconnect
re-arms it (tiers — narrow+frequent … wide+rare — are several of these; arming
is idempotent, so the daemon just arms every live connection each loop). The
daemon keeps only the connection's re-dial cadence; no armed marker, no settle
marker, no round bookkeeping. A lost frame needs no retry state; the next
cadence compare repairs it. Every peer link is full-duplex, and reconciliation
is what a fact authored on one side rides to reach the others.

**The daemon sends nothing to a peer twice — the re-descend is free.** Everything
on the wire is content-addressed: a shipped fact by its id, and a compare frame by
its content (a compare fixes `ts=0`, so an unchanged claim is byte-identical every
time). The daemon keeps one per-connection *sent* set (source-side, process-local —
poc-10's `network_outgoing` in spirit) holding both — both are 32-byte digests — and
`pump` skips anything already sent this session. That closes the two halves of the
old `O(n²)` catch-up: a `need` re-asks for facts still in flight (unadmitted on the
peer), but each ships once; and a static source re-authoring the same split every
cadence tick, or re-answering the same range on every re-descend, ships that compare
once. A re-descend then costs `O(diff)` fresh discovery, not `O(n)` re-ship plus
`O(n)` re-discovery — the difference between `O(n)` and `O(n²)` wire as the peer
catches up, and a converged pair falls silent because its compares are all repeats.
Handshake frames are exempt: `connection.connection`'s content *is* the connection id
(both peers must derive it identically, and a durable request re-handshakes to the
same id), so it can't vary — a reconnect must always re-send it. Only what actually
left the outbox is marked (`deliver` reports the prefix it enqueued), so an
overflow-dropped tail stays unmarked and re-ships on the next re-descend, and a
partially-shipped `need` drains its remainder across turns rather than re-seal a
parked frame. A peer's socket break clears its sent set — the connection id is
deterministic and outlives the socket, so a reconnect (a healed partition) re-syncs
in full. The set is wiped on restart, exactly as poc-10's temp-table outgoing queue is.

## Connections

Peer sessions are facts too — the transport is a fact family, not an engine
primitive — living in `facts/connection/`. There is no kernel change.

**First contact is a sealed handshake (poc-10's request/connection).** A
`connection.request` (durable, LocalOnly) is the sealed first-contact fact: its
bytes ARE its id, and its public envelope (seal version, initiator ephemeral
X25519 key, addressed endpoint, nonce) wraps a ciphertext hiding both static
endpoints, the transcript nonce, the dial/return addresses, an authority proof,
and a branch signature. CHECK is structural only (widths parse); decryption
happens in PROJECT, keyed by opening secrets the fact Watches (the responder
opens with its static endpoint secret, the initiator with its own ephemeral —
the X25519 box is symmetric). The responder authors a `connection.connection`
(volatile, LocalOnly; its id IS the connection id, its bytes ARE the wire
message so both sides admit identical bytes): the plaintext carries the recomputed
`handshake_hash` and per-session `connection_secret`, and the projector refuses
unless it re-derives them from the transcript. Key agreement is `ee = DH(init_eph,
resp_eph)`, `es = DH(init_eph, resp_static)` → HKDF-SHA256 → the session key that
seals every established frame with XChaCha20-Poly1305. Recurrence is edge-triggered
on the requester: the durable request re-dials on a process-local cadence while
unanswered; the responder answers each arrival with no cadence of its own, and the
connection's `answered` offer retires the request's resend.

**Two handshake modes, one shape.** *Bootstrap* signs the request with the invite
key and proves authority with the invite's `bootstrap_hash` (the secret the
inviter retains as `invite_accepted`). *Membership* — reconnect after both nodes
are enrolled, with no invite — signs with the member's own key and names its
`endpoint_shared` record; the responder verifies the signature against the
signing key that record binds. The endpoint (X25519) is machine-wide, one per
node and identical across every workspace (`auth.endpoint`, LocalOnly, holding
the secret); the per-workspace binding is `auth.device` (poc-10 endpoint_shared,
role=Device): durable + **shareable**, self-attested by the member's signing key,
valid only if that signer is an enrolled member, publishing
`endpoint_shared@auth = frame(endpoint, signing_pk, wid)` and an `endpoint_key`
reverse index. So a node that joins two workspaces has two device facts carrying
one identical endpoint, and recognizing a peer is a workspace-scoped
endpoint→member lookup. That lookup is the `auth` column of
`connection.connection.peers` — a query-side value-compare, never a hard Require,
so an unrecognized endpoint still connects and simply shows `anon`, matching
Authority's stance.

**Close is a death key, and forward secrecy is its verdict.** `connection.close`
(durable, LocalOnly) offers `closed` at an id; the request, connection, and
ephemeral secrets each Suppress-need `closed@SELF`, so admitting a close flips
the cluster to Suppressed — and suppression purges, so the ephemeral private
keys leave disk and memory at the close itself, no sweep to schedule. The
daemon drops the socket and stops dialing; the close fact is what a restart
keeps — the cluster it killed no longer exists to replay, and a reconnect
must author a fresh request. `sever` closes a whole cluster (connection +
request + both handshake ephemerals) from one connection id.

**Frame bundles are ephemeral transport.** A `connection.frame` bundle is
volatile and unshareable exactly like a sync compare — never stored, never in
leaves, excluded from the reconciliation it carries. Its one value packs many
length-framed canonical fact bytes (up to ~48 KiB of inner fact bytes per
frame); the sync driver's shipments ride bundles instead of one fact per wire
frame. A receiver unpacks a bundle and
admits each inner fact through the normal gate, a bounded batch per turn — a
corrupt inner is a per-fact miss that never poisons its siblings, and the wrapper
itself is never admitted. Bundling, paired with the deferred-round rule above,
turns a bulk catch-up from hundreds of leaf-rescanning compare rounds into a
handful: on the measured 5000-fact catch-up it is roughly a 10x lift in both
facts/s and MB/s.

## Content

`facts/content/` is the messaging surface: `message` (a text message in a
channel), `reaction` and `message_deletion` (each carrying its target's
death keys per the suppression-closure discipline), and `retention_policy`
(records the retention window as an ordinary offer — last-write-wins is a
read-side fold; the purge
machinery that enforces it is a later family). The poc-12 blob content
spec — descriptor/outboard/chunk facts with `chunk -> outboard ->
descriptor -> anchor` arrows, anchors never requiring chunks, validity
public over ciphertext, the tree sharing the descriptor's death keys — is
protocol, not yet implemented.

## Family Specs Not Yet Implemented

These are protocol, specified fully in the poc-12 design; they land as fact
families without kernel changes:

- **Blob content** — the descriptor/outboard/chunk tree above (Content).
- **Retention and purge** — the policy fact exists (Content); enforcement
  does not. Timestamp order alone never purges: pins, retained closures,
  and live suppressor targets all hold facts; purge is `DELETE` over the
  db, and `VACUUM` reclaims space. The purge horizon is sync's window
  floor (see Sync).
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
