# The Atom Model — TinyP2P Design

This document is the design of record for the protocol implemented in this
repository. Ground truth is the running code in `kernel.py`, `facts/`, and
`bin/`, with executable claims pinned by `tests/` and `bench/bench.py`.

TinyP2P is a compact protocol runtime for local-first collaboration. Facts are
the units of identity and wire transfer, atoms are the units of durable storage
and matching, and the four atom relationships are the fact language. Commands,
queries, authority, content, connections, hydration, and synchronization all
use that same model.

The architecture follows the event-sourcing pattern; this protocol calls its
immutable events **facts**. Validated state is projected from those facts, and
the event model also describes the system machinery: transit connections,
sealed frame delivery, and range-based set reconciliation are fact families
rather than separate sidecar protocols.

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
  dirty discovery data; only validated Provides justify projection state,
  effects, or another fact's validity.
- The runtime has one durable authority: the persisted atom relation (one
  row per atom of every durable fact; canonical bytes are derived, never
  stored) plus a `FactId`/type-tag spine. Everything else — validity, the
  clean twin, the frontier, and family-owned indexes — is derived and rebuilt
  on demand.
- Matching looks to the persisted relation: when a resident fact steps,
  each Gather, Require, and SuppressIf key is checked once against the store
  and cold providers fault in through ordinary admission. Provides never wake
  cold facts. Boot is the degenerate demand: one total hydrate fact.
- The store answers existence, never standing: it can say who Provides at a
  key and hand back reconstructed bytes; verdicts are computed only in the
  engine over the resident set. A family CHECK result, notably Ed25519
  verification, is certified by first admission and stored existence. A local
  fault still strict-decodes and re-hashes reconstructed rows before skipping
  that already-completed CHECK.
- Atoms have exactly four relationships. `Provide` publishes candidates;
  `Gather` collects zero or more matches; `Require` parks on zero matches; and
  `SuppressIf` terminally evicts on any match. All three consumer
  relationships acquire matches identically. Precedence: SuppressIf >
  Require(Park) > Project.
- Admission is idempotent and content-addressed; wrong bytes are a miss,
  never a wrong fact.
- Wire provenance enters through the same graph as every other input. The host
  labels bare facts and facts opened by an authenticated connection with
  engine-owned Provides; family SHAPEs SuppressIf or Gather those Provides.
  There is no central table classifying fact tags as local or remote.
- Queues, effects, sync, connections, content, and retention policy are fact
  families, not engine primitives. Time and wire-flush reports are transient
  host inputs to the turn. The kernel owns identity, admission, matching, and
  the turn loop.
- Generic projected-Provide `observe()` and reserved-name `answer()` registries
  let a family maintain and query a rebuildable index without teaching the
  kernel its semantics. Sync uses them to own its treap in its own register.
- Projectors ARE the routers: the kernel runs one root projector, and a
  router is just a projector that dispatches on type-tag segments.
- Every fact family is one file with one fixed six-part contract: SHAPE,
  EXTRACT, PROJECT, COMMANDS, QUERIES, CLI.
- Replicated application content is signed: a message, reaction, deletion, or
  retention policy is authorized by a separate canonical signature fact and
  by the authority Provides its projector requires.

# Part I — The Kernel

## Canonical Data

### Atom

```text
Atom { relationship: Provide|Gather|Require|SuppressIf,
       name, scope, target: Exact(bytes)|SELF|Range{lo,hi}, value? }
       # wire grammar; in memory a target is a span (lo, hi) — a point is
       # lo == hi — and SELF until materialization rewrites it to the owner
```

`relationship` is one closed sum, not a kind combined with an effect. `name`,
`scope`, and `target` form the match address; `value` is not read by core
matching. Ordinary consumer relationships are value-free; reserved Gathers
may carry query parameters for an engine or family answerer. Values are small;
large payloads are content facts.

`SELF` means "this fact's eventual `FactId`" and is legal only in the canonical
fact form, whose encoding retains `SELF` so identity never contains its own
hash. Every resident match row and persisted atom row materializes it to the
owner id. Store reconstruction recognizes an owner-targeted row as canonical
`SELF`, rebuilds the fact, and accepts that interpretation only when the
resulting hash is the row owner's `FactId`. `SELF` never participates in
matching directly.

Atoms belong to one owner fact and have no independent identity. SQLite's
`atoms` table is therefore an owner-keyed relation, not an intern pool: the
same atom in two facts occupies two rows with different `fid` values. In
memory, derived match rows may reference the fact's frozen atom objects as an
implementation detail.

### Fact and Identity

A fact is a type tag plus a strictly increasing, duplicate-free sequence of
atoms, ordered byte-lexicographically on the canonical atom encoding.

`‖` means length-framed concatenation (each field prefixed with its 4-byte
LE length). Each atom contributes its own framed canonical byte form.

```text
FactId = H("tinyp2p.fact.v2" ‖ type_tag ‖ atoms)
```

`H` is BLAKE3-256 (32 bytes, via the `blake3` package). The encoding is one fixed
self-delimiting byte form, version-free forever; the domain string is the
only dialect marker. Strict decode rejects malformed encodings, unsorted or
duplicate atoms, and trailing bytes — anything that does not re-encode
byte-identically.

A fact never embeds its own `FactId`. Hash references in values or targets
must name already-existing facts, so the hash-reference graph is acyclic by
construction.

Every durable fact whose projector can emit a sync-leaf marker carries one canonical timestamp atom
`Provide(name="ts", scope=family_scope, target=SELF, value=u64le)` — the
reconciliation sort key and a retention input, never an authority proof.
A fact without one promotes rows at `ts = 0`.

## Extraction and Durability

Extraction is the content-pure durability decision from the fact's own bytes,
made at admission before validation and routed through the same router tree as
projection. Extracted wire bytes are staged until their first graph judgment: a
nonterminal verdict certifies them into the durable map, while a first-step
Suppressed/Reap fact never becomes durable. This prevents a crash between wire
admission and provenance judgment from resurrecting unlabeled bytes. Locally
authored and checked-store facts retain immediate durability. Volatile facts
vanish on restart. Unknown tags default to Durable + Parked and project no
Provides.

Replication is not extraction policy. A Valid projector includes the derived
`leaf@sync/SELF` Provide returned by `sync_leaf()` when its owner may enter sync
egress. The sync family observes only that validated clean Provide. Ingress is
a separate graph relation and remains accept-by-default. A handler
opts into source constraints in its own SHAPE: node-private families carry
`SuppressIf(remote@origin/SELF)`; bare handshake facts carry
`SuppressIf(connection@origin/SELF)`; and established sync controls carry
`SuppressIf(bare@origin/SELF)` plus `Gather(connection@origin/SELF)`. The last
lets the projector compare the authenticated outer connection id with the id
inside the fact. One-argument intrinsic CHECKs rebuild source-sensitive family
shapes exactly, so a sender cannot remove or substitute their policy atoms;
CHECK itself never receives or classifies provenance.

## Runtime State

Durable: the persisted atom relation — SQLite `atoms`, one row per atom of
every durable fact, beside a two-column `facts(fid, tag)` spine. Each atom row
stores relationship, name, scope, value, and the materialized target as
`(exact, lo, hi)` with `SELF` rewritten to the owner id. There is no bytes
column: a read regroups a fid's rows, restores canonical `SELF`, rebuilds,
re-encodes, and re-hashes. Rows that do not add up to their fid are a miss,
never a wrong fact. One write door (`add`, downstream of admission) makes
existence the persisted certificate: intrinsic checks ran once at first
admission, and the re-hash transfers them, so a faulted fact re-enters checked
and a boot re-verifies no signatures.

The relationship grammar is protocol v2. Its two-byte atom header and
`(relationship, name, ...)` store relation are intentionally incompatible with
v1; opening a v1 atom table fails closed and requires a fresh database rather
than guessing at an identity-changing migration.

Ephemeral, all rebuilt from demand and promotion:

- resident `Fact` objects and canonical bytes for resident durable facts;
- the asserted match buckets, populated immediately with every resident
  fact's materialized atoms;
- the validity memo (`Unknown|Parked|Valid|Invalid|Suppressed`) and the
  validated Provide set (the clean twin, stamped `(owner, ts, atom)` with
  engine-owned provenance);
- owner-to-clean-row bookkeeping, checked store keys, and the bounded FIFO
  frontier with its membership set;
- staged wire-extracted bytes plus engine-owned `remote`, `bare`, and `connection`
  source rows, retained only through the fact's first judgment; and
- `Node.regs`, one rebuildable register per family group. A registered
  `observe()` function folds validated Provide deltas into a register, and a
  registered `answer()` function can expose its index through a reserved
  Gather. Sync's `b"sync"` register holds its treap, leaf membership, summary
  memo, and monotonic version counter.

Validated Provides are the application read model. Registers are derived family
indexes, not a second authority surface, and are never persisted.

The crash story is one fact: derived state is a pure, order-independent
function of the durable set, and a fresh node over the same store rebuilds
it by admitting a single total hydrate demand. There is no load and no
replay path. Storage loss shrinks the set — it costs completeness, never
coherence. Storage is outside the trust boundary; faulted bytes re-enter
through checked admission, and wrong rows are a miss.

With a `Store` attached, a session admits nothing at boot and pays only for
what its facts and queries ask about (see Hydration); the total demand is
the degenerate case that faults everything.

`bin/tinyd.py` owns the database exclusively and constructs a cold node: it
performs no database-wide load and decides no application residency policy.
Startup demands only its local signer and endpoint identity. Other residency is
demanded — a verb's queries
fault their keys, and hydration at any scale is a client verb
(`store.hydrate.pull` with no key faults everything). It runs
the three-phase host turn in a single-threaded select loop — client verbs
over a unix socket at `<db>.sock`, peers over TCP. Its reusable core is
`bin/runtime.py`, a socket-free seam: `cycle` admits a locally-authored inbox
and drains one bounded turn presenting the wire's flush reports; `pump`
groups the validated `send`/`ship` Provides by owner, resolves each route and
its ship-ids, and hands the frames to a `deliver` callback. The wire's only
payload is length-framed canonical fact bytes under a one-byte discriminator:
a bare handshake fact before a session key exists, a sealed `connection.frame`
after. On input, the daemon admits a bare body with `WireOrigin()`; after it
authenticates and opens a frame, it admits each inner body with
`WireOrigin(connection_id)`. Those labels are engine-owned graph rows, never
sender-authored atoms. There is **one out door** — the daemon reads validated
outbox Provides and
`deliver` seals iff the route yields a session secret, else sends bare — so
handshake responses and sync frames leave through the same mechanism. The
outbound path tolerates loss until the receiver admits: a frame is handed
best-effort to the bounded socket buffer, and a dropped or truncated frame is
re-derived by cadence and either fails authenticated opening or re-enters normal
admission. Sync reconciles the resident set. An explicit total hydrate demand
makes reconciliation cover the complete durable set; a partially hydrated node
advertises only its resident coverage. Purge uses `DELETE`; SQLite space
reclamation requires `VACUUM`.

## Turn Semantics

A host turn has three phases.

**Host in.** Admission strict-decodes candidate bytes, recomputes `FactId`
(rejecting a mismatch when an id was requested), returns early for an already
resident id, then runs an optional intrinsic family CHECK and extraction. A
successful admission stores the resident fact, stages extracted bytes, adds
every materialized atom directly to the asserted match buckets, and enqueues
the owner. Locally authored and checked-store facts enter the durable map
immediately. Wire input instead stages extracted bytes and publishes transient,
engine-owned source Provides at that owner's id: `remote` plus either `bare` or
`connection` (whose value is the authenticated connection id). Failed
intrinsic checks are inert.

**Engine drain.** Drain the frontier to a bound (overflow parks, never
drops). For each owner, check already-resident suppressors first, so a rejected
source cannot trigger another consumer relationship such as total hydration.
If no suppressor is present and a store is attached, the fault leg checks every
Gather, Require, and SuppressIf key once against the persisted relation and
admits all cold providers (checked admission — the bytes passed the intrinsic
gate once). The engine then answers all three consumer relationships through
that same match path. Any nonempty SuppressIf suppresses; otherwise any empty
Require parks; otherwise the engine builds `Context<Validated>` from Gather and
Require matches and calls the routed projector
`project(fact, ctx) -> Out(verdict, provides)`. Promotion records the verdict
and replaces the owner's clean output atomically, so old and new Provides are
never both visible. The kernel restamps projected Provides with engine
provenance, notifies registered observers of changed Provide addresses, and
wakes every resident owner whose asserted consumer relationships match a
changed Provide. `Reap` and
`Suppressed` are terminal: after clean replacement and observer notification,
the engine removes the resident body, asserted rows, memo, durable bytes, and
SQLite rows. A first nonterminal verdict moves staged extracted bytes into the
durable map before settlement; a first terminal verdict discards them. Source
rows are cleared after this first judgment because the source decision is then
certified; for durable facts, stored existence carries that certificate across
restart. After the turn, the host flushes newly durable facts as one SQLite
transaction.

**Host out.** The host drains validated Provides at keys it Gathers, performs
external work, and admits facts reporting what happened. Host code never
mutates validated state.

## Relationships

**Provide** publishes a candidate at `(name, scope, target)`. It becomes part
of validated state only when its owner projects it. **Gather** is a
non-blocking subscription: its complete match set, including the empty set, is
passed to the projector and changes wake it. **Require** uses the same match
set, but an empty set Parks the owner before projection. **SuppressIf** also
uses the same match set, but a nonempty set flips the owner to Suppressed before
projection. Suppression withdraws the owner's output and terminally purges its
resident body, asserted rows, and durable bytes. Deletion is immediate and
real. What suppression keeps is the relationship, never the husk: the
suppressor and death key it matches are durable facts, so a purged fact that
re-arrives re-derives Suppressed and dies on arrival.

Precedence: SuppressIf > Require(Park) > Project. Gather never gates.

Stratification is a family obligation: `Require` edges are positive,
`SuppressIf` edges negative, and `Gather` edges don't participate; a fact may not
depend on its own validity through any path containing a negative edge. A
family that could create such a cycle must reject the shape or define a
local total-order break.

Suppression closure is family discipline too: every fact that must die with
a target carries the target's death keys directly (as `SuppressIf`
relationships).
There is no implicit cluster deletion or consumer demotion cascade. A related
fact without that death key — including a detached signature — remains unless
its own relationships park, suppress, or reap it. Connection teardown copies the close
keys into every secret/session fact that must be physically removed; content
families copy a message death key into dependents that must die with it.

### Collapsible alternative: Provide and Gather only

`Require` and `SuppressIf` are not additional matching power. A smaller atom
algebra could express both as `Gather`, leaving only `Provide | Gather`, but the
coherent simplification would remove both relationships rather than only
`SuppressIf`: an empty Require is just as expressible as a projector branch as
a nonempty SuppressIf. The projector would check death matches first and return
`Suppressed`, return `Parked` while any declared dependency is absent, and run
its semantic projection once all dependencies are present. Every validated
Provide delta already re-enqueues matching owners, so the resident fact would
be re-stepped and re-projected until that projection succeeds.

That replay would not re-admit, decode, hash, or signature-check the fact. The
fact is immutable and its admission CHECK remains trusted; in particular,
Ed25519 verification still happens once. Compared with the current engine, the
number of dependency-driven steps is unchanged. `Require` merely avoids calling
the projector on incomplete steps. A local synthetic measurement with ten
dependencies found one batched settlement at about 171 µs with Require versus
175 µs with Gather-only (one extra projector call, about 2%). With the ten
dependencies arriving in ten separate waves, it measured about 256 µs versus
284 µs (ten extra calls, about 11%, or 28 µs total). These figures are
machine-specific, but the shape is stable: the extra work is
`O(arrival waves × projector preflight)`, and a cheap completeness check before
shape or authority work keeps it small relative to storage, transport, and
one-time cryptographic admission.

The larger cost is semantic, not computational. A Gather-only kernel no longer
enforces suppression-before-parking, distinguishes positive from negative
dependency edges for stratification, or identifies dependency ancestry for
sync closure. Those responsibilities would have to move into every projector
or another declaration mechanism; adding such a mechanism could recreate the
relationships the collapse removed. The four-relationship model keeps that
policy generic even though the two-relationship model is expressively
sufficient.

## Matching

```text
consumer.name == provide.name  ∧  consumer.scope == provide.scope
∧  target_covers(provide.target, consumer.target)
```

`target_covers` is exact equality, a range Provide covering an exact consumer
key byte-lexicographically (inclusive), or symmetrically a range consumer
covering an exact Provide key — bulk demand is ordinary matching. Range never
matches range, and `SELF` never matches. Admission materializes every resident
atom before it can be matched. The asserted index is bidirectional
(consumer→Provide for dependencies, Provide→consumer for wakes), while the clean twin is
the only validity justifier. Both use the same bucket shape: exact targets are
indexed by point and spans are kept separately, so an exact lookup reaches its
point bucket plus covering spans without counting or scanning every same-name
point.

## Hydration

One rule: **when a resident fact steps, each of its Gather, Require, and
SuppressIf keys is checked once against the persisted relation, and every cold
owner Providing at that key is admitted** (the fault leg). Faulted facts land
on the frontier; when they step, their consumer relationships fault in turn —
the step loop is the spider, and residency grows to the demand fixpoint. All
three relationships fault alike: `Require` finds its dependency, `SuppressIf`
finds its tombstone (absence is only trusted after the key is checked — a cold
suppressor bites on its target's own step), and `Gather` finds its subjects.
Verdicts are exact at quiescence; a fact may transiently judge
before its faults land and is re-woken by normal fanout, exactly as a
late-arriving wire fact re-judges it. Demand flows backward through consumer
relationships only: Provides never wake cold facts (a fact that wants waking while cold is
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
Matching-side it is two indexed SELECTs: `providers(consumer)` (whose WHERE clause
is the atom coverage relation, property-pinned to kernel `covers`) and
`fact_bytes(fid)`. A demand is one key and drains all stored owners matching
that key; bounded working sets come from choosing bounded keys rather than from
a separate window, budget, or delivery-order API.

## Routing: Projectors Are the Routers

The kernel runs one root projector. A `Router` is a projector that
dispatches on the next type-tag segment and delegates whole; extraction
routes through the same tree, and so does the dotted api/CLI namespace
(`content.message.send` resolves through the same routes as the
`content.message` tag).
Routers narrow inputs and cannot widen a delegate's context; delegation
must equal the delegate run alone. Unknown tags fall out as Durable + Parked
with no projected Provides and no special casing.

## The Clock and the Flush Report

Time is not a fact family: it is the one input the host reads from the OS and
hands to the turn. `kernel.turn(now)` presents `now` as a single transient
Provide at the NOW key; a time-waiting fact carries a Gather over
[deadline, ∞) (`now_gather`), and when now reaches its deadline the Provide falls
in range and wakes it. There are no tick facts, so nothing accumulates;
matching stays ordinary (a plain Range Gather over a plain Provide); and durable
derived state never depends on `now`, so a reboot at any `now` rebuilds it
identically. The daemon reads the clock each loop and passes it to the turn;
a `wake@clock` alarm — a cadence fact's next boundary — sets its `select`
timeout via `runtime.next_wake`, so it sleeps exactly until the earliest
deadline and services a due time relationship on that wake.

The flush report is the clock's sibling — the other host signal handed to the
turn. Just as the host hands in `now`, it hands back the ids of the
host-Gathered Provides it flushed to the socket: `kernel.turn(now, shipped)`
presents each as a transient Provide at the SHIPPED key, waking any sender that
Gathers `shipped@SELF`. A one-shot sender (an `outbox.send`, a `sync.need`)
answers by returning the terminal **Reap** verdict, on which the engine evicts
the fact whole — Provides, memo, and match rows — so a busy session leaves no
drained-send residue. Reap and Suppressed are both terminal evictions; they
differ in cause and guard. Reap is family-chosen with no durable cause, so it
is safe only leafward — nothing may gate on the reaped Provides, an invariant
the engine asserts before evicting. Suppression is kernel-derived from a
durable edge, so it is deliberately unguarded: withdrawing Provides others gate
on is the point (dependents park, or die by their own death key), and the
verdict re-derives on any re-arrival because its cause outlives the fact. The daemon re-presents an
unacked `shipped` until its sender acts (a bounded drain never drops the
report) and drives no retirement itself: the policy — reap, or re-arm a retry
— lives in the family, never in the pump. Persistence is the same shape
inverted: the host's other completion set, `flushed`, tracks which durable
facts have reached the db, but a durable fact must *survive*, so it is written
by `runtime.flush` and never reaped.

Recurrence is central but the onus is on one party: everything that must
happen repeats, and the repeating side drives it. Sync's periodic re-descend
is a `sync.cadence` fact (see Sync) — its `wake@clock` alarm drives the
schedule, not a daemon marker. The initiator's durable request is also its
known-peer anchor: the daemon dials it every 500 ms until answered, every 2 s
after answering while no live session socket exists, and not at all while that
socket is up. The responder answers each arrival and needs no cadence of its
own. This address and retry timing is the one operational repetition kept
process-local in the daemon.

## The CLI

`bin/tiny.py`: `tiny <db> <scope.fact.verb> [args...]`. It is a thin client:
resolve nothing locally, just proxy to the daemon that owns the db. `<db>.sock`
accepts, the verb path and args go out as one framed request, and one framed
`+ok`/`-err` reply comes back after any authored durable facts reach SQLite.
With no daemon reachable the client exits with an error. The daemon is the
only writer and boots cold; a verb's queries demand the keys they read, and
after an operator's `store.hydrate.pull` every later store-key demand is
covered by the checked total.

# Part II — Fact Families

Everything below is fact-level design: families under `facts/<scope>/`, one
file each, built on Part I. The contract comes first because it is the
boundary the kernel holds every family to.

## The Fact Contract

Every fact family is one file, `facts/<scope>/<fact>.py`, with six required
parts (plus an optional CHECK between EXTRACT and PROJECT), always in this
order, enforced by a source-contract test:

- **SHAPE** — constructors returning canonical `Fact`s. The only place
  asserted input atoms are chosen. This is the whole codec story: the kernel's one
  canonical encoding covers every family, so there are no per-family byte
  formats. Source policy lives here too: a family adds the provenance
  SuppressIf/Gather relationships that describe where its facts may come from.
  A family that wants a private format inside a value is a signal the atom
  vocabulary is missing something.
- **EXTRACT** — content-pure durability (`True` is durable, `False` volatile).
- **CHECK** — optional intrinsic self-verification at the admission gate; pure
  function of the fact's own bytes; runs once, never on replay. It never
  receives host provenance. Families with source-policy atoms rebuild their
  exact SHAPE here, so a sender cannot strip the relationship that would
  suppress or bind it.
- **PROJECT** — the only place the family's meaning lives: validity and
  projected Provides, including any derived sync marker. Pure function of
  `(fact, ctx)`; never touches the node.
- **COMMANDS** — local authoring: `(node, params) -> fact id`. Build a
  fact, admit it, stop. Commands may call queries to choose parameters and
  write only through admission. Anything multi-step or retryable is more
  facts (the outbox pattern), not a fancier command.
- **QUERIES** — observations: `(node, params) -> data`, read only from
  validated state (the clean twin, Gathered keys) — never asserted
  rows, never authority for anything.
- **CLI** — the string boundary: a `CLI = {verb: fn}` dict mapping names to
  thin wrappers over COMMANDS/QUERIES that coerce strings in and out.
  Exposure is deliberate; verbs, not helpers.

The module itself is the Python API — `facts.content.message.send(node, ...)` —
and scope `__init__.py` files are router-only tables of contents.

## Signatures

Signatures are detached facts (`auth.signature`): an ordinary fact Providing
`b"pk"` (the signer's public key) and `b"sig"` at a target fact's id, carrying a
real Ed25519 signature. It self-checks at the admission gate over exactly the
32-byte target id — the id IS the whole canonical fact, so signing the id
covers everything, and wrong math is a falsy check: an inert miss, never a bad
fact. The gate extracts the candidate fields, rebuilds the exact fact with the
family's SHAPE constructor, and requires byte-for-byte canonical equality before
verifying. PROJECT repeats that canonical-shape check before publishing the one
verified public-key claim. Extra atoms, foreign scopes, alternate tags, and
additional public-key claims are therefore inert rather than riding beside an
honest signature.

A signed fact Requires the `b"pk"` Provide at its own id, so it validates only
after its signature lands and the signer key is present in the projector's
context. The signature proves that some key signed; the target projector binds
that key to workspace authority by value comparison (see Authority).
Cryptographic verification runs once at first admission. Store reconstruction
re-hashes the canonical rows, and checked local faults reuse existence as the
certificate that the gate already ran. PROJECT still checks canonical shape on
that replay path. Tampering with the local file is a local-integrity problem;
external bytes enter through the admission gate.

## Authority

A signature proves a key signed a fact; authority proves that key was allowed
to. The `auth` families make membership a chain that every fact climbs, by
value-compare, to one root — closing the gap where any key could mint a member.

The root public key is embedded in the workspace fact itself. Two things
gate `auth.workspace`'s validity, so it is never self-trusting: a `pk`
self-signature by that root key (you only found a workspace with the key you
hold), and a LOCAL `workspace_accepted` Provide from `auth.invite_accepted` — a
workspace fact received over sync is inert until THIS node accepted an invite
to it, or created it. That local acceptance is the trust anchor: a rival
workspace fact can arrive over sync, but it validates on no node that wasn't
invited into it. The root private key is ephemeral to `workspace.create`: it
signs the workspace, the first invite, and the bootstrap admin, then is
dropped — never a durable fact. The creator then joins through that first
invite like any other member; there is no founder special-case in the DAG.

The chain is one binding, applied per family: **the pk that signed a fact must
equal a pk the authority chain blessed.** Each fact Requires its own `b"pk"`
(who signed me) and Requires or Gathers the Provides that carry the blessed pk;
PROJECT intersects the two value sets and returns `Out("Invalid")` on no match —
a real refusal, distinct from parking on a not-yet-arrived signature.

- `auth.user_invite` blesses a fresh invite pk (`b"invite"` at its own id);
  valid iff signed by the workspace root (`b"root"`, the workspace's own Provide)
  or an existing member key (`b"key"`, the rendezvous where every member Provides
  its own key). The invite secret is the link, carried out-of-band; the inviter
  retains the bootstrap context as its own `invite_accepted`.
- `auth.user` is membership: it Provides the member's name and own pk, and is
  valid iff its signer equals the pk blessed by the one invite it names by id —
  a joiner signs the membership with the invite key from the link, and the
  invite vouches for the member key the fact carries. From then on the member
  signs with their own key, now a blessed `b"key"`.
- `auth.invite_accepted` is the node-private acceptance record: it never syncs,
  gates the workspace as above, and carries the replayable bootstrap context
  (the invite secret keyed by its `bootstrap_hash`, the inviter's address and
  endpoint) — so it doubles as the bootstrap-reconnect source. Both the creator
  (self-accepting the first invite) and every joiner author one.
- `auth.admin` grants admin to a named member; it Requires that membership (a
  grant can never outrun the member it elevates) and is valid iff signed by the
  workspace root — the bootstrap admin `create` authors. Admin-to-admin
  delegation is not implemented.
- `auth.device_invite` / `auth.device` are the same two shapes for endpoints: a
  member blesses a device key; the device joins by signing with it.

Because each fact Requires its blesser, any fact's authority chain is
reachable through its Require edges, and a peer re-derives every verdict
itself — a dep rides sync as one of its dependents' closure ids, advertised
in the range's id list and pulled by id (see Sync).

## Demand: store.hydrate

Hydration is just a fact. A demand is the `store.hydrate` family: a
volatile fact with one value-free Gather, authored by queries before they read
— and the engine answers it exactly the way it answers every consumer
relationship, through the fault leg (Hydration, Part I): the family adds no
machinery, it only names a key. The total demand (the reserved `\x00all`
key) is the whole boot story — and the daemon itself doesn't even author
it: it boots cold, and `tiny <db> store.hydrate.pull` (one verb, one fact)
makes a full replica. Queries may author volatile demand and drain; they still never
author durable facts. Persistent standing demand and pins are outside the
implemented family.

## Sync

Sync reconciles complete facts, never individual atoms, and its set and
protocol live in `facts/sync/`. The kernel contributes two generic seams:

- `observe(name, scope, fn)` passes `fn(node, before_rows, after_rows)` the
  validated clean-Provide delta at one address so a family can fold it into its
  group register.
- `answer(name, fn)` registers a handler for a reserved Gather name and injects
  the handler's rows into projector context like ordinary validated Provides.

A replicating projector includes `facts.sync.index.sync_leaf()` in its Valid
`Out.provides`. This creates the validated `leaf@sync/SELF` row whose engine-owned
provenance names the fact and timestamp. The index observer folds marker deltas
into the `b"sync"` register's treap, leaf-membership set, summary memo, and
monotonic `ver` counter. A fact is a leaf exactly while it is durable and its
projector publishes that marker. Raw asserted marker atoms have no effect. The
decision to replicate is therefore owned by each projector, while peers running
the same family code derive the same set.

Suppression's clean replacement retracts the target marker before terminal
eviction. Deletion travels because the deletion fact itself is durable, Valid,
and projects a marker; wherever it validates, its `dead` Provide purges matching
targets. A laggard may re-send a purged target, but the durable suppressor makes
that admission settle `Suppressed` and disappear again. Hydration rebuilds the
register by stepping durable facts through the ordinary projection path, with
no separate sync replay feed.

Each reconciliation key is `ts‖FactId`, where `ts` is 8-byte big-endian for
ordering. Its leaf hash is `H(FactId ‖ ts ‖ H(canonical_bytes))`; the treap stores
only `key -> leaf hash`, not fact bodies. `ver` is a change counter rather than a
set hash.

**Range-based set reconciliation (RBSR; Meyer & Scherer,
`rbsr_nonhomomorphic`).** The reconciliation set is a treap in
`facts/sync/index.py`: a search tree on `ts‖FactId` and a heap on
`(leaf_hash, key)`. Priority is a pure function of the item, so tree shape is a
function of the set rather than insertion history. Each node caches subtree
size and `H(left_label ‖ leaf_hash ‖ right_label)`.

A range `[lo, hi)` is summarized by its clamped label: the label of the tree
with out-of-range items discarded. The iterative implementation walks the two
boundary spines and reuses labels for fully included subtrees, taking expected
`O(log n)` time. The label is a canonical function of the in-range set, so it
uses an ordinary cryptographic hash rather than a homomorphic XOR or sum. A
mismatch splits into at most `B=16` equal-count ranges by order-statistic
selection, independent of key-prefix distribution. A range with at most `T=8`
leaves is listed by id, which terminates descent and also lets an empty peer
pull. Adversarial priorities can produce an `O(n)` spine, but the iterative
walks do not overflow the Python stack.

**Bundled compare facts.** A `sync.compare` fact carries multiple claims:
`fp` for a range fingerprint, `ids` for a small range's complete id list, or
`done` for an agreed range. Each live claim carries a reserved
`summary@range` Gather. The sync index answers with its own fingerprint and
either its equal-count split or its id list. The projector prunes a matching
fingerprint, descends a mismatch, re-advertises local extras, and accumulates
all missing peer ids into one batched `sync.need`. Each compare is one fact, so
matched subranges prune together and mismatch depth is `O(log_B n)`.

Windowing is the domain's lower bound: the root claim covers `[floor, HI)`, and
every subrange stays inside it. The daemon's active tier pair uses `floor=b""`,
so its domain is the complete resident marker-owning set. A nonempty floor
is the reconciliation counterpart of a retention horizon; enforcement is not
implemented.

Dependency-awareness rides in id lists. For a windowed small range, the summary
answerer expands its in-range leaves through `Node.closure()`, which computes
Require and SuppressIf ancestry directly from resident asserted matches. It adds
marker-owning dependencies below the floor to the listed ids, deduplicated and
capped at 4096. A peer requests only ids that the other side advertised. The
resulting `sync.need` Gathers `leaf@sync` at every requested id and its projector
Provides only matching marker owners to the outbox, so a forged by-id request
cannot turn a durable marker-free fact into sync egress. Every received fact
enters ordinary admission with its host-observed source rows; the `checked=True`
path is reserved for reconstruction from the node's own store.

`compare` and `need` are volatile and project no marker, so they are absent
from the set they reconcile and leave no reboot state. A `need` Provides its
marker-authorized requested ids by reference at the host-Gathered outbox key;
the pump resolves them against resident durable bytes at send time, and the
need reaps after its wire-flush report. `resident@id` is answered by the kernel's durable map, while
`summary@range` is answered by the sync family. Both appear in projector
context in the same row shape, and the kernel never reads the treap.

**Cadence and convergence certificates are facts.** Every live connection arms
an idempotent pair of volatile `sync.cadence` facts over the full domain:

- the 500 ms gated tier opens when its current claim hash differs from its last
  opener and remained the same across a due boundary; this carries low latency
  without launching overlapping cascades while the set is still changing; and
- the 4 s anchor tier opens unconditionally, which supplies the liveness bound
  under loss, duplication, reordering, restart, or starvation of the gated
  optimization.

Each tier Gathers the clock, publishes its next `wake@clock` alarm, and stores
`last boundary`, `sent`, `seen`, and `confirmed` hashes in a self-Gathered tick
Provide keyed by `(connection, floor, period, mode)`. Every clock-handling branch
re-emits that Provide, so the register survives reprojection. `closed@conn`
suppresses and purges both tiers; reconnecting arms fresh volatile facts.

When every claim in a compare matches, the responder sends an all-`done`
compare. Its `confirmed@connection` pulse lets the cadence record a certificate
for the last opener only if the currently derived opener still hashes to the
same value. `cadence.synced(node, cid)` is true exactly while such a certificate
matches the current local split and becomes false as soon as the set changes.

**Wire dedup is bounded and cannot veto healing.** The pump keeps a
per-connection process-local `TTLSet`. Shipped facts are keyed by `FactId`, and
sync control compares by content hash; handshake frames are exempt. A digest
suppresses an identical send for 3 s, which collapses immediate re-asks and
mirrored cascades. The TTL is strictly shorter than the 4 s unconditional
anchor, so a lost byte-identical opener becomes sendable before the next anchor
and dedup can delay recovery but cannot prevent it.

`deliver` reports how many inner facts it actually enqueued. Only that prefix is
marked, so an outbox-limited tail remains eligible for a later request. A socket
break clears the connection's TTL set for immediate resynchronization, and a
process restart starts with empty dedup memory. A converged full-duplex pair
therefore exchanges bounded anchor claims and small all-done certificates rather
than maintaining persistent round state.

The current sync register is global per node and summarizes the resident set.
Workspace-scoped lanes and explicit coverage claims for partial replicas are
outside the implemented protocol.

## Connections

Peer sessions are facts too — the transport is a fact family, not an engine
primitive — living in `facts/connection/`. There is no kernel change.

**First contact is a sealed handshake.** A
`connection.request` (durable, no sync marker) is the sealed first-contact fact: its
bytes ARE its id, and its public envelope (seal version, initiator ephemeral
X25519 key, addressed endpoint, nonce) wraps a ciphertext hiding both static
endpoints, the transcript nonce, the dial/return addresses, an authority proof,
and a branch signature. CHECK verifies the exact public shape and envelope
widths; decryption happens in PROJECT, keyed by opening secrets the fact Gathers (the responder
opens with its static endpoint secret, the initiator with its own ephemeral —
the X25519 box is symmetric). The responder authors a `connection.connection`
(volatile, no sync marker; its id IS the connection id, its bytes ARE the wire
message so both sides admit identical bytes): the plaintext carries the recomputed
`handshake_hash` and per-session `connection_secret`, and the projector refuses
unless it re-derives them from the transcript. Key agreement is `ee = DH(init_eph,
resp_eph)`, `es = DH(init_eph, resp_static)` → HKDF-SHA256 → the session key that
seals every established frame with XChaCha20-Poly1305.

The two handshake families carry `SuppressIf(connection@origin/SELF)`: local
authoring and bare first contact are allowed, but smuggling a handshake inside
an existing session is not. Established `sync.compare` and `sync.need` facts
instead carry `SuppressIf(bare@origin/SELF)` plus
`Gather(connection@origin/SELF)`; their projectors require the outer
authenticated connection id to equal the id embedded in the control fact.

The durable request remains after its first answer and continues to Provide its
bare handshake as a dial anchor. The connection's `answered` Provide moves it
from the 500 ms unanswered cadence to the 2 s known-peer cadence; a live socket
suppresses actual dialing. Read EOF and write failure both reset the
address-keyed outbound link and clear that connection's sent-memory, so the
anchor can redial and the next session can resynchronize immediately. The
responder remains arrival-driven and authors a response for each admitted
request.

**Two handshake modes, one shape.** *Bootstrap* signs the request with the invite
key and proves authority with the invite's `bootstrap_hash` (the secret the
inviter retains as `invite_accepted`). *Membership* — reconnect after both nodes
are enrolled, with no invite — signs with the member's own key and names its
`endpoint_shared` record; the responder verifies the signature against the
signing key that record binds. The endpoint (X25519) is machine-wide, one per
node and identical across every workspace (`auth.endpoint`, projecting no
marker, holding the secret); the per-workspace binding is `auth.device`: durable and
projecting a **sync leaf**, self-attested by the member's signing key,
valid only if that signer is an enrolled member, publishing
`endpoint_shared@auth = frame(endpoint, signing_pk, wid)` and an `endpoint_key`
reverse index. So a node that joins two workspaces has two device facts carrying
one identical endpoint, and recognizing a peer is a workspace-scoped
endpoint→member lookup. That lookup is the `auth` column of
`connection.connection.peers` — a query-side value-compare, never a hard Require,
so an unrecognized endpoint still connects and simply shows `anon`, matching
Authority's stance.

**Close is a death key, and forward secrecy is its verdict.** `connection.close`
(durable, no sync marker) Provides `closed` at an id; the request, connection,
and ephemeral secrets each carry `SuppressIf closed@SELF`, so admitting a close flips
the cluster to Suppressed — and suppression purges, so the ephemeral private
keys leave disk and memory at the close itself, no sweep to schedule. The
daemon drops the socket and stops dialing; the close fact is what a restart
keeps — the cluster it killed no longer exists to replay, and a reconnect
must author a fresh request. `sever` closes a whole cluster (connection +
request + both handshake ephemerals) from one connection id.

**Frame bundles are ephemeral transport.** A `connection.frame` bundle is
volatile and marker-free exactly like a sync compare — never stored, never in
leaves, excluded from the reconciliation it carries. Its one value packs many
length-framed canonical fact bytes (up to ~48 KiB of inner fact bytes per
frame); the sync driver's shipments ride bundles instead of one fact per wire
frame. A receiver unpacks a bundle and
admits each inner fact with the authenticated connection id, a bounded batch per turn — a
corrupt inner is a per-fact miss that never poisons its siblings, and the wrapper
itself is never admitted. Bundling amortizes framing, encryption, and socket
overhead during bulk catch-up while preserving per-inner admission checks.

## Content

`facts/content/` is the messaging surface: member-signed `channel` facts,
`message` (text routed by channel fact id), `reaction`, file attachments,
`message_deletion`, and
`retention_policy` (the retention window is an ordinary Provide;
last-write-wins is a read-side fold).

**Attachments are facts, not a second blob store.** `content.file` is the
message-attached descriptor. Content instance id, BLAKE3 root, byte and slice
geometry, filename, MIME, and encoding are separate named atoms; there is no
family-specific metadata record inside an atom value. `content.file_slice`
carries one indexed canonical Bao slice encoding: the requested bytes plus the
authentication path that proves them against the descriptor root. The
dependency arrows point only toward metadata:

```
Bao slice -> descriptor -> message
```

The message never Requires its descriptor or slices, so its dependency closure
does not drag attachment bytes. Each requested range is at most 256 KiB and a
descriptor may name at most 10 GiB. A slice's intrinsic gate bounds its index
and proof bytes. Its projector obtains root, length, slice count, width, encoding,
and message binding from one validated descriptor owner, then uses the official
Bao format to authenticate the range. Only projected proof Provides count toward
download progress. Save authenticates every proof again, streams the extracted
bytes through BLAKE3, checks root and total length, fsyncs a sibling temporary,
and atomically replaces its output path.

The descriptor is member-signed. It Requires the parent message's `posted`
Provide, its own signature key, and the workspace member keys; PROJECT rebuilds
the canonical SHAPE and accepts only when the parent's author key signed the
descriptor. Slices need no additional authorship claim: the canonical Bao proof
is self-validating against that signed descriptor's root.

The narrow `native/bao_py` binding uses the official Rust `bao` 0.13.1 crate for
streaming outboard creation, range extraction, and proof decoding. Send builds
one temporary outboard, extracts each bounded range proof in-process, verifies
all of them, then discards the outboard before admission. Projection and save
call the same optimized decoder, so engine validity never invokes a subprocess
or depends on host files. The dependency is pinned because upstream describes
Bao as beta cryptographic software that has not been formally audited.

Every descriptor and slice directly carries `SuppressIf` for the parent
message's `dead` key. A valid message deletion therefore terminally purges the whole attachment
from residency, durable bytes, SQLite, and the sync register. The deletion fact
is the durable replicated relationship; deleted bytes are not tombstone leaves,
and a laggard re-shipping an old attachment fact buys one admission that
re-derives Suppressed and dies.

The active attachment encoding is `clear-v1`, matching message bodies: bytes
are visible in the local fact store and sealed by the established-connection
transport on the wire. A content-key family can replace the payload with
ciphertext without changing the public descriptor/slice validation graph,
because the Bao root and proofs commit to the carried bytes.

- `channel` is replicated structural state whose fact id is the routing id and
  whose bounded UTF-8 name is only display data. It Requires its workspace,
  its detached signature, and the workspace member keys; any enrolled member
  may create one. A workspace bootstrap creates `general` through this same
  command path.
- `message` carries workspace, channel, body, author member id, and its own
  death key. It Requires the exact channel fact id, its signature key, and the
  workspace's member-key Provides. PROJECT rebuilds the canonical SHAPE and
  accepts only when the key blessed for the claimed author is one of the actual
  signers. The channel edge brings the workspace and channel signature into the
  message's transitive closure.
- `reaction` Requires the target message's valid `posted` Provide, carries the
  target's death key, and binds its claimed reactor member id to the signer.
  It parks without the message and is physically suppressed when the message
  is deleted.
- `message_deletion` is target-independent so the thing it must kill cannot
  race its validity. Any enrolled member may currently sign a deletion; a
  per-author policy is outside this implementation.
- `retention_policy` records a window as an ordinary Provide and binds its signer
  to both an enrolled member and an admin grant. The query chooses the latest
  `(timestamp, owner)` row, so last-write-wins is a read-side fold rather than
  kernel state.

Signed content makes the authority chain part of hydration and sync closure: a
message feed faults the author's membership resident, and a windowed sync id
list carries marker-owning authority ancestors below the floor. A detached
signature remains an independent fact when its target is suppressed unless it
also carries the applicable death key.

## Outside the Implemented Surface

- **Retention enforcement** — the signed policy fact and query exist, but no
  worker applies its horizon. Policy-based purge must preserve pins,
  dependency closures, and suppressors whose targets remain live. Semantic
  deletion is separate and immediate through SuppressIf; retention still needs a
  policy-driven deletion fact. Physical purge uses `DELETE`, and `VACUUM`
  reclaims SQLite file space.
- **Workspace sync lanes** — one global `b"sync"` register currently feeds
  every peer. Per-workspace authorization and coverage isolation are required
  before unrelated workspace sets can safely share a node.
- **Local-input drivers** — connection driving exists and time is a turn
  primitive; a general host-authored input family is not implemented.

## Testing

Tests mirror the protocol's quantifiers: admission-order tests shuffle fact
streams and assert identical derived state; codec, crypto, and storage tests
feed mutations and assert inert misses; treap tests pin history independence,
clamping invariance, deletion, and degenerate-spine safety; reliability tests
exercise loss, duplication, reordering, partitions, TTL dedup, anchor liveness,
and convergence certificates. The source-contract test keeps every fact file
in the prescribed module shape. Black-box stories drive `bin/tiny.py` and real
daemon subprocesses over Unix and TCP sockets. Hydration tests compare
demand-selected verdicts with a fully resident node, including suppression
across the cold boundary and authority closure for signed content.
