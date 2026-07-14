# TinyP2P language lab contract

This lab compares languages on the same executable slice of `poc-13`. It is
not a second implementation of every fact family, cryptographic primitive,
SQLite query, or socket option. Those would mostly measure ecosystem APIs and
porting effort. The slice keeps the mechanisms that determine whether the
kernel/runtime design is easy to express:

1. canonical binary atoms and facts;
2. content-derived fact ids;
3. exact/range matching with symbolic `SELF` materialization;
4. asserted and validated indexes;
5. `Suppress > Require > project` evaluation;
6. owner-scoped offer replacement, dependency wake-up, and terminal eviction;
7. bounded host turns with clock and shipped signals;
8. durable bytes, an outbox pump, route resolution, by-reference shipment,
   source-side deduplication, and incremental daemon wire framing.

## Deliberate substitutions and omissions

The production protocol uses BLAKE3. The lab uses SHA-256 because Go, Erlang,
and Python expose it in their standard libraries while Rust's normal SHA-256
crate is tiny. Hash choice does not alter any state-machine structure. The lab
domain is `tinyp2p.language-lab.v1`, so its ids cannot be mistaken for protocol
ids.

SQLite fault-in, family-owned observers/reserved answerers, crypto checks, and
real sockets are omitted. They are important production work, but they sit on
the tested seams represented here: admission, projection, durable bytes,
host signals, route/deliver callbacks, and the streaming wire decoder. The
report treats the omissions explicitly rather than extrapolating raw LOC as a
full rewrite estimate.

## Canonical data

Every scalar is an opaque byte string. `frame(parts...)` prefixes each part with
its unsigned 32-bit little-endian length. An atom encodes as framed parts:

```text
[kind, effect, target-tag], role, scope, target-parts..., value?
```

Kinds are `Need=0`, `Offer=1`; effects are `None=0`, `Require=1`, `Watch=2`,
`Suppress=3`; targets are `Exact=0`, `Self=1`, `Range=2`. Exact has one target
part, Self has none, and Range has two. Offers must have effect None. A
NUL-prefixed reserved role is legal only on a Watch need. Decode re-encodes and
requires byte equality, rejecting degenerate Range encodings and extra parts.

A fact is `frame(tag)` followed by `frame(encoded_atom)` for a strictly
increasing, duplicate-free atom sequence. Construction sorts and deduplicates
atoms by encoded bytes. Its lab id is:

```text
SHA256(frame("tinyp2p.language-lab.v1", tag, joined-framed-atoms))
```

Resident rows materialize Self as `Exact(owner-id)`; canonical bytes retain
Self.

## Evaluation

The root callback owns two operations:

- `extract(fact) -> durable?`
- `project(fact, validated-context) -> Out | no-family`

Admission strict-decodes, derives the id, is idempotent, indexes asserted rows,
records durable bytes when extracted, and queues the owner. A step faults no
storage in this lab, then applies:

```text
matching validated Suppress -> Suppressed
else missing validated Require -> Parked
else root.project(fact, answers to Require/Watch), default Parked
```

Only a Valid `Out` publishes its offers. Settlement atomically replaces all
validated offers from that owner, wakes asserted matching needs for changed
offers, and completely evicts Reap/Suppressed owners. A turn replaces the
transient `now@clock` and `shipped@wire` slots and steps at most `bound` queued
owners.

## Runtime and wire

`cycle` admits an inbox and executes one bounded turn. `outbox` reads validated
`send@outbox` (inline bytes) and `ship@outbox` (a framed list of fact ids).
`pump` groups rows by owner, resolves its target through `route`, resolves ship
ids through durable bytes, suppresses ids already sent on that route, calls
`deliver` with one batch, records only the delivered prefix, and reports fired
owners for the next turn's shipped signal.

The daemon wire is incrementally decoded as `u32be(length) || kind || body`.
Incomplete tails remain buffered. The outbound link is bounded and supports
partial drains without repeatedly copying its sent prefix.

## Required native tests

Each implementation proves, in its own test runner:

- canonical construction, strict round-trip, shared golden id, and malformed
  rejection;
- exact/range matching;
- Require parking followed by offer-triggered promotion;
- Suppress precedence, offer withdrawal, and whole-owner eviction;
- Watch re-projection from the clock signal and bounded turns;
- inline courier pump followed by shipped Reap;
- by-reference shipment deduplication and undelivered-tail retry;
- fragmented wire input and bounded partial output.
