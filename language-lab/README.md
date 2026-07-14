# Which language fits the TinyP2P kernel and runtime?

## Result

For the stated objective—minimum conceptual complexity and lines of code—keep
`poc-13` in Python.

Elixir is the interesting second choice. It expresses binary parsing and daemon
ownership well and used 1.58x the Python code for the same executable slice.
Strict TypeScript placed third at 1.92x; Node makes the daemon side convenient,
but value-safe opaque bytes and relational indexes need substantial explicit
machinery. Go and Rust both needed about 2.2x. Rust buys the strongest
compile-time model; Go buys the most conventional production-daemon story.
None is a reduction in the amount of machinery a reader must hold.

The practical recommendation is:

1. Keep the kernel, families, runtime seam, and daemon in one Python process
   while this is a compact executable design/protocol exploration.
2. Continue moving only measured byte/crypto hotspots behind narrow Rust
   bindings, as `native/bao_py` already does.
3. If the project later needs a single-language production rewrite, choose
   Rust when protocol invariants, memory safety, and predictable performance
   justify roughly twice the source. Choose TypeScript when Node integration
   and iteration speed dominate, or Go when a simple static deployment and a
   conventional network daemon matter more than encoding invalid states out of
   the kernel model.
4. Do not split an Elixir daemon from a Python/Rust kernel by RPC merely to use
   OTP. The extra serialization, failure, deployment, and atomic-turn boundary
   is more conceptual machinery than this daemon currently contains. Elixir is
   credible only as a whole-system choice.

## Measured result

The five implementations execute the contract in [`CONTRACT.md`](CONTRACT.md):
canonical facts, SHA-256 content ids, exact/range matching, Require/Watch/
Suppress evaluation, owner-scoped replacement and eviction, bounded host
turns, durable by-reference outbox pumping with delivered-prefix deduplication,
and incremental/bounded daemon wire buffers.

`cloc 2.04` counts production files separately from native tests:

| Language | Production code | vs Python | Physical lines | Test code |
|---|---:|---:|---:|---:|
| Python 3.13 | 419 | 1.00x | 520 | 229 |
| Elixir 1.18 / OTP 27 | 664 | 1.58x | 815 | 266 |
| TypeScript 7 / Node 24 | 804 | 1.92x | 920 | 354 |
| Go 1.24 | 913 | 2.18x | 1,020 | 453 |
| Rust 1.93 | 919 | 2.19x | 1,003 | 388 |

Test LOC is shown only for transparency. It is not a language score: the
native suites use different assertion styles and some add extra cases. Every
suite has at least eight top-level scenarios and covers every required
behavior. All five compute the same golden id,
`33a234f18d975af511b7648e6199ac1db55521a60b811e1478e57fe16943b8c7`.
The pump tests also follow the real lifecycle: short delivery fires and reaps
the current courier, then a newly authored cadence demand retries only the
unrecorded tail; shipped feedback is retained across bounded backlog until the
courier actually steps.

For scale, the current real [`kernel.py`](../kernel.py),
[`bin/runtime.py`](../bin/runtime.py), and [`bin/tinyd.py`](../bin/tinyd.py)
contain 589 `cloc` code lines together (981 physical lines including the design
commentary). That is not an apples-to-apples sixth row: the real files include
SQLite fault-in, family observers/answerers, flush bookkeeping, crypto/wire
integration, real sockets, reconnect cadence, and CLI service. The lab omits
those equally in every language; it measures the state-machine and byte-level
expression cost rather than claiming to estimate a completed port exactly.
It is not an execution-speed benchmark. The ports use idiomatic but not
identical data structures (for example Rust uses an ordered exact-key map while
the other kernels scan exact keys for range queries), so the LOC table must not
be read as a throughput or allocation result.

## What the code made apparent

### Python

Python is not winning only through untyped tuples. The lab uses explicit enums,
frozen data classes, a target type, a projector protocol, and the same indexed
bucket structure as the typed ports. It is shorter because bytes, tuples, dict
keys, callbacks, SQLite, and a single-owner mutable state machine are all direct
language/library values. The production code has already concentrated risk at
good seams: strict decode, projector callbacks, `cycle`, `route`, and `deliver`.

The cost is runtime enforcement. Invalid variants, callback shape, aliasing,
and partial mutation are prevented by tests and conventions rather than the
compiler. CPU-heavy matching also remains under the GIL. Those are reasons to
add tests and profile native kernels, not evidence that a wholesale rewrite is
conceptually smaller.

### Elixir

Elixir was the only alternative materially closer to Python. Binary pattern
matching makes framing pleasant, tagged tuples express targets cleanly, and
OTP's restart model matches the architecture unusually well: SQLite is durable
authority, derived engine state is rebuildable, and dropped volatile link
buffers heal through cadence.

The kernel itself is less compact. Every admission, settlement, wake, and
eviction threads a new nested map state; efficient outbound buffering needs a
chunk queue. An idiomatic production design should use one Engine `GenServer`
as the sole Node/SQLite owner, supervised inbound readers, and one bounded
outbound-link process per address. Facts and atoms should remain values, not
processes. That OTP wrapper was deliberately not added to the equal-scope lab,
so this experiment supports the functional-core result and the architectural
fit—not a measured LOC claim about a complete Elixir daemon.

### TypeScript

Strict TypeScript gives the runtime a pleasant shape: discriminated unions make
target and verdict branching exhaustive, typed callbacks document the
kernel/runtime seam, and Node already supplies hashing, buffers, networking,
and an event loop. It is a credible whole-system option for a team already
operating Node services, and it remained shorter than the Go and Rust ports.

It did not approach Python's density. `Buffer`, `Map`, and `Set` use object
identity rather than byte-value identity, so the implementation needs stable
content keys, defensive copies, and explicit row keys. Readonly types are
shallow and erased, so strict decoding and tests still enforce the wire
boundary. The type annotations and discriminated unions help readers, but do
not eliminate the mutable-runtime risks that Rust prevents. At 804 production
code lines, TypeScript is a pragmatic ecosystem choice rather than the LOC or
conceptual-compression winner.

### Go

Go produces a clear, deployable shape: one engine owner, typed route/deliver
functions, goroutines around I/O, and a single binary. Its standard library was
enough for the whole lab. The daemon would likely be easier to operate than the
manual Python `select` loop.

The relational kernel is verbose. Opaque bytes become a binary-safe `string`
type so atoms can be map keys; optional bytes need a separate `HasValue`; sets,
sorting, error propagation, and owner deltas are explicit loops. Targets remain
tagged structs with representable invalid combinations. Go is a good “boring
production service” candidate, but it did not compress this design.

### Rust

Rust gives the best kernel boundary: exhaustive `Target`, `Effect`, `Verdict`,
fact/signal owner distinctions, explicit `Result` failures, deterministic
`BTreeMap` buckets, and static projector callbacks. Several category mistakes
become impossible or compiler-visible. The socket-free `route`/`deliver` seam
also maps cleanly to generic closures.

That clarity costs source-level mechanics: owned byte vectors, cloning choices,
error plumbing, generic bounds, staged borrows during settlement, and explicit
collection conversion. A real `rusqlite` store and `mio`/Tokio daemon would add
more scaffolding than Python's built-in SQLite and current `select` loop. Rust
is the static-safety and predictability candidate, not the
conceptual-compression or LOC winner; this lab does not establish a throughput
winner.

## Why not another language?

These candidates span the useful design space: dynamic/mutable (Python),
functional/actor (Elixir), gradual static/GC (TypeScript), simple static/GC
(Go), and algebraic/ownership-checked (Rust). Raw JavaScript was not tested
because the requested candidate is TypeScript. C, C++, Zig, and Java would not
plausibly beat these LOC results. OCaml/F# or Gleam could make the pure kernel
attractive, but their SQLite, crypto, and daemon ecosystems would dominate a
small project and they offer no clear route to fewer whole-system concepts than
Python or Elixir.

## Reproduce it

Run every native suite:

```bash
# Installs the locked TypeScript development dependencies when absent.
./language-lab/run_all.sh
```

Run stricter language checks:

```bash
cargo fmt --manifest-path language-lab/rust/Cargo.toml --check
cargo clippy --manifest-path language-lab/rust/Cargo.toml --all-targets -- -D warnings
(cd language-lab/go && go test -race ./... && go vet ./...)
tmp=$(mktemp -d); elixirc --warnings-as-errors -o "$tmp" \
  language-lab/elixir/kernel.exs language-lab/elixir/runtime.exs; rm -rf "$tmp"
mix format --check-formatted language-lab/elixir/*.exs
(cd language-lab/typescript && npm run typecheck && npm test && \
  node --check model.ts && node --check kernel.ts && \
  node --check runtime.ts && node --check lab.test.ts)
```

Recompute LOC (requires `cloc`):

```bash
./language-lab/measure_loc.sh
```
