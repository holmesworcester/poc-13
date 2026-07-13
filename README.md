# poc-13

The atom model played for conciseness: a single-file kernel, a `facts/` tree
where every fact family is one file with one fixed contract, and a CLI whose
db is sqlite holding one dumb table of canonical fact bytes (plus a derived
match index the kernel's Store owns). The design of record
is [`DESIGN.md`](DESIGN.md); protocol semantics descend from poc-12, where they
were proven.

- `kernel.py` — identity, admission, matching, the turn loop. Nothing else:
  sync, queues, effects, clocks, content, and retention are fact families.
- `facts/<scope>/<fact>.py` — one file per family, six parts, always in
  order: SHAPE, EXTRACT, PROJECT, COMMANDS, QUERIES, CLI. Projectors are
  the routers: `facts.ROOT` dispatches type tags, api paths, and CLI verbs
  through one tree. The module is the Python API.
- `bin/con.py` — `con <db> <scope.fact.verb> [args...]`. Proxies to a
  running daemon at `<db>.sock`; with no daemon reachable it refuses and
  names the daemon to start.
- `bin/cond.py` — `cond <db> [--listen HOST:PORT]`. The daemon: owns the db,
  boots cold — residency is demanded, and `con <db> store.hydrate.pull`
  (one verb, one fact) makes a full replica; there is no load or replay
  path. Serves con over the unix socket, reconciles facts (the wire's
  only message) with TCP peers via the sync family. A peer is dialed by a durable
  sealed `connection.request` fact (the `connect` verb authors one); shipments ride
  `connection.frame` bundles. Backpressure everywhere is the frontier's rule: park,
  never drop.
- `facts/sync/compare.py` — dependency-aware reconciliation over the kernel's
  radix Merkle skeleton: prefix-fingerprint descent over `(ts, FactId)` leaves,
  splitting by count. A round carries a floor — a full round advertises leaves
  only, a windowed one also rides each leaf's below-floor dependency closure, so a
  recent fact validates without a dependency round-trip. Compare frames are
  volatile, unshareable, content-addressed facts; the daemon dedups them (and the
  fact ships) per connection, so a re-descend is fresh discovery, never re-work,
  and a converged pair falls silent.
- `facts/connection/` — peer sessions as facts: a durable sealed `request` to
  dial a peer and a `close` to retire it, a volatile `connection` record
  binding the session to a key, per-handshake `ephemeral_secret`s purged for
  forward secrecy, and a `frame` bundle that packs many facts into one wire
  frame for bulk-catch-up throughput.
- `tests/` — skeleton tests (kernel claims), a source-contract test (fact
  file shape), and black-box tests (one process per command, plus real
  daemon subprocesses on real sockets).

Run: `pytest` or `python3 tests/test_<name>.py`. Two dependencies: PyNaCl and
blake3 (`pip install pynacl blake3`).

```
$ bin/con.py w.facts auth.workspace.create acme        # prints <wid>
$ bin/con.py w.facts content.message.send <wid> general al "hello"
$ bin/con.py w.facts content.message.feed <wid> general
hello
```

## Performance

`python3 bench/bench.py` — one file, stdlib only, ~20s. It prints a table and
exits nonzero if any budget is violated, so it gates CI. Budgets sit at ~2x the
value measured on the build machine: headroom for a slower box, a tripwire for a
real regression. Headline numbers over a 10,000-fact workspace (one laptop core):

| path | cost |
|---|---|
| admit + run 10k facts | ~0.47s (0.047 ms/fact) |
| boot 10k facts from rows (one total demand) | ~1.0s |
| daemon cold boot (loads nothing) | ~0.03s |
| hydrate a 10k-fact db (one verb) | ~1.2s |
| one verb via the daemon (hydrated) | ~0.02s |
| fault a 100-deep Require spine (one keyed demand) | ~6ms (~58 us/hop) |
| `feed()` query over 10k messages | ~1 ms |
| sync a 1-fact diff into a 10k set | 28 rounds, ~9 KiB, ~0.35s |
| two daemons over TCP, sustained | ~395 authored facts/s converged, query stays low-ms |
| bulk sync catch-up (5000 facts, fresh peer) | ~1900 facts/s, ~0.58 MB/s (frame bundles) |
| signed-fact admission (Ed25519 verify) | ~15k/s gated; boot re-verifies **0** |

**Where the linearity lives now.** The db is the kernel `Store`: sqlite holding
the persisted atom relation (one row per atom; canonical bytes derived on
read — reconstruct, re-encode, re-hash), WAL-journaled. A session with a
store is demand-driven — a stepped fact's needs fault only what they ask
about resident, so a bounded working set costs its own size, not the db's.
Hydration and every sync `leaves()` remain linear over the resident set —
sync reconciles what is resident, so the operator's total pull is what makes
fingerprints cover the whole durable set (coverage-clipped partial sync is a
later wave). If a single db
ever outgrows the daemon's resident set, the next step is teaching the sync
family to ship from the Store rather than from residency — a family change,
not a kernel one. Linear is accepted and measured, not hidden.

