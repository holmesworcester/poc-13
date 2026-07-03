# poc-13

The atom model played for conciseness: a single-file kernel, a `facts/` tree
where every fact family is one file with one fixed contract, and a CLI whose
db is sqlite holding one dumb table of canonical fact bytes (plus a derived
match index the kernel's Store owns). The design of record
is `docs/DESIGN.md`; protocol semantics descend from poc-12, where they were
proven.

- `kernel.py` — identity, admission, matching, the turn loop. Nothing else:
  sync, queues, effects, clocks, content, and retention are fact families.
- `facts/<scope>/<fact>.py` — one file per family, six parts, always in
  order: SHAPE, EXTRACT, PROJECT, COMMANDS, QUERIES, CLI. Projectors are
  the routers: `facts.ROOT` dispatches type tags, api paths, and CLI verbs
  through one tree. The module is the Python API.
- `bin/con.py` — `con <db> <scope.fact.verb> [args...]`. Proxies to a
  running daemon at `<db>.sock`, else a crash-and-demand: the file is
  indexed cold and hydration pulls only what the verb asks about.
- `bin/cond.py` — `cond <db> [--listen HOST:PORT] [--peer HOST:PORT ...]`.
  The daemon: owns the db, amortizes replay, serves con over the unix
  socket, reconciles facts (the wire's only message) with TCP peers via the
  sync family. Peers come from `connection.request` facts (`--peer` authors
  one each); shipments ride `connection.frame` bundles. Backpressure everywhere
  is the frontier's rule: park, never drop.
- `facts/sync/compare.py` — dependency-aware negentropy: range-fingerprint
  reconciliation over `(ts, FactId)` leaves, closures so tombstones travel,
  compare frames that are themselves volatile, unshareable facts.
- `facts/connection/` — peer sessions as facts: a durable `request`/`close` to
  dial and retire a peer, a signed volatile `hello` binding a session to an
  identity key at the gate, a volatile `connection` record, and a `frame` bundle
  that packs many facts into one wire frame for bulk-catch-up throughput.
- `tests/` — skeleton tests (kernel claims), a source-contract test (fact
  file shape), and black-box tests (one process per command, plus real
  daemon subprocesses on real sockets).

Run: `pytest` or `python3 tests/test_<name>.py`. No dependencies.

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
| admit + run 10k facts | ~0.35s (0.035 ms/fact) |
| full in-memory replay of 10k facts | ~0.54s |
| one verb, cold `con.py` (crash + demand + verb) | ~0.04s |
| same verb via the daemon (replay amortized) | ~0.04s |
| `feed()` query over 10k messages | ~1 ms |
| sync a 1-fact diff into a 10k set | 28 rounds, ~9 KiB, ~0.35s |
| two daemons over TCP, sustained | ~395 authored facts/s converged, query stays low-ms |
| bulk sync catch-up (5000 facts, fresh peer) | ~1900 facts/s, ~0.58 MB/s (frame bundles) |
| signed-fact admission (Ed25519 verify) | ~14/s; replay re-verifies **0** |

**Where the linearity lives now.** The db is the kernel `Store`: sqlite holding
the dumb `facts(fid, bytes)` table plus a derived atom index, WAL-journaled.
A cold `con.py` is demand-driven — hydration pulls only the facts the verb's
needs and queries ask about, which is why the cold-verb cost above matches the
daemon-proxy cost instead of a full replay. Full `replay()` and every sync
`leaves()` remain linear over the resident set — the daemon full-loads
deliberately, because sync fingerprints must cover the whole durable set (a
partially-hydrated node must never initiate compare rounds). If a single db
ever outgrows the daemon's resident set, the next step is teaching the sync
family to ship from the Store rather than from residency — a family change,
not a kernel one. Linear is accepted and measured, not hidden.

