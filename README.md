# poc-13 — the atom model

poc-13 is an executable proof of concept for a small local-first, peer-to-peer
backend for collaboration applications such as team chat. It explores whether
identity, validation, storage, demand-driven loading, synchronization, transport,
and application behavior can share one data language instead of accumulating a
separate mechanism for each concern.

That language is made of immutable facts containing needs and offers called
atoms. Facts are the units of identity and wire transfer; atoms are the units of
storage and matching. A command authors a fact, the kernel matches its needs
against validated offers, and the owning fact family decides what the fact
means. The same model represents workspaces, membership, messages, deletions,
peer connections, sync compares, timers, and queues.

The implementation is intentionally compact and inspectable, and is not
production software. The concrete protocol currently demonstrates workspace
and invite authority, member-signed messages and reactions, signed deletion and
retention policy, demand-driven SQLite hydration, sealed peer sessions, and
dependency-aware set reconciliation.

The design of record is [`DESIGN.md`](DESIGN.md).

## How it works

```text
command
  -> canonical fact + detached signature
  -> admission and need/offer matching
  -> one SQLite row per atom
  -> validated offers and family-owned derived indexes
  -> treap range reconciliation
  -> sealed fact bundles to peers
  -> the same admission path on receipt
  -> queries over validated offers
```

SQLite does not store canonical fact blobs. Its durable relation is a
two-column `facts(fid, tag)` spine plus one `atoms` row for every atom. Reads
regroup those rows, reconstruct the canonical fact, re-encode it, and verify
that it hashes to `fid`. Corrupt or inconsistent rows are therefore a miss,
not a different fact. Validity, resident fact objects, match buckets, sync
labels, family registers, and queues are derived state.

The main pieces are:

- [`kernel.py`](kernel.py) — canonical identity, admission, matching, the
  bounded turn loop, demand faults, and two generic family-index seams:
  `settle()` and `answer()`.
- [`facts/`](facts/) — one module per fact family. Each module owns SHAPE,
  EXTRACT, optional CHECK, PROJECT, COMMANDS, QUERIES, and CLI. Projectors are
  also the routing tree, so protocol policy stays out of the kernel.
- [`facts/sync/index.py`](facts/sync/index.py) — the sync family’s own
  rebuildable register: leaf membership, a history-independent Merkle treap,
  summary memo, and version counter. The kernel contains no sync tree.
- [`facts/connection/`](facts/connection/) — sealed handshake, session,
  frame-bundle, close, and ephemeral-secret families. A durable answered
  request remains the known-peer anchor and redials only when its session is
  down.
- [`bin/cond.py`](bin/cond.py) and [`bin/runtime.py`](bin/runtime.py) — the
  single-writer daemon and its socket-free host-turn seam. The daemon performs
  no database-wide boot load; it demands local identity plus whatever later
  queries and hydrate facts request from the atom store.
- [`bin/con.py`](bin/con.py) — a thin client for
  `con <db> <scope.fact.verb> [args...]` over `<db>.sock`.
- [`tests/`](tests/) — kernel contracts, randomized order and adversarial
  storage cases, hydration, sync and reliability properties, and real
  multi-daemon stories over sockets.

## Current scope

The prototype has a global resident sync set per node. Workspace-scoped sync
lanes and negative multi-workspace isolation are not implemented yet. Also,
`LocalOnly` currently controls sync egress but is not enforced on wire ingress,
so the present threat model assumes connected peers do not send local-only
families. Blob content and retention-policy enforcement remain outside the
implemented surface.

## Quick start

Python 3.13 is used on the build machine. Install the three runtime/test
dependencies:

```bash
python3 -m pip install pynacl blake3 pytest
```

Start the daemon in one terminal:

```bash
bin/cond.py w.facts --listen 127.0.0.1:41000
```

Then use the CLI from another terminal:

```text
$ bin/con.py w.facts auth.workspace.create acme
<workspace-id>
$ bin/con.py w.facts content.channel.list <workspace-id>
<channel-id> general
$ bin/con.py w.facts content.channel.create <workspace-id> random
<channel-id>
$ bin/con.py w.facts content.message.send <workspace-id> general al "hello"
<message-id>
$ bin/con.py w.facts content.message.feed <workspace-id> general
hello
```

`auth.workspace.create` authors a replicated, member-signed `general` channel.
Additional channels are `content.channel` facts: their fact ids are routing ids
and their bounded UTF-8 names are display data. Message commands accept either
a validated name or a 64-hex channel id. A message cannot validate until the
exact channel fact, its signature, and its workspace authority closure are
valid, so channel lists and isolated feeds converge across peers instead of
depending on local aliases that happen to share a string.

The daemon starts cold. A normal query faults only the keys it needs;
`bin/con.py w.facts store.hydrate.pull` explicitly makes the complete durable
set resident, which is also required before claiming full sync coverage.

Run the tests and performance harness with:

```bash
pytest -q
python3 bench/bench.py
```

## Performance

These numbers were measured on the build machine with Python 3.13.7. The
standard corpus is 10,000 signed messages: each message and its detached
signature is a separate durable fact, so the load contains about 20,000 facts
plus the small authority spine. Rates described as messages per second include
both facts and their validation work.

| path | measured cost |
|---|---:|
| admit + settle 10k signed messages / 20k facts | 2.22 s (0.111 ms/fact) |
| rebuild the same set from atom rows with one total demand | 2.96 s |
| daemon cold boot (no database-wide hydration) | 0.040 s |
| hydrate the full signed-message database through one verb | 3.16 s |
| one CLI verb through a hydrated daemon | 0.024 s |
| fault a 100-deep `Require` spine from one keyed demand | 5.60 ms (56.0 µs/hop) |
| `feed()` over 10k messages | 1.67 ms |
| reconcile a one-fact diff in the ~20k-leaf set | 0.018 s, 14 frames, 51.3 KiB |
| two daemons, sustained author / convergence rate | 901 / 721 signed messages/s; 2.00 MB/s |
| query latency during sustained sync | 1.69 ms |
| fresh-peer catch-up of 5k signed messages | 1,364 messages/s (~2,728 facts/s), 3.87 MB/s |
| newest message visible on a caught-up peer | 0.55 s |
| Ed25519-gated signature admission | 10,534 facts/s; replay verifies 0 signatures |

Full hydration reconstructs each selected fact from atom rows and rebuilds
derived indexes, so a total pull scales with the stored atom set. Point matching
uses indexed buckets; a point lookup does not scan every same-role row. Sync
range fingerprints use the treap’s clamped Merkle labels and take expected
`O(log n)` local work, while mismatch depth is `O(log_B n)` and a fresh replica
still transfers `O(n)` facts. Sync covers the resident set, so a node that wants
whole-database reconciliation first issues the total hydrate demand.
