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
  socket, exchanges facts (the wire's only message) with TCP peers.
  Backpressure everywhere is the frontier's rule: park, never drop.
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
