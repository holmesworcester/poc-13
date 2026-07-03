# TODO — black-box tests

## Remaining: workspace isolation (needs sync scoping)

`test_workspaces.py::test_workspace_lanes` — one matrix test porting poc-10's
isolation pair (`tests/black_box_sync_test.rs:67` private workspace never
leaks; `:94` alice/bob/carol scopes separate) plus its mutual-workspaces test
(`:25`). W1: alice+bob+carol; W2: alice+bob; W3: alice+carol; W4: alice alone;
distinct message counts per workspace so any cross-bleed shows as a count
mismatch. Asserts: everyone converges W1; bob gets W2 and never W3/W4; carol
gets W3 and never W2/W4; W4 never leaves alice.

EXPECTED TO FAIL today: the pump offers every durable+shareable fact to every
peer and `facts/sync/compare.py` reconciles one global `b"sync"` scope — there
is no per-workspace sync scoping. Land the negative lanes as xfail; they are
the spec for the sync-scoping work, and xfail flipping to xpass is the signal
it landed. The positive lanes (multiple mutual workspaces converge
independently) should pass immediately.

Related open design item, measured by `bench.py` 5c: a fresh message authored
mid catch-up does not jump the queue — its visibility on the receiver is the
remaining catch-up time (~3.6s against a 5k backlog). Fresh-facts-first would
show up as that number collapsing.

## Done (2026-07-03): consolidation + ports

The black-box suite was collapsed from 15 tests in four files to 4 story tests
in three, sharing `tests/harness.py` (converge/never with phase-labeled
failures naming node, verb, expectation, and last observed output; fleet()
appends every daemon's stderr tail to any failure).

- `tests/test_solo.py` — one node: cold crash-and-demand CLI, identity/join/
  admin, reactions, deletion, retention, outbox, daemon proxy parity, restart
  replay. Absorbed test_blackbox.py and test_daemon.py's proxy test.
- `tests/test_pair.py` — two daemons: parked-until-root, invite chain both
  ways, reaction closure, concurrent authorship merge, cross deletions,
  partition+heal, restart-both no-resurrection; plus never-wedges (absent +
  never-reading peers, burst under query load). Absorbed the rest of
  test_daemon.py, all of test_multiplayer.py, and test_invites.py's black box.
- `tests/test_trio.py` — hub through alice: sequential invites, late-joiner
  carol, relayed legs, offline ~1k delta (unix-socket authored), rejoin
  catch-up with tail markers, post-rejoin liveness all directions. Ports
  poc-10 `black_box_sync_test.rs:673` and poc-7 `cli_test.rs:1997`; absorbed
  three_node_relay.
- `bench.py` 5c — newest-message-visible mid catch-up, budgeted (ports poc-7
  `daemon_tiered_window_perf_test.rs:479` distilled).
