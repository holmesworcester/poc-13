# TODO — handshake-port branch: remaining daemon integration

The handshake-port branch has the sealed request/connection handshake, transit
key agreement, sealed frame codec, and the trust-anchoring refactor (founder
deleted, invite_accepted acceptance gate) — all green IN-PROCESS
(test_handshake, test_crypto, test_sigs, test_invites, test_skeleton, test_sync
in-process, test_clock, test_hydrate, test_contract).

RED until M7 wires the daemon: the black-box story tests (test_solo, test_pair,
test_trio, test_sync's daemon leg). Rewire cond.py to poc-10's ADDRESS-KEYED
transport — the daemon is a stateless byte queue keyed by destination address;
NO per-socket session object, NO cid<->socket binding (facts name addresses and
inbound frames self-describe their connection_id):
- Transport = an address-keyed outbox (poc-10 network_outgoing(queue_key,
  target_addr, bytes)): `send`/`ship` offers name a DEST ADDRESS; the pump
  connects to that address and writes (persistent-pool or connect-per-drain, an
  efficiency knob — poc-10 chose stateless connect/send/close).
- Routing is fact-driven both ways: outbound reads the connection fact for
  (peer_addr, secret) and emits send@peer_addr of sealed bytes; inbound peeks
  frame_cid(wire) -> conn.secret(node, cid) -> open, regardless of which socket
  delivered it. `frame.py` already has frame_cid + conn.secret for this.
- Dial: the pump connects to any dest address with staged send offers. No
  dial-request family, no --peer; add a `connection.request.connect wid iid
  secret endpoint addr` CLI verb (bootstrap authors invite_accepted + the
  sealed request, whose send@addr drives the dial).
- Seams (host performs at a watched offer, reports via a fact): inbound request
  arrival -> author fact_receipt(REQUEST, origin=addr); `respond` offer ->
  connection.respond + send@origin_addr; the connection fact carries the peer
  address so no binding step is needed.
- Handshake facts (request/connection) travel bare (own X25519 envelopes);
  everything after is a sealed frame keyed by connection_id.
- Acceptance over the wire: the connect verb authors invite_accepted from the
  link, so the synced workspace validates on the joiner (else it parks).
- Then: wire-tap test (a known plaintext never appears post-handshake); peers()
  `auth|anon` via M6 endpoint_shared.

Follow-ups surfaced: admin DELEGATION (root key is dropped after bootstrap, so
only the founder's bootstrap admin is valid until an existing-admin-grants-admin
path lands, poc-10 authority_fact_id style); multi-workspace sync scoping
(global leaf tree is single-tenant).

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

Done (2026-07-03): fresh-facts-first landed as live-tail sends (poc-10
`advertise_indexed_fact_to_connections` ported into the daemon's quiescence
block) — a fresh leaf reaches a caught-up peer in ~37 ms (bench 5c, retargeted
2026-07-05 to measure exactly that steady-state live-tail latency).

Known perf (measured 2026-07-05): **bulk sync catch-up from empty is ~O(n²)**
with a sharp throughput cliff at ~1 MiB of shipped bytes (~2000 messages): fast
below it (thousands/s), a few hundred/s above. Two compounding causes — the
outbox `OUTCAP` (1 MiB) parks overflow, healed only on the next re-descend; and
the RBSR descent restarts from the root per bounded batch, re-fingerprinting the
growing tree (raising OUTCAP gave 2–4×; lowering CADENCE did nothing, so it is
not pacing-bound). Live-tail is unaffected. Fold the fix (resume/stream the
descent; re-ship parked frames when the outbox drains) into the residency/sync
split — the daemon-transition work. bench §5 budgets are loose tripwires until
then.

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
