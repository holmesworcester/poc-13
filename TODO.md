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

Perf (profiled + largely fixed 2026-07-05). A "profile 10k–500k, isolate
segments, make it work" pass root-caused the apparent bulk-catch-up O(n²) to four
distinct bugs, all fixed (all tests green, bench budgets met):
  1. `_wake` used `o not in self.frontier` (deque membership, O(len)); a late-
     validating fact wakes N needs as the frontier grows 0→N → O(n²). Now a
     `_queued` set mirrors the frontier → O(1). Replay 295→61 µs/fact (5×).
  2. `needs_for`/`offers_for` scanned a whole (role,scope) bucket then filtered by
     `covers`; the volatile-courier `shipped` bucket got rescanned every turn
     (358M covers). Now `kernel.Bucket` indexes exact targets in a dict → O(1) point.
  3. `sync/compare.project` authored one `need` per claim, not the batched single
     pull it documents → catch-up frames 139k→16 at n=4000. `claims_within` also
     rescanned the whole summary per claim → now a bisect over sorted claims.
  4. `runtime.flush` rescanned ALL of `node.durable` each call → authoring N facts
     was O(n²) (the dominant cost, 36s/96s at 50k). durable is append-only, so scan
     only the new tail. Authoring is now linear (~0.2 ms/fact).
Also: bytes-buffer outbox → amortized-O(1) bytearray+offset, OUTCAP 1→32 MiB; a
Node `_sumcache` lets the static source answer repeated re-opens from cache.

The residual after those four (catch-up ~O(n^1.3)) was the sink re-fingerprinting
on each re-descend: the flat sorted-list `Skeleton.fp` was O(range).

Treap landed 2026-07-05 — the principled finish, following the paper poc-13 cites
(Meyer & Scherer, "RBSR Without Homomorphic Hashing"). `kernel.Skeleton` (sorted
list) → `kernel.Treap`: a history-independent, clamping-invariant treap. Range fp is
the CLAMPED Merkle label (walk the two boundary spines), a canonical function of the
in-range set — so peers agree with an ORDINARY hash (no XOR/sum fold; the non-
homomorphic stance is kept, NOT traded away). Range fp goes O(range) → O(log n):
tree-isolated root fingerprint 8 ms → 0.008 ms at 100k (~1000×), 78 ms → 0.011 ms at
500k. Clamped walks + fids/keys are iterative (a maliciously degenerate spine costs
O(n) time, never a stack overflow). `leaf_xor` (a hash of the leaf set) → `leaf_ver`
(a monotonic counter), so change-detection never hashes. (A deferred/range-scoped
leaf-hashing queue was built and measured, then removed: it only saved a NON-syncing
node ~11-21% of admit — a syncing node paid the same total — so it wasn't worth the
LOC. The eager treap keeps the tree current on each promote.) New `tests/test_treap.py`
pins clamping-invariance, history-independence, deletion, and the degenerate-spine
guard; a 4-agent adversarial pass (incl. an independent Algorithm-1 oracle) found no
soundness defects.

Result (controlled A/B, list vs treap): two-daemon catch-up 100k 39.6 s → 31.0 s
(~22%); 500k ~736 → ~2782 fact/s (~3.8×). Single-node admit/replay stays linear.

CleanBucket landed 2026-07-05 — the daemon-layer residual, isolated. A daemon
cProfile of the sink at 100k named `valid_offers` (the clean twin, the only
justifier) the #1 cost: it was the ONE index the earlier six-bug pass left as a
LINEAR SCAN of `self.clean[(role,scope)]` (the asserted index got `Bucket`; the
clean twin did not). Some (role,scope) bucket grows with n, so the scan was O(n)
per call × O(n) calls = O(n²). `kernel.CleanBucket` gives it the same exact/range
split as Bucket → a point lookup. Controlled A/B (pre 974cce9 vs post): catch-up
100k 59.8 s → 33.8 s, 200k 251.9 s → 143.8 s — a ~1.77× win (bench §3 confirms
valid_offers is now a 0.1 µs bucket lookup).

STILL superlinear after CleanBucket (200k/100k ≈ 4.3×): a SECOND O(n²) in the
re-descend structure. The sink re-opens a root compare on every leaf_ver change
(cond.py); each re-descend re-finds the (still large) remaining diff and the peer
re-advertises/re-ships facts already in the sink's inbox → the cost shows up as
codec (re-decoding re-sent compares/facts). Damping the immediate re-open was
tried and BACKFIRED (200k 143.8 s → 271.6 s: the immediate open is load-bearing —
it pulls the next batch promptly; without it the sink idles on the 500 ms cadence).
The real fix is source-side: don't re-ship a fact recently sent to a peer (poc-10
per-connection shipped-set) so a re-descend during drain costs O(diff) discovery,
not O(diff) re-shipping. Left as the next residual. bench §5 budgets stay loose.

Hash: `H` switched from the BLAKE2b-256 stand-in to real BLAKE3-256 (the `blake3`
package; `crypto.keyed_hash` too) — every fact id changes; all tests + bench green.

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

# fault-in branch: matching faults from the persisted relation

The store hook, hydration windows/budget, `missing_needs`, `Store.pull/all`,
`Node.replay`, and `runtime.load` are gone. The Store is a rows-only atom
relation (bytes derived: reconstruct → re-encode → re-hash); the engine's
fault leg checks each stepped need key once against it and admits cold owners
(`Node.checked` memo; the reserved `\x00all` total demand ends faulting for
the session). Boot is the insertion of ONE hydrate fact — and the daemon
doesn't even author it: cond boots cold, and `store.hydrate.pull` (a client
verb) makes a full replica; sync reconciles the resident set.
Existence in the store is the persisted certificate: boot re-verifies 0
signatures (benched). Standing (verdicts) is never persisted.

Adversarial review (5 finder lenses, refute-first verify pairs, 53 agents)
confirmed 4 distinct bugs, all fixed + pinned as tests:
- add() swallowed transient sqlite write errors while flush marked the fact
  flushed → silent permanent loss with a false `+ok` (regression vs main).
  Write errors now propagate whole; bad BYTES remain a miss.
- cond's signal handler raises SystemExit; landing between add()'s two
  inserts it escaped `except Exception` and RELEASE committed a torn
  half-fact that INSERT OR IGNORE then refused to heal → BaseException.
- A canonical zero-atom durable fact was stored but unreadable
  (`fact_bytes` required atom rows) → lost at every reboot; zero rows is
  now legal, the re-hash decides.
- Every add() self-committed (SAVEPOINT outside a transaction), voiding
  one-transaction-per-turn → explicit BEGIN; commit() ends the turn.
Plus two surviving mutants killed with new pins (savepoint removal,
DISTINCT drop in owners()).

## simplification pass (2026-07-13, on fault-in)

An ultracode audit (5 lenses, 13 adversarially-verified proposals) then applied
in nine commits, each suite-green:

- one frame dual: kernel.unframe everywhere (six byte-identical copies died);
  envelope readers/_splitN became unframe one-liners (now strict on field
  count); LOCAL_FULL/AUTH_FULL/CONN_FULL/inline → kernel.FULL.
- one Bucket class: rows end in the atom (r[-1]); the clean twin is the same
  index over (owner, ts, atom).
- targets are spans: Exact(v) = (v, v), SELF = () until mat; the 3-tag form
  survives only as wire tags in enc/dec_atom (bytes unchanged, no DOMAIN
  bump). Store 12 → 9 columns; _mk rebuilds SELF from lo == fid (a fact
  cannot target its own id; the re-hash certifies). covers() is point-in-span.
- deps() is pure (the _deps memo cleared whole on every admit — worthless).
- turn() presents now/shipped directly (wrappers inlined).
- cond: phantom RETAIN_FLOOR knob deleted; bare-message peek deleted (admit
  is the only door for wire bytes).
- cadence: idempotent (no first field, no daemon armed marker) and FIXED —
  the not-due branch used to wipe its tick slice and re-fire off the stale
  first boundary (a round every other busy cycle instead of every 500ms).
  test_cadence now probes two intermediate wakes; the forgetting mutant dies.
- slices left the kernel: one read-model; project(f, ctx); retention's LWW is
  a read-side max; cadence's memory is its own self-Watched tick offer.

kernel.py 699 → 650; code (kernel+bin+facts) net −87, tests −11 (several
audit proposals overlapped, so the sum of their verified deltas overstates
the union). Perf: bench all
budgets met (targets change measured noise-level; covers() itself is slower
but has no production call sites — it is the tested spec of the bucket/SQL).
Known gap left deliberately: the set-moved counter (leaf_ver, now
facts.sync.index.ver) is polled by bench/tests only; the daemon relies on
the cadence (DESIGN.md prose softened to match).

# TODO — LocalOnly ingress

LocalOnly gates egress only: extract()'s shareable bit keeps a fact from
syncing OUT, but cycle() admits every inbound wire byte with no provenance
filter, so a connected peer can write into b"local" scope — including
auth.local_signer_secret (identity selection: current() takes the first
sk/pk rows independently) and auth.invite_accepted (the trust anchor gating
workspace validity). The invariant to land: a fact family that never syncs
out is never admitted from the wire either — a one-line refusal at the
inbox seam (cond knows provenance; the kernel must not). Until then the
threat model assumes connected peers are honest about locals.
