#!/usr/bin/env python3
"""bench/bench.py — TinyP2P performance harness.  Run: python3 bench/bench.py

One file, stdlib only. Measures the load paths that matter, prints a table, and
exits nonzero if any budget is violated (so it can gate CI). A budget is a
ceiling (lower is better) or a floor (higher is better) with headroom for a
slower box — a tripwire for a real regression, not a tuned target.

The load is deliberately the shape the design assumes: one workspace, messages
fanned across a few channels. Two costs are made visible rather than hidden: full
in-memory replay and every sync `leaves()` are LINEAR over the resident set; the
daemon's cold start pays a full replay before it serves (§2). The two-daemon TCP
sync sections (§5) are now thousands of fact/s (mildly superlinear — see the note
there); budgets stay loose because the feed-poll used to detect convergence is
itself O(n) and the wall varies with the box. See README.
"""
import os, signal, socket, subprocess, sys, tempfile, time
BENCH = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(BENCH)
sys.path.insert(0, ROOT_DIR)
from kernel import Node, Store, encode, decode, fact_id, frame, unframe, _rd
from facts import ROOT
from facts.sync import index as _sidx
from facts.auth.workspace import workspace
from facts.content.channel import channel
from facts.content.message import message, feed
from facts.sync import compare as sync
from facts.auth import signature
from facts.auth.invite_accepted import invite_accepted
import crypto as ed

N = 10_000                               # the standard load: N messages (signed: 2N facts)
CHAN_NAMES = [b"c%d" % i for i in range(5)] # a few real channels, messages fanned across them
RK, RPK = ed.ed25519_keygen(bytes(32))
WS = workspace(b"acme", RPK, 1); WID = fact_id(WS)
# the facts that make WS Valid: root self-signature (marker-emitting) + local acceptance,
# plus one enrolled member and five signed channels. Every message also travels
# with its member signature.
sys.path.insert(0, os.path.join(ROOT_DIR, "tests"))
from content_fixtures import member_context, signed_channel, signed_message
MEMBER = member_context(WID, RK, RPK, t=1)
CHANNEL_BUNDLES = [signed_channel(MEMBER, WID, name, 2) for name in CHAN_NAMES]
CHANS = [fact_id(bundle[0]) for bundle in CHANNEL_BUNDLES]
WSPRE = [encode(WS), encode(signature.signature(b"auth", RPK, WID, ed.ed25519_sign(RK, WID), 1)),
         encode(invite_accepted(WID, bytes(32), bytes(32), b"", RPK, 1))] + \
        [encode(f) for f in (*MEMBER.facts, *(f for bundle in CHANNEL_BUNDLES for f in bundle))]
MSGS = [encode(f) for i in range(N)
        for f in signed_message(MEMBER, WID, CHANS[i % 5], b"m%d" % i, i + 3)]
BIN = os.path.join(ROOT_DIR, "bin")

# --- table + budgets ----------------------------------------------------------
FAIL = []
def report(name, val, unit, budget, hi_ok=False):
    # hi_ok=False: lower is better, violate if val > budget (a ceiling).
    # hi_ok=True : higher is better, violate if val < budget (a floor).
    bad = budget is not None and ((val < budget) if hi_ok else (val > budget))
    if bad: FAIL.append(name)
    mark = "  " if budget is None else ("!!" if bad else "ok")
    b = "" if budget is None else f"{'>=' if hi_ok else '<='} {budget:g}"
    print(f"  {mark} {name:<42} {val:>10.3f} {unit:<7} {b}")

def section(t): print(f"\n{t}")

# --- daemon plumbing ----------------------------------------------------------
def spawn(db, *a):                       # a tinyd.py daemon; returns (proc, announced addr)
    p = subprocess.Popen([sys.executable, os.path.join(BIN, "tinyd.py"), db, *a],
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    line = p.stdout.readline()
    assert line.startswith("listening:"), (line, p.poll() and p.stderr.read())
    return p, line.split()[1]

def stop(*ps):
    for p in ps: p.send_signal(signal.SIGTERM)
    for p in ps: p.wait(5)

def uverb(sockpath, path, *args):        # one proxy roundtrip over the daemon's unix socket
    s = socket.socket(socket.AF_UNIX); s.connect(sockpath)
    s.sendall(frame(path.encode(), *(a.encode() for a in args))); s.shutdown(socket.SHUT_WR)
    b = b""
    while (c := s.recv(65536)): b += c
    s.close(); r, _ = _rd(b, 0)
    if not r.startswith(b"+"): raise RuntimeError(r[1:].decode())
    return r[1:].decode()

def cli(db, *args):                      # a full tiny.py invocation (subprocess proxy to the daemon)
    r = subprocess.run([sys.executable, os.path.join(BIN, "tiny.py"), db, *args],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    return r.stdout.strip()

def peer(sa, sb, wid, addr_a, addr_b):   # B bootstrap-dials A; both daemons must be --listen-ing.
    iid, secret = uverb(sa, "auth.user_invite.invite", wid).split(":")   # A (founder) mints an invite
    ep = uverb(sa, "auth.endpoint.endpoint")                             # ... and exposes its endpoint pk
    uverb(sb, "connection.request.connect", wid, iid, secret, ep, addr_a, addr_b)

# --- 1. in-process engine: admit + run, then linear replay --------------------
def bench_engine():
    section("1. in-process engine (%d facts: %d signed messages)" % (len(MSGS), N))
    n = Node(ROOT)
    for b in WSPRE: n.admit(b)
    n.run()
    t = time.time()
    for b in MSGS: n.admit(b)
    n.run(); dt = time.time() - t
    report("admit+run", dt, "s", 3.0)                 # signed: 2N facts + N gate verifies
    report("  per fact", dt / len(MSGS) * 1e3, "ms", None)
    from facts.store import hydrate
    hydrate.demand(n)                                 # same seed fact on both sides
    st = Store()
    for b in n.durable.values(): st.add(b)
    t = time.time(); m = Node(ROOT, st); hydrate.demand(m); rp = time.time() - t
    assert m.derived() == n.derived(), "boot diverged"
    report("boot (one total demand)", rp, "s", 5.0)   # MEASURED ~2.9s at 2N signed facts (reconstruct + re-hash)
    return n

# --- 1b. deep Require chain: author it, then fault it back through one demand -
def bench_chain(depth=100):
    section("1b. deep Require chain (depth %d)" % depth)
    from types import SimpleNamespace
    from kernel import Atom, Exact, SELF, PROVIDE, REQUIRE, Out, Router, fact, ts_atom
    from facts.store import hydrate
    fam = SimpleNamespace(extract=lambda f: True,
                          project=lambda f, ctx: Out(provides=tuple(a for a in f.atoms if a.relationship == PROVIDE)))
    root = Router({b"chain": fam, b"store": hydrate})
    fbs, prev = [], None
    for i in range(depth):                # each fact Requires its predecessor: one 100-deep spine
        atoms = [ts_atom(1000 + i, b"w"), Atom(PROVIDE, b"doc", b"w", SELF)]
        if prev is not None: atoms.append(Atom(REQUIRE, b"doc", b"w", Exact(prev)))
        f = fact(b"chain.doc", *atoms); fbs.append(encode(f)); prev = fact_id(f)
    t = time.time()
    n = Node(root)
    for b in fbs: n.admit(b, checked=True)
    n.run()
    report("admit+run the chain", (time.time() - t) * 1e3, "ms", 10)      # MEASURED ~4ms
    st = Store()
    for b in fbs: st.add(b)
    st.commit()
    m = Node(root, st)
    t = time.time()
    hydrate.demand(m, b"doc", b"w", Exact(prev))      # ONE demand at the head faults the spine
    dt = (time.time() - t) * 1e3
    assert all(m.memo[fact_id(decode(b))] == "Valid" for b in fbs), "the whole spine validates"
    report("fault the spine (one keyed demand)", dt, "ms", 25)            # MEASURED ~10ms
    report("  per hop", dt / depth * 1e3, "us", None)

# --- 2. daemon cold-load, then one proxied verb against a big db --------------
def bench_cli(db):
    section("2. daemon boot + hydrate verb against a %d-fact db" % N)
    t = time.time(); p, _ = spawn(db)     # cold: the daemon loads nothing before "listening:"
    report("daemon cold boot (loads nothing)", time.time() - t, "s", 0.5)
    try:
        t = time.time(); uverb(db + ".sock", "store.hydrate.pull")        # residency is a verb
        report("hydrate everything (one verb)", time.time() - t, "s", 3.5)
        t = time.time(); cli(db, "content.message.send", "wid=" + WID.hex(), "c0", "warm", "t=98")
        report("daemon-proxy tiny.py (one verb)", time.time() - t, "s", 0.2)
    finally: stop(p)

# --- 3. query under load ------------------------------------------------------
def bench_query(n):
    section("3. query under load (%d messages)" % N)
    R = 50
    t = time.time()
    for _ in range(R): rows = feed(n, WID, CHANS[0])
    report("feed() / provided() scan", (time.time() - t) / R * 1e3, "ms", 5.0)  # MEASURED 1.0ms
    consumer = next(a for a in message(WID, CHANS[0], MEMBER.uid, b"x", 1, bytes(32)).atoms
                if a.name == b"channel")                              # the channel REQUIRE
    t = time.time()
    for _ in range(R): n.matches(consumer)
    report("matches() bucket lookup", (time.time() - t) / R * 1e6, "us", None)
    assert len(rows) == N // 5

# --- 4. sync: dependency-aware negentropy over a big set ----------------------
def _node(bs):
    n = Node(ROOT)
    for b in bs: n.admit(b)
    n.run(); return n

_CID = b"\x22" * 32                      # a fixed connection id for the in-process pair


def leaves(n): return set(_sidx.tree(n).keys)   # the reconciliation set as 40-byte (ts‖FactId) keys

def _reconcile(a, b, maxr=100_000):      # the daemon's exact wire discipline, in-process (mirrors test_sync)
    inbox, ver, fired = {a: [], b: []}, {a: None, b: None}, {a: [], b: []}
    frames, wire = [0], [0]
    def step(me, other):
        me.turn(shipped=tuple(fired[me])); fired[me] = []       # present last cycle's flush reports
        got, inbox[me] = inbox[me], []
        for blob in got: me.admit(blob)                         # admit what the peer sent
        me.run()
        if _sidx.ver(me) != ver[me]:                            # leaf set moved: open a fresh compare round
            sync.open_round(me, _CID, b""); ver[me] = _sidx.ver(me); me.run()
        did = False                                             # pump: deliver every send/ship Provide to the peer
        for name in (b"send", b"ship"):
            for o, _, at in me.provided(name, b"outbox"):
                blobs = ([at.value] if name == b"send"
                         else [me.durable[x] for x in unframe(at.value) if x in me.durable])
                inbox[other] += blobs; frames[0] += 1; wire[0] += sum(len(x) for x in blobs)
                if o not in fired[me]: fired[me].append(o)
                did = True
        return did or bool(got)
    while (step(a, b) | step(b, a)) and frames[0] < maxr: pass
    for n in (a, b): n.turn(shipped=tuple(fired[n])); n.run()   # final flush so the last couriers reap
    return frames[0], wire[0]

def bench_sync():                         # the incremental case; bulk catch-up is §5b (real daemon)
    section("4. incremental sync: a 1-fact diff over a %d-fact set" % N)
    a, b = _node(WSPRE + MSGS), _node(WSPRE + MSGS[:-1])   # b lacks exactly one leaf
    t = time.time(); fr, w = _reconcile(a, b); dt = time.time() - t
    assert leaves(a) == leaves(b)                         # the descent located and shipped just the diff
    report("1-fact diff: wall", dt, "s", 0.5)
    report("  frames", fr, "", 40)
    report("  wire", w / 1024, "KiB", 60)

# --- 5. two real daemons over TCP: sustained convergence ----------------------
# Bulk catch-up used to cliff at ~1 MiB (a few hundred fact/s past it); a 2026-07-05
# profiling pass fixed the four O(n^2) causes (frontier membership, bucket scan,
# un-batched pulls, and the flush rescan — see TODO.md), then the treap (now
# `facts.sync.index.Treap`) took the range fingerprint from O(range) to O(log n),
# clearing the last superlinear term in the tree (catch-up ~22% faster at 100k, ~3.8x
# at 500k, controlled A/B). What now dominates the 500k tail is the daemon layer
# (per-turn SQLite commit + admission + round-trips under OUTCAP), not the tree.
# Live-tail (§5c) is unaffected. Budgets stay loose regression tripwires — the
# feed-poll used to detect convergence is itself O(n) and understates throughput.
def bench_daemons():
    section("5. two daemons over TCP (min 30s / 2000 facts)")
    with tempfile.TemporaryDirectory() as d:
        dba, dbb = os.path.join(d, "a.facts"), os.path.join(d, "b.facts")
        pa, addr_a = spawn(dba, "--listen", "127.0.0.1:0")
        pb, addr_b = spawn(dbb, "--listen", "127.0.0.1:0")
        sa, sb = dba + ".sock", dbb + ".sock"
        try:
            wid = uverb(sa, "auth.workspace.create", "acme", "1")   # A is founder -> can mint invites
            peer(sa, sb, wid, addr_a, addr_b)                       # B bootstrap-dials A
            cap, t0, qlat = 2000, time.time(), None
            for i in range(cap):
                uverb(sa, "content.message.send", "wid=" + wid, "general", "m%d" % i, "t=" + str(i + 2))
                if i == cap // 2:                         # a query on B mid-stream
                    q = time.time(); uverb(sb, "content.message.feed", "wid=" + wid, "general")
                    qlat = (time.time() - q) * 1e3
                if time.time() - t0 > 30: cap = i + 1; break
            auth = time.time() - t0
            end = time.time() + 60
            while time.time() < end:
                got = len(uverb(sb, "content.message.feed", "wid=" + wid, "general").splitlines())
                if got >= cap: break
                time.sleep(0.05)
            conv = time.time() - t0
            mb = os.path.getsize(dbb) / 1048576   # B's db is exactly the fact bytes shipped
            report("author rate (A, via socket)", cap / auth, "fact/s", None)
            report("converged on B (end-to-end)", got / conv, "fact/s", 40, hi_ok=True)
            report("converged volume (B's db)", mb / conv, "MB/s", None)
            report("mid-stream query B latency", qlat, "ms", 25)
            assert got == cap, f"B converged only {got}/{cap}"
        finally: stop(pa, pb)

def bench_catchup():                      # a bulk backlog authored on A (the founder), then a
    n = 5000                              # fresh B bootstrap-dials A and catches the whole set up
    section("5b. sync catch-up over TCP (%d facts bulk-authored on A, fresh B)" % n)
    with tempfile.TemporaryDirectory() as d:
        dba, dbb = os.path.join(d, "a.facts"), os.path.join(d, "b.facts")
        pa, addr_a = spawn(dba, "--listen", "127.0.0.1:0"); sa = dba + ".sock"
        wid = uverb(sa, "auth.workspace.create", "acme", "1")
        for name in CHAN_NAMES: uverb(sa, "content.channel.create", "wid=" + wid, name.decode(), "t=2")
        for i in range(n):                                    # author the backlog on A (untimed setup)
            uverb(sa, "content.message.send", "wid=" + wid, CHAN_NAMES[i % 5].decode(), "m%d" % i, "t=" + str(i + 3))
        pb, addr_b = spawn(dbb, "--listen", "127.0.0.1:0")
        peer(sa, dbb + ".sock", wid, addr_a, addr_b)          # B bootstrap-dials A
        t0 = time.time()
        try:
            got, end = 0, time.time() + 120
            while got < n and time.time() < end:
                got = sum(len(uverb(dbb + ".sock", "content.message.feed",
                                    "wid=" + wid, c.decode()).splitlines()) for c in CHAN_NAMES)
                time.sleep(0.05)
            dt = time.time() - t0
            assert got >= n, f"caught up only {got}/{n}"
            mb = os.path.getsize(dbb) / 1048576               # B's db is exactly the fact bytes it synced
            report("catch-up (bulk sync)", n / dt, "fact/s", 800, hi_ok=True)  # ~5700 here; catches the old ~200/s cliff
            report("catch-up volume", mb / dt, "MB/s", 0.5, hi_ok=True)
        finally: stop(pa, pb)

def bench_newest():                       # live-tail: a freshly-authored leaf reaches a caught-up
    n = 2000                              # peer directly, not behind a fresh reconcile round
    section("5c. live-tail latency to a caught-up peer (after a %d-fact backlog)" % n)
    with tempfile.TemporaryDirectory() as d:
        dba, dbb = os.path.join(d, "a.facts"), os.path.join(d, "b.facts")
        pa, addr_a = spawn(dba, "--listen", "127.0.0.1:0"); sa = dba + ".sock"
        wid = uverb(sa, "auth.workspace.create", "acme", "1")
        uverb(sa, "content.channel.create", "wid=" + wid, "c0", "t=2")
        for i in range(n):                                    # a backlog B first catches up on (untimed)
            uverb(sa, "content.message.send", "wid=" + wid, "c0", "m%d" % i, "t=" + str(i + 3))
        pb, addr_b = spawn(dbb, "--listen", "127.0.0.1:0"); sb = dbb + ".sock"
        peer(sa, sb, wid, addr_a, addr_b)                     # B bootstrap-dials A
        try:
            end = time.time() + 60        # wait until B has fully caught up and gone quiet
            while time.time() < end and len(uverb(sb, "content.message.feed", "wid=" + wid, "c0").splitlines()) < n:
                time.sleep(0.02)
            t0 = time.time()
            uverb(sa, "content.message.send", "wid=" + wid, "c0", "newest", "t=" + str(n + 99))
            got, end = "", time.time() + 30
            while time.time() < end:
                got = uverb(sb, "content.message.feed", "wid=" + wid, "c0")
                if got.endswith("newest"): break
                time.sleep(0.01)
            dt = time.time() - t0
            assert got.endswith("newest"), "newest message never displayed on B"
            report("live-tail: newest visible on B", dt, "s", 2.0)
        finally: stop(pa, pb)

# --- 6. crypto gate: verify folded into admission, zero on replay -------------
def bench_crypto():
    section("6. signed-fact admission (Ed25519 gate)")
    sk, pk = ed.ed25519_keygen()
    M = 25
    # a valid detached signature over each target id (the id IS the signed message)
    facts = []
    for _ in range(M):
        tid = os.urandom(32)
        facts.append(encode(signature.signature(WID, pk, tid, ed.ed25519_sign(sk, tid), 3)))
    calls, orig = [0], signature.verify
    signature.verify = lambda *a: (calls.__setitem__(0, calls[0] + 1), orig(*a))[1]
    try:
        n = Node(ROOT)
        for b in WSPRE: n.admit(b)
        n.run()
        t = time.time()
        for b in facts: assert n.admit(b) is not None
        n.run(); dt = time.time() - t
        report("signed admits", M / dt, "adm/s", 6, hi_ok=True)   # MEASURED ~13/s
        report("  verify() cost", dt / M * 1e3, "ms", None)
        assert calls[0] >= M, "the gate must have verified each signature"
        calls[0] = 0
        from facts.store import hydrate
        hydrate.demand(n)                                         # same seed fact on both sides
        st = Store()
        for b in n.durable.values(): st.add(b)
        m = Node(ROOT, st); hydrate.demand(m)                     # boot from the durable rows
        report("boot verifies (must be 0)", calls[0], "", 0)
        assert m.derived() == n.derived()
    finally: signature.verify = orig

def main():
    print("TinyP2P bench  |  python", sys.version.split()[0], " facts:", N)
    n = bench_engine()
    bench_chain()
    with tempfile.TemporaryDirectory() as d:
        db = os.path.join(d, "big.facts")
        st = Store(db)
        from facts.auth.local_signer_secret import secret
        st.add(encode(secret(MEMBER.sk, MEMBER.pk, 1)))   # the daemon signs as the member
        for b in WSPRE: st.add(b)
        for b in MSGS: st.add(b)
        st.commit(); st.db.close()
        bench_cli(db)
    bench_query(n)
    bench_sync()
    bench_daemons()
    bench_catchup()
    bench_newest()
    bench_crypto()
    print("\n" + ("BUDGET VIOLATED: " + ", ".join(FAIL) if FAIL else "all budgets met"))
    sys.exit(1 if FAIL else 0)

if __name__ == "__main__":
    main()
