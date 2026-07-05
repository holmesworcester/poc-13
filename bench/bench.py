#!/usr/bin/env python3
"""bench/bench.py — poc-13 performance harness.  Run: python3 bench/bench.py

One file, stdlib only. Measures the load paths that matter, prints a table, and
exits nonzero if any budget is violated (so it can gate CI). A budget is a
ceiling (lower is better) or a floor (higher is better) with headroom for a
slower box — a tripwire for a real regression, not a tuned target.

The load is deliberately the shape the design assumes: one workspace, messages
fanned across a few channels. Two costs are made visible rather than hidden: full
in-memory replay and every sync `leaves()` are LINEAR over the resident set; the
daemon's cold start pays a full replay before it serves (§2). The two-daemon TCP
sync sections (§5) run in a slow, variable regime past ~1 MiB of shipped bytes —
see the note there — so their budgets are loose smoke-test floors. See README.
"""
import os, signal, socket, subprocess, sys, tempfile, time
BENCH = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(BENCH)
sys.path.insert(0, ROOT_DIR)
from kernel import Node, Store, encode, decode, fact_id, frame, _rd
from facts import ROOT
from facts.auth.workspace import workspace
from facts.content.message import message, feed
from facts.sync import compare as sync
from facts.auth import signature
from facts.auth.invite_accepted import invite_accepted
import crypto as ed

N = 10_000                               # the standard load: facts admitted + run
CHANS = [b"c%d" % i for i in range(5)]   # a few channels, messages fanned across them
RK, RPK = ed.ed25519_keygen(bytes(32))
WS = workspace(b"acme", RPK, 1); WID = fact_id(WS)
# the facts that make WS Valid: root self-signature (shareable) + local acceptance
WSPRE = [encode(WS), encode(signature.signature(b"auth", RPK, WID, ed.ed25519_sign(RK, WID), 1)),
         encode(invite_accepted(WID, bytes(32), bytes(32), b"", RPK, 1))]
MSGS = [encode(message(WID, CHANS[i % 5], b"al", b"m%d" % i, i + 2)) for i in range(N)]
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
def spawn(db, *a):                       # a cond.py daemon; returns (proc, announced addr)
    p = subprocess.Popen([sys.executable, os.path.join(BIN, "cond.py"), db, *a],
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

def cli(db, *args):                      # a full con.py invocation (subprocess proxy to the daemon)
    r = subprocess.run([sys.executable, os.path.join(BIN, "con.py"), db, *args],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    return r.stdout.strip()

def peer(sa, sb, wid, addr_a, addr_b):   # B bootstrap-dials A; both daemons must be --listen-ing.
    iid, secret = uverb(sa, "auth.user_invite.invite", wid).split(":")   # A (founder) mints an invite
    ep = uverb(sa, "auth.endpoint.endpoint")                             # ... and exposes its endpoint pk
    uverb(sb, "connection.request.connect", wid, iid, secret, ep, addr_a, addr_b)

# --- 1. in-process engine: admit + run, then linear replay --------------------
def bench_engine():
    section("1. in-process engine (%d facts)" % N)
    n = Node(ROOT)
    for b in WSPRE: n.admit(b)
    n.run()
    t = time.time()
    for b in MSGS: n.admit(b)
    n.run(); dt = time.time() - t
    report("admit+run", dt, "s", 1.2)                 # MEASURED 0.4-0.6s
    report("  per fact", dt / N * 1e3, "ms", None)
    t = time.time(); m = n.replay(); rp = time.time() - t
    assert m.derived() == n.derived(), "replay diverged"
    report("replay (full, in-memory)", rp, "s", 1.3)   # MEASURED 0.5-0.7s
    return n

# --- 2. daemon cold-load, then one proxied verb against a big db --------------
def bench_cli(db):
    section("2. daemon load + one verb against a %d-fact db" % N)
    t = time.time(); p, _ = spawn(db)     # cond replays the whole db before it announces "listening:"
    report("daemon cold load (full replay)", time.time() - t, "s", 2.0)
    try:
        uverb(db + ".sock", "content.message.feed", WID.hex(), "c0")      # warm the loaded node
        t = time.time(); cli(db, "content.message.send", WID.hex(), "c0", "al", "warm", "98")
        report("daemon-proxy con.py (one verb)", time.time() - t, "s", 0.2)
    finally: stop(p)

# --- 3. query under load ------------------------------------------------------
def bench_query(n):
    section("3. query under load (%d messages)" % N)
    R = 50
    t = time.time()
    for _ in range(R): rows = feed(n, WID, b"c0")
    report("feed() / watched() scan", (time.time() - t) / R * 1e3, "ms", 5.0)  # MEASURED 1.0ms
    need = message(WID, b"c0", b"al", b"x", 1).atoms[1]                          # the workspace REQUIRE
    t = time.time()
    for _ in range(R): n.valid_offers(need)
    report("valid_offers() bucket lookup", (time.time() - t) / R * 1e6, "us", None)
    assert len(rows) == N // 5

# --- 4. sync: dependency-aware negentropy over a big set ----------------------
def _node(bs):
    n = Node(ROOT)
    for b in bs: n.admit(b)
    n.run(); return n

_CID = b"\x22" * 32                      # a fixed connection id for the in-process pair

def _ids(v):                             # a ship offer's value: length-framed fact ids
    out, i = [], 0
    while i < len(v): x, i = _rd(v, i); out.append(x)
    return out

def leaves(n): return set(n.tree.keys)   # the reconciliation set as 40-byte (ts‖FactId) keys

def _reconcile(a, b, maxr=100_000):      # the daemon's exact wire discipline, in-process (mirrors test_sync)
    inbox, xor, fired = {a: [], b: []}, {a: None, b: None}, {a: [], b: []}
    frames, wire = [0], [0]
    def step(me, other):
        me.turn(shipped=tuple(fired[me])); fired[me] = []       # present last cycle's flush reports
        got, inbox[me] = inbox[me], []
        for blob in got: me.admit(blob)                         # admit what the peer sent
        me.run()
        if me.leaf_xor != xor[me]:                              # leaf set moved: open a fresh compare round
            sync.open_round(me, _CID, b""); xor[me] = me.leaf_xor; me.run()
        did = False                                             # pump: deliver every send/ship offer to the peer
        for role in (b"send", b"ship"):
            for o, _, at in me.watched(role, b"outbox"):
                blobs = ([at.value] if role == b"send"
                         else [me.durable[x] for x in _ids(at.value) if x in me.durable])
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
# Bulk catch-up is bimodal: below ~1 MiB of shipped bytes (~2000 messages) it runs
# at thousands of facts/s; past that it falls to a few hundred/s. Two compounding
# causes (measured): the outbox OUTCAP (1 MiB) parks the overflow, healed only on
# the next re-descend; and the RBSR descent restarts from the root per bounded
# batch, so bulk-from-empty is ~O(n^2). Live-tail (a fresh leaf to a caught-up
# peer, §5c) stays sub-second regardless. The budgets here are loose regression
# tripwires for this regime, not tuned targets.
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
                uverb(sa, "content.message.send", wid, "g", "al", "m%d" % i, str(i + 2))
                if i == cap // 2:                         # a query on B mid-stream
                    q = time.time(); uverb(sb, "content.message.feed", wid, "g")
                    qlat = (time.time() - q) * 1e3
                if time.time() - t0 > 30: cap = i + 1; break
            auth = time.time() - t0
            end = time.time() + 60
            while time.time() < end:
                got = len(uverb(sb, "content.message.feed", wid, "g").splitlines())
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
        for i in range(n):                                    # author the backlog on A (untimed setup)
            uverb(sa, "content.message.send", wid, CHANS[i % 5].decode(), "al", "m%d" % i, str(i + 2))
        pb, addr_b = spawn(dbb, "--listen", "127.0.0.1:0")
        peer(sa, dbb + ".sock", wid, addr_a, addr_b)          # B bootstrap-dials A
        t0 = time.time()
        try:
            got, end = 0, time.time() + 120
            while got < n and time.time() < end:
                got = sum(len(uverb(dbb + ".sock", "content.message.feed",
                                    wid, c.decode()).splitlines()) for c in CHANS)
                time.sleep(0.05)
            dt = time.time() - t0
            assert got >= n, f"caught up only {got}/{n}"
            mb = os.path.getsize(dbb) / 1048576               # B's db is exactly the fact bytes it synced
            report("catch-up (bulk sync)", n / dt, "fact/s", 40, hi_ok=True)
            report("catch-up volume", mb / dt, "MB/s", 0.04, hi_ok=True)
        finally: stop(pa, pb)

def bench_newest():                       # live-tail: a freshly-authored leaf reaches a caught-up
    n = 2000                              # peer directly, not behind a fresh reconcile round
    section("5c. live-tail latency to a caught-up peer (after a %d-fact backlog)" % n)
    with tempfile.TemporaryDirectory() as d:
        dba, dbb = os.path.join(d, "a.facts"), os.path.join(d, "b.facts")
        pa, addr_a = spawn(dba, "--listen", "127.0.0.1:0"); sa = dba + ".sock"
        wid = uverb(sa, "auth.workspace.create", "acme", "1")
        for i in range(n):                                    # a backlog B first catches up on (untimed)
            uverb(sa, "content.message.send", wid, "c0", "al", "m%d" % i, str(i + 2))
        pb, addr_b = spawn(dbb, "--listen", "127.0.0.1:0"); sb = dbb + ".sock"
        peer(sa, sb, wid, addr_a, addr_b)                     # B bootstrap-dials A
        try:
            end = time.time() + 60        # wait until B has fully caught up and gone quiet
            while time.time() < end and len(uverb(sb, "content.message.feed", wid, "c0").splitlines()) < n:
                time.sleep(0.02)
            t0 = time.time()
            uverb(sa, "content.message.send", wid, "c0", "al", "newest", str(n + 99))
            got, end = "", time.time() + 30
            while time.time() < end:
                got = uverb(sb, "content.message.feed", wid, "c0")
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
        m = n.replay()                                            # rebuild from durable file
        report("replay verifies (must be 0)", calls[0], "", 0)
        assert m.derived() == n.derived()
    finally: signature.verify = orig

def main():
    print("poc-13 bench  |  python", sys.version.split()[0], " facts:", N)
    n = bench_engine()
    with tempfile.TemporaryDirectory() as d:
        db = os.path.join(d, "big.facts")
        st = Store(db)
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
