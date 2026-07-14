"""Adversarial reliability: sync must converge under ANY channel behavior, and the
argument must rest only on the kernel handling facts correctly (docs/anchor-sync.md).

The harness is two real nodes driven through the real runtime seam (cycle -> prune ->
pump, exactly cond.py's loop) with a simulated clock and a faulty duplex channel:
frames can be dropped (loss, partition), duplicated, reordered, or truncated to a
prefix (a full outbox). Rounds are opened ONLY by the real sync.cadence tiers — no
test-side open_round — so what is exercised is the shipped design: an unconditional
ANCHOR tier that re-descends every period no matter what, a GATED fast tier
(changed+settled) that may be starved without harm, and a TTL sent-memory that may
only delay bytes, never veto them.

Each test is one quantifier of the informal proof:
  * loss/partition     -> the anchor re-opens over current state; healing <= ~2 anchors
  * lost opener        -> gates stay silent (changed says no); the anchor alone heals it,
                          and ONLY because the dedup memory expires before it fires
                          (the negative control pins that invariant as load-bearing)
  * duplication        -> content-addressed frames are the same fact; admission
                          idempotence absorbs them with no response amplification
  * reordering         -> every frame is a pure function of current state; order is noise
  * both-sided churn   -> perpetual motion starves changed+settled forever; the anchor
                          bounds the lag (the negative control shows the bare gated
                          tier really does stall — the hazard is real, not theoretical)
  * restart            -> durable facts replay; volatile round state is not state
  * converged silence  -> wire falls to the anchor heartbeat exactly, nothing else
"""
import os, random, sys
from collections import Counter
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT_DIR = os.path.dirname(HERE)
sys.path[:0] = [HERE, ROOT_DIR, os.path.join(ROOT_DIR, "bin")]
import crypto as _c
from kernel import Node, decode, encode, fact_id
from facts import ROOT
from facts.sync import cadence
from facts.sync import compare as cmp, index as _sidx, need as _need
from runtime import cycle, outbox, pump, TTLSet, SENT_TTL
from facts.auth.workspace import workspace
from facts.auth.invite_accepted import invite_accepted
from facts.auth.signature import signature
from content_fixtures import flat, member_context, signed_channel, signed_message

RK, RPK = _c.ed25519_keygen(bytes(32)); T0 = 1_700_000_000
WS = workspace(b"acme", RPK, T0); WID = fact_id(WS)
WS_SIG = signature(b"auth", RPK, WID, _c.ed25519_sign(RK, WID), T0)
ACCEPT = invite_accepted(WID, bytes(32), bytes(32), b"", RPK, T0)
AL = member_context(WID, RK, RPK, b"al", T0 + 1)   # ONE member authors everything; bodies name the sender
MEMBER = AL.facts                        # invite + its sig + user + its sig: the 4-fact chain a message leans on
CHANNEL, CHANNEL_SIG = signed_channel(AL, WID, b"g", T0 + 2)
CH_ID = fact_id(CHANNEL)
CID = b"\x11" * 32
W = 4000                                 # the default anchor period (cadence.TIERS)
SYNC_TAGS = (cmp.TAG, _need.TAG)

def node(*fs):
    n = Node(ROOT); n.admit(encode(ACCEPT))
    for f in fs: n.admit(encode(f))
    if WS in fs and CHANNEL not in fs:
        for f in (CHANNEL, CHANNEL_SIG): n.admit(encode(f)) # a workspace fixture includes structural #g
    n.run(); return n

def msgs(author, t0, k):                 # k signed messages = 2k facts: each rides with its member signature
    return flat(signed_message(AL, WID, CH_ID, author + b" m%d" % i, t0 + i) for i in range(k))

def leaves(n): return set(_sidx.tree(n).keys)

class World:
    """Two nodes on a faulty duplex channel, stepped on a simulated clock. Mirrors
    cond.py's iteration: deliver inbox -> cycle (drain to quiescence) -> prune the
    to_ship set -> pump through the real TTL sent-memory. Faults apply per inner
    fact-frame at the emission boundary; `emitted` counts what actually left the
    pump (post-dedup), `delivered` what survived the channel."""
    def __init__(self, a, b, tiers=cadence.TIERS, ttl=SENT_TTL, seed=0,
                 drop=None, dup=1, reorder=False, cap=None):
        self.nodes = {"a": a, "b": b}
        self.chan = {"a": [], "b": []}
        self.fired = {"a": set(), "b": set()}
        self.sent = {s: {CID: TTLSet(ttl)} for s in ("a", "b")}
        self.rng = random.Random(seed)
        self.drop = drop or (lambda side, t, blob: False)
        self.dup, self.reorder, self.cap = dup, reorder, cap
        self.t = 0
        self.emitted, self.delivered = Counter(), Counter()
        for s in ("a", "b"): cadence.arm(self.nodes[s], CID, tiers)

    def _kind(self, blob):
        tag = decode(blob).type_tag
        return tag.decode() if tag.startswith(b"sync.") else "ship"

    def _side(self, me, other):
        n = self.nodes[me]
        inbox, self.chan[me] = self.chan[me], []
        if self.reorder: self.rng.shuffle(inbox)
        def deliver(cid, addr, secret, inners):
            k = len(inners) if self.cap is None else min(self.cap, len(inners))
            for blob in inners[:k]:
                self.emitted[self._kind(blob)] += 1
                if not self.drop(me, self.t, blob):
                    for _ in range(self.dup):
                        self.chan[other].append(blob)
                        self.delivered[self._kind(blob)] += 1
            return k
        # pump after EVERY turn, as cond does: a cadence due-fire is a transient
        # offer the next clock presentation erases, so a drain-then-pump harness
        # silently drops any opener fired before the drain's last turn.
        cycle(n, inbox, self.t, tuple(self.fired[me]), 4096)
        while True:
            self.fired[me] &= {o for o, _, _ in outbox(n)}
            self.fired[me] |= pump(n, lambda c: (b"peer", None), deliver,
                                   self.fired[me], self.sent[me], self.t)
            if not n.frontier: break
            n.turn(self.t, tuple(self.fired[me]), 4096)

    def step(self, dt=100):
        self.t += dt
        self._side("a", "b"); self._side("b", "a")

    def run_until(self, pred, until, dt=100):
        while self.t < until:
            self.step(dt)
            if pred(): return self.t
        return None

    def converged(self): return leaves(self.nodes["a"]) == leaves(self.nodes["b"])

    def settle(self, ms=1600):           # a lossless tail so in-flight couriers flush and reap
        drop, dup, cap = self.drop, self.dup, self.cap
        self.drop, self.dup, self.cap = (lambda *x: False), 1, None
        for _ in range(ms // 100): self.step()
        self.drop, self.dup, self.cap = drop, dup, cap

def no_residue(w):                       # volatile couriers must not outlive their round
    for n in w.nodes.values():
        assert not any(f.type_tag in SYNC_TAGS for f in n.facts.values())

# --- bulk + duplication ----------------------------------------------------------
def test_bulk_catchup_then_duplication_does_not_amplify():
    def run(dup):
        w = World(node(WS, WS_SIG, *MEMBER, *msgs(b"al", T0 + 100, 250)), node(), dup=dup, seed=1)
        assert w.run_until(w.converged, 60_000)
        w.settle(); no_residue(w)
        return w
    w1 = run(1)
    assert w1.emitted["ship"] <= 508 + 8            # each fact leaves the source ~once (TTL >> catch-up);
                                                    # signatures double the messages (250 msg + 250 sig),
                                                    # + ws/its sig + member chain + channel/sig = 508
    e1 = sum(w1.emitted.values())
    w2 = run(2)                                     # every frame delivered twice
    e2 = sum(w2.emitted.values())
    assert e2 <= 2 * e1 + 20                        # duplicated input never multiplies emitted output

def test_random_loss_still_converges():
    for seed in (2, 3):
        rng = random.Random(seed)
        w = World(node(WS, WS_SIG, *MEMBER, *msgs(b"al", T0 + 100, 40)),
                  node(WS, WS_SIG, *MEMBER, *msgs(b"bo", T0 + 500, 40)),
                  seed=seed, drop=lambda s, t, blob: rng.random() < 0.35)
        assert w.run_until(w.converged, 180_000), f"no convergence under loss, seed {seed}"
        w.settle(); no_residue(w)

def test_reorder_duplication_loss_combined():
    rng = random.Random(7)
    w = World(node(WS, WS_SIG, *MEMBER, *msgs(b"al", T0 + 100, 25)),
              node(WS, WS_SIG, *MEMBER, *msgs(b"bo", T0 + 500, 25)),
              seed=7, dup=2, reorder=True, drop=lambda s, t, blob: rng.random() < 0.25)
    assert w.run_until(w.converged, 180_000)
    w.settle(); no_residue(w)

# --- partitions and lost openers --------------------------------------------------
def test_partition_heals_within_anchor_bound():
    down = [False]
    w = World(node(WS, WS_SIG, *MEMBER, *msgs(b"al", T0 + 100, 10)), node(),
              drop=lambda s, t, blob: down[0])
    assert w.run_until(w.converged, 30_000)          # b now holds the member chain too: it can author
    down[0] = True                                   # total partition; both sides keep authoring
    for i in range(10):                              # each authoring is a msg + its signature: two facts
        for f in signed_message(AL, WID, CH_ID, b"p%d" % i, T0 + 1000 + i): w.nodes["a"].admit(encode(f))
        for f in signed_message(AL, WID, CH_ID, b"q%d" % i, T0 + 2000 + i): w.nodes["b"].admit(encode(f))
        w.step(); w.step()
    w.run_until(lambda: False, w.t + 2 * W)          # dark for two more anchor periods
    assert not w.converged()
    down[0] = False
    assert w.run_until(w.converged, w.t + 2 * W + 2000)   # healed by re-descent over current state
    w.settle(); no_residue(w)

def test_lost_opener_healed_by_anchor_only_because_dedup_expires():
    def run(ttl):
        dark = [True]
        w = World(node(WS, WS_SIG, *MEMBER, *msgs(b"al", T0 + 100, 3)), node(),
                  ttl=ttl, drop=lambda s, t, blob: dark[0])
        w.run_until(lambda: False, 3000)             # every gated opener (and the mirror) is lost;
        dark[0] = False                              # nothing changes after, so the gates stay silent forever
        assert not w.converged()
        return w
    w = run(SENT_TTL)                                # TTL < anchor period: the anchor's identical
    assert w.run_until(w.converged, 12_000)          # re-open reaches the wire and heals it
    w2 = run(10 ** 9)                                # a session-scoped (never-expiring) memory vetoes the
    assert not w2.run_until(w2.converged, 24_000)    # byte-identical re-open forever: dedup lifetime
                                                     # bounded by the anchor period is LOAD-BEARING

# --- gate starvation under churn ---------------------------------------------------
def _churn(w, until, every=500):
    """Author one signed message per side per `every` ms; return [(t, fid, source-side)]
    for BOTH facts of each bundle — the signature must cross exactly like its message."""
    authored, k = [], 0
    while w.t < until:
        if w.t % every == 0:
            for s, base in (("a", T0 + 10), ("b", T0 + 10_000)):
                for f in signed_message(AL, WID, CH_ID, s.encode() + b" c%d" % k, base + k):
                    w.nodes[s].admit(encode(f)); authored.append((w.t, fact_id(f), s))
            k += 1
        w.step()
    return authored

def test_both_sided_churn_anchor_bounds_the_lag():
    w = World(node(WS, WS_SIG, *MEMBER), node(WS, WS_SIG, *MEMBER))
    authored = _churn(w, 20_000)
    for t, fid, s in authored:                       # every fact older than 2 anchor periods has crossed
        if t <= w.t - 2 * W:
            other = w.nodes["b" if s == "a" else "a"]
            assert fid in other.durable, f"fact authored at {t} still missing at {w.t}"
    assert w.run_until(w.converged, w.t + 2 * W + 2000)   # churn over: full convergence within ~an anchor

def test_churn_starves_the_gated_tier_without_an_anchor():
    w = World(node(WS, WS_SIG, *MEMBER), node(WS, WS_SIG, *MEMBER),
              tiers=((b"", 500, cadence.GATED),))    # the fast tier alone — no liveness anchor
    authored = _churn(w, 20_000)
    stalled = [t for t, fid, s in authored
               if 2000 <= t <= 10_000 and fid not in w.nodes["b" if s == "a" else "a"].durable]
    assert stalled, "expected changed+settled to be starved by perpetual motion"
    # the hazard the anchor exists for: without it, a set that never settles never opens.

# --- restart, overflow, silence -----------------------------------------------------
def test_restart_mid_catchup_replays_and_converges():
    w = World(node(WS, WS_SIG, *msgs(b"al", T0 + 100, 120)), node(), cap=32)
    assert w.run_until(lambda: 0 < len(leaves(w.nodes["b"])) < 100, 30_000)   # mid-flight
    old = w.nodes["b"]; nb = Node(ROOT)
    for fid in old.durable: nb.admit(old.durable[fid], checked=True)          # replay = the whole crash story
    nb.run()
    w.nodes["b"], w.chan["b"], w.fired["b"] = nb, [], set()
    w.sent["b"] = {CID: TTLSet()}
    cadence.arm(nb, CID)                             # volatile round state is gone; reconnect re-arms
    assert w.run_until(w.converged, w.t + 30_000)
    w.settle(); no_residue(w)

def test_overflow_tail_drop_heals_by_redescend():
    w = World(node(WS, WS_SIG, *msgs(b"al", T0 + 100, 20)), node(), cap=5)
    assert w.run_until(w.converged, 60_000)          # each round ships a prefix; the re-descend re-asks the rest
    w.settle(); no_residue(w)

def test_certificate_synced_flips_with_the_set():
    """The synced predicate is local and honest: true only while a peer's all-done
    reply attests the split I hold NOW. Converge -> synced; author one fact ->
    un-synced at once (the certificate dies with the set movement); converge
    again -> synced again."""
    ms = msgs(b"al", T0 + 100, 5)
    w = World(node(WS, WS_SIG, *ms), node(WS, WS_SIG, *ms))
    assert w.run_until(lambda: cadence.synced(w.nodes["a"], CID), 30_000)
    assert w.run_until(lambda: cadence.synced(w.nodes["b"], CID), 30_000)
    for f in signed_message(AL, WID, CH_ID, b"new", T0 + 999):
        w.nodes["a"].admit(encode(f))
    w.nodes["a"].run()
    assert not cadence.synced(w.nodes["a"], CID)     # my split moved: certificate retired
    assert w.run_until(lambda: w.converged() and cadence.synced(w.nodes["a"], CID), 30_000)
    w.settle(); no_residue(w)

def test_converged_silence_is_exactly_the_anchor():
    w = World(node(WS, WS_SIG, *msgs(b"al", T0 + 100, 5)), node())
    assert w.run_until(w.converged, 30_000)
    w.settle()
    w.emitted.clear()
    w.run_until(lambda: False, w.t + 3 * W)          # three quiet anchor periods
    assert w.emitted.get("ship", 0) == 0 and w.emitted.get("sync.need", 0) == 0
    assert w.emitted.get("sync.compare", 0) <= 4 * 3 + 2   # per side per anchor: one opener + one
    no_residue(w)                                          # all-done certificate reply, nothing else —
                                                           # the synced predicate costs one small frame
                                                           # per heartbeat

if __name__ == "__main__":
    for t in (test_bulk_catchup_then_duplication_does_not_amplify,
              test_random_loss_still_converges,
              test_reorder_duplication_loss_combined,
              test_partition_heals_within_anchor_bound,
              test_lost_opener_healed_by_anchor_only_because_dedup_expires,
              test_both_sided_churn_anchor_bounds_the_lag,
              test_churn_starves_the_gated_tier_without_an_anchor,
              test_restart_mid_catchup_replays_and_converges,
              test_certificate_synced_flips_with_the_set,
              test_overflow_tail_drop_heals_by_redescend,
              test_converged_silence_is_exactly_the_anchor):
        t(); print("ok ", t.__name__)
