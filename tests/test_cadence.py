"""Cadence as facts (M7): a sync.cadence fact opens a round once per period, driven
by the clock the turn presents — no daemon marker. It provides a wake@clock alarm at
its next boundary (runtime.next_wake reads it for the select timeout), fires at most
once per period though the clock re-wakes it every turn, re-arms itself, and is torn
down by `SuppressIf closed@conn`. Driven in-process by advancing turn(now=...)."""
import os, sys
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT_DIR = os.path.dirname(HERE)
sys.path[:0] = [ROOT_DIR, os.path.join(ROOT_DIR, "bin")]
import crypto as _c
from kernel import Node, encode, fact_id, decode
from facts import ROOT
from facts.sync import cadence
from facts.sync.compare import TAG as CMP_TAG
from runtime import next_wake
from facts.auth.workspace import workspace
from facts.auth.invite_accepted import invite_accepted
from facts.auth.signature import signature
from content_fixtures import member_context, signed_channel, signed_message

RK, RPK = _c.ed25519_keygen(bytes(32)); T0 = 1_700_000_000
WS = workspace(b"acme", RPK, T0); WID = fact_id(WS)
WS_SIG = signature(b"auth", RPK, WID, _c.ed25519_sign(RK, WID), T0)
ACCEPT = invite_accepted(WID, bytes(32), bytes(32), b"", RPK, T0)
MEMBER = member_context(WID, RK, RPK, t=T0 + 1)
CHANNEL, CHANNEL_SIG = signed_channel(MEMBER, WID, b"g", T0 + 2)
CH_ID = fact_id(CHANNEL)
MESSAGE, MESSAGE_SIG = signed_message(MEMBER, WID, CH_ID, b"hi", T0 + 3600)
CID = b"\x22" * 32
PERIOD = 500
ONE = ((b"", PERIOD, cadence.ANCHOR),)   # a single unconditional tier: the old semantics

def node():
    n = Node(ROOT); n.admit(encode(ACCEPT))
    for f in (WS, WS_SIG, *MEMBER.facts, CHANNEL, CHANNEL_SIG, MESSAGE, MESSAGE_SIG):
        n.admit(encode(f))
    n.run(); return n

def _compares(n):                                       # send provides carrying a compare frame, at Exact(CID)
    return [a for _, _, a in n.provided(b"send", b"outbox")
            if a.target[1] == CID and decode(a.value).type_tag == CMP_TAG]

def test_cadence_opens_a_round_once_per_period():
    n = node()
    cadence.arm(n, CID, ONE)                               # first clock sight anchors the boundary
    n.turn(now=0); n.run()
    assert not _compares(n)                              # before the boundary: no round, only an alarm
    ds = [int.from_bytes(a.target[1], "big") for _, _, a in n.provided(b"wake", b"clock")]
    assert ds == [PERIOD]                                # alarm parked at the first boundary
    n.turn(now=PERIOD); n.run()
    assert len(_compares(n)) == 1                        # boundary reached: exactly one round opened
    n.turn(now=PERIOD + 1); n.run()
    assert not _compares(n)                              # same period, re-woken: does not fire again
    n.turn(now=PERIOD + 2); n.run()
    assert not _compares(n)                              # and again: the tick memory survived the re-wake
    n.turn(now=2 * PERIOD); n.run()
    assert len(_compares(n)) == 1                        # next period: fires once more

def test_next_wake_reads_the_alarm():
    n = node(); cadence.arm(n, CID, ONE); n.turn(now=100); n.run()
    assert abs(next_wake(n, 200, 1.0) - (PERIOD - 100) / 1000.0) < 1e-6   # sleep exactly until 100 + PERIOD
    assert next_wake(Node(ROOT), 0, 0.5) == 0.5         # no alarms -> the cap

def test_closed_conn_tears_it_down():
    from facts.connection import close
    n = node(); cadence.arm(n, CID, ONE); n.turn(now=0); n.turn(now=PERIOD); n.run()
    assert _compares(n)
    n.admit(encode(close.close([CID], 1)))                 # a close for this connection
    n.turn(now=2 * PERIOD); n.run()
    assert not _compares(n)                              # suppressed: the cadence stops opening rounds
    assert not n.provided(b"wake", b"clock")             # and stops arming alarms

def test_tier_pair_registers_do_not_collide():
    """Two tiers over one (cid, floor): the tick key includes period and mode, so
    the anchor's memory survives the fast tier's — a collision here silently
    disables the anchor (found by test on the anchor branch, pinned ever since)."""
    n = node(); cadence.arm(n, CID)                      # the default TIER PAIR
    n.turn(now=0); n.run()
    W = cadence.ANCHOR_W
    for t in range(500, 3 * W + 1, 500): n.turn(now=t); n.run()
    ticks = {a.target[0] for _, _, a in n.provided(b"tick", b"sync")}
    assert len(ticks) == 2                               # one register per tier, distinct keys

def test_anchor_fires_every_period_gated_goes_silent():
    n = node(); cadence.arm(n, CID)
    n.turn(now=0); n.run()
    opened = []
    W = cadence.ANCHOR_W
    for t in range(500, 3 * W + 1, 500):
        n.turn(now=t); n.run()
        opened += [(t, a.value) for a in _compares(n)]
        n.turn(now=t, shipped=tuple({o for o, _, a in n.provided(b"send", b"outbox")})); n.run()
    gated_fires = [t for t, _ in opened if t % W != 0]
    anchor_fires = [t for t, _ in opened if t % W == 0]
    assert len(anchor_fires) == 3                        # every anchor boundary, unconditionally
    assert len(gated_fires) <= 1                         # the gated tier fired once, then held (unchanged)

def test_cadence_is_volatile():
    n = node(); cadence.arm(n, CID, ONE); n.turn(now=0); n.turn(now=PERIOD); n.run()
    syn = [fid for fid, f in n.facts.items() if f.type_tag == cadence.TAG]
    assert syn and not any(fid in n.durable for fid in syn)   # session state, never flushed

if __name__ == "__main__":
    for t in (test_cadence_opens_a_round_once_per_period, test_next_wake_reads_the_alarm,
              test_closed_conn_tears_it_down, test_tier_pair_registers_do_not_collide,
              test_anchor_fires_every_period_gated_goes_silent, test_cadence_is_volatile):
        t(); print("ok ", t.__name__)
