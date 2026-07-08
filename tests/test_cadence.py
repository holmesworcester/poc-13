"""Cadence as facts (M7): a sync.cadence fact opens a round each period IF its domain
split moved, driven by the clock the turn presents — no daemon marker. It offers a
wake@clock alarm at its next boundary (runtime.next_wake reads it for the select
timeout), fires at most once per period though the clock re-wakes it every turn,
re-opens only when its split hash changed since the last ship (idempotent silence
otherwise — the fact-native replacement for the daemon's opener dedup), re-arms
itself, and is torn down by a closed@conn Suppress. Driven by advancing turn(now=...)."""
import os, sys
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT_DIR = os.path.dirname(HERE)
sys.path[:0] = [ROOT_DIR, os.path.join(ROOT_DIR, "bin")]
import crypto as _c
from kernel import Node, Atom, Exact, OFFER, encode, fact, fact_id, ts_atom, decode
from facts import ROOT
from facts.sync import cadence
from facts.sync.compare import TAG as CMP_TAG
from runtime import next_wake
from facts.auth.workspace import workspace
from facts.auth.invite_accepted import invite_accepted
from facts.auth.signature import signature
from facts.content.message import message

RK, RPK = _c.ed25519_keygen(bytes(32)); T0 = 1_700_000_000
WS = workspace(b"acme", RPK, T0); WID = fact_id(WS)
WS_SIG = signature(b"auth", RPK, WID, _c.ed25519_sign(RK, WID), T0)
ACCEPT = invite_accepted(WID, bytes(32), bytes(32), b"", RPK, T0)
CID = b"\x22" * 32
PERIOD = 500

def node():
    n = Node(ROOT); n.admit(encode(ACCEPT))
    for f in (WS, WS_SIG, message(WID, b"g", b"al", b"hi", T0 + 3600)): n.admit(encode(f))
    n.run(); return n

def _compares(n):                                       # send offers carrying a compare frame, at Exact(CID)
    return [a for _, _, a in n.watched(b"send", b"outbox")
            if a.target[1] == CID and decode(a.value).type_tag == CMP_TAG]

def test_cadence_opens_a_round_when_the_split_moves():
    n = node()
    cadence.arm(n, CID, 0)                               # first boundary at now(0) + PERIOD
    n.turn(now=0); n.run()
    assert not _compares(n)                              # before the boundary: no round, only an alarm
    ds = [int.from_bytes(a.target[1], "big") for _, _, a in n.watched(b"wake", b"clock")]
    assert ds == [PERIOD]                                # alarm parked at the first boundary
    n.turn(now=PERIOD); n.run()
    assert len(_compares(n)) == 1                        # boundary reached: exactly one round opened
    n.turn(now=PERIOD + 1); n.run()
    assert not _compares(n)                              # same period, re-woken: does not fire again
    n.turn(now=2 * PERIOD); n.run()
    assert not _compares(n)                              # next period, split unchanged: idempotent silence
    n.admit(encode(message(WID, b"g", b"al", b"hi2", T0 + 3601))); n.run()   # my shareable set moves
    n.turn(now=3 * PERIOD); n.run()
    assert len(_compares(n)) == 1                        # split changed: re-opens exactly one round
    n.turn(now=4 * PERIOD); n.run()
    assert not _compares(n)                              # and falls silent again once it has re-shipped

def test_next_wake_reads_the_alarm():
    n = node(); cadence.arm(n, CID, 0); n.turn(now=100); n.run()
    assert abs(next_wake(n, 100, 1.0) - (PERIOD - 100) / 1000.0) < 1e-6   # sleep exactly until the boundary
    assert next_wake(Node(ROOT), 0, 0.5) == 0.5         # no alarms -> the cap

def test_closed_conn_tears_it_down():
    n = node(); cadence.arm(n, CID, 0); n.turn(now=PERIOD); n.run()
    assert _compares(n)
    n.admit(encode(fact(b"connection.close", ts_atom(1, b"conn"),
                        Atom(OFFER, b"closed", b"conn", Exact(CID)))))   # a close for this connection
    n.turn(now=2 * PERIOD); n.run()
    assert not _compares(n)                              # suppressed: the cadence stops opening rounds
    assert not n.watched(b"wake", b"clock")             # and stops arming alarms

def test_cadence_is_volatile():
    n = node(); cadence.arm(n, CID, 0); n.turn(now=PERIOD); n.run()
    syn = [fid for fid, f in n.facts.items() if f.type_tag == cadence.TAG]
    assert syn and not any(fid in n.durable for fid in syn)   # session state, never flushed

if __name__ == "__main__":
    for t in (test_cadence_opens_a_round_when_the_split_moves, test_next_wake_reads_the_alarm,
              test_closed_conn_tears_it_down, test_cadence_is_volatile):
        t(); print("ok ", t.__name__)
