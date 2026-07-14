"""Real channel semantics: replicated identity, dependency gating, resolution,
and feed isolation. These are protocol tests, not UI-label tests: messages name
the channel fact id and must stay parked until that exact validated fact exists."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import crypto as _c
from kernel import Atom, Exact, OFFER, Node, encode, fact, fact_id
from facts import ROOT
from facts.auth.invite_accepted import invite_accepted
from facts.auth.signature import signature
from facts.auth.workspace import workspace
from facts.content import channel
from facts.content.message import feed, message

T0 = 1_700_000_000
RK, RPK = _c.ed25519_keygen(bytes(32))
WS = workspace(b"acme", RPK, T0); WID = fact_id(WS)
WS_SIG = signature(b"auth", RPK, WID, _c.ed25519_sign(RK, WID), T0)
ACCEPT = invite_accepted(WID, bytes(32), bytes(32), b"", RPK, T0)
GENERAL = channel.channel(WID, b"general", T0 + 1); GENERAL_ID = fact_id(GENERAL)


def node(*facts):
    n = Node(ROOT); n.admit(encode(ACCEPT))
    for f in facts: n.admit(encode(f))
    n.run(); return n


def test_channel_is_a_workspace_backed_replicated_fact():
    parked = node(GENERAL)
    assert parked.memo[GENERAL_ID] == "Parked"
    n = node(WS, WS_SIG, GENERAL)
    assert n.memo[GENERAL_ID] == "Valid"
    assert channel.index(n, WID) == [(GENERAL_ID, b"general")]
    assert channel.resolve(n, WID, "general") == GENERAL_ID
    assert channel.resolve(n, WID, GENERAL_ID.hex()) == GENERAL_ID


def test_message_parks_until_exact_channel_arrives_then_wakes():
    m = message(WID, GENERAL_ID, b"alice", b"hello", T0 + 2); mid = fact_id(m)
    n = node(WS, WS_SIG, m)
    assert n.memo[mid] == "Parked" and feed(n, WID, GENERAL_ID) == []
    n.admit(encode(GENERAL)); n.run()
    assert n.memo[mid] == "Valid"
    assert feed(n, WID, GENERAL_ID) == [b"hello"]
    assert {mid, GENERAL_ID, WID, fact_id(WS_SIG)} <= n.closure(mid)


def test_messages_cannot_cross_channel_or_workspace_boundaries():
    RANDOM = channel.channel(WID, b"random", T0 + 2); rid = fact_id(RANDOM)
    gm = message(WID, GENERAL_ID, b"alice", b"in general", T0 + 3)
    rm = message(WID, rid, b"alice", b"in random", T0 + 4)
    n = node(WS, WS_SIG, GENERAL, RANDOM, gm, rm)
    assert feed(n, WID, GENERAL_ID) == [b"in general"]
    assert feed(n, WID, rid) == [b"in random"]

    # A channel fact in another workspace has the right id but the wrong scope,
    # so it cannot satisfy this workspace's message need.
    ork, orpk = _c.ed25519_keygen(b"\x01" * 32)
    ows = workspace(b"other", orpk, T0); owid = fact_id(ows)
    osig = signature(b"auth", orpk, owid, _c.ed25519_sign(ork, owid), T0)
    oaccept = invite_accepted(owid, bytes(32), bytes(32), b"", orpk, T0)
    other = channel.channel(owid, b"general", T0 + 1)
    foreign = message(WID, fact_id(other), b"mallory", b"cross-scope", T0 + 5)
    for f in (oaccept, ows, osig, other, foreign): n.admit(encode(f))
    n.run()
    assert n.memo[fact_id(other)] == "Valid"
    assert n.memo[fact_id(foreign)] == "Parked"


def test_channel_projector_rejects_noncanonical_or_useless_channels():
    blank = channel.channel(WID, b"", T0 + 1)
    non_utf8 = channel.channel(WID, b"\xff", T0 + 1)
    extra = fact(channel.TAG, *GENERAL.atoms,
                 Atom(OFFER, b"alias", WID, Exact(b"general"), b"smuggled"))
    canonical_message = message(WID, GENERAL_ID, b"alice", b"hello", T0 + 2)
    forged_message = fact(b"content.message", *canonical_message.atoms,
                          Atom(OFFER, b"alias", WID, Exact(GENERAL_ID), b"smuggled"))
    n = node(WS, WS_SIG, GENERAL, blank, non_utf8, extra, forged_message)
    assert n.memo[fact_id(blank)] == "Invalid"
    assert n.memo[fact_id(non_utf8)] == "Invalid"
    assert n.memo[fact_id(extra)] == "Invalid"
    assert n.memo[fact_id(forged_message)] == "Invalid"
    assert channel.index(n, WID) == [(GENERAL_ID, b"general")]


def test_local_creation_rejects_duplicate_names_but_ids_support_out_of_order():
    n = node(WS, WS_SIG)
    cid = channel.create(n, WID, b"general", T0 + 1); n.run()
    assert cid == GENERAL_ID
    try:
        channel.create(n, WID, b"general", T0 + 9)
        assert False, "duplicate name should be rejected at the authoring boundary"
    except RuntimeError as err:
        assert "already exists" in str(err)
    hex_name = b"a" * 64
    named = channel.create(n, WID, hex_name, T0 + 10); n.run()
    assert channel.resolve(n, WID, hex_name.decode()) == named  # known name wins over hex-id syntax
    future = bytes.fromhex("22" * 32)
    assert channel.resolve(n, WID, future.hex()) == future


if __name__ == "__main__":
    for t in (test_channel_is_a_workspace_backed_replicated_fact,
              test_message_parks_until_exact_channel_arrives_then_wakes,
              test_messages_cannot_cross_channel_or_workspace_boundaries,
              test_channel_projector_rejects_noncanonical_or_useless_channels,
              test_local_creation_rejects_duplicate_names_but_ids_support_out_of_order):
        t(); print(f"ok  {t.__name__}")
