"""Real channel semantics: replicated identity, dependency gating, resolution,
and feed isolation. These are protocol tests, not UI-label tests: messages name
the channel fact id and must stay parked until that exact validated fact exists."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import crypto as _c
from kernel import Atom, Exact, PROVIDE, Node, encode, fact, fact_id
from facts import ROOT
from facts.auth.invite_accepted import invite_accepted
from facts.auth.signature import signature
from facts.auth import workspace as workspace_mod
from facts.content import channel
from facts.content.message import feed, message
from content_fixtures import member_context, signed_channel, signed_message

T0 = 1_700_000_000
RK, RPK = _c.ed25519_keygen(bytes(32))
WS = workspace_mod.workspace(b"acme", RPK, T0); WID = fact_id(WS)
WS_SIG = signature(b"auth", RPK, WID, _c.ed25519_sign(RK, WID), T0)
ACCEPT = invite_accepted(WID, bytes(32), bytes(32), b"", RPK, T0)
MEMBER = member_context(WID, RK, RPK, t=T0 + 1)
GENERAL, GENERAL_SIG = signed_channel(MEMBER, WID, b"general", T0 + 2)
GENERAL_ID = fact_id(GENERAL)


def node(*facts):
    n = Node(ROOT); n.admit(encode(ACCEPT))
    for f in facts: n.admit(encode(f))
    n.run(); return n


def test_channel_is_a_workspace_backed_replicated_fact():
    parked = node(GENERAL, GENERAL_SIG)
    assert parked.memo[GENERAL_ID] == "Parked"
    n = node(WS, WS_SIG, *MEMBER.facts, GENERAL, GENERAL_SIG)
    assert n.memo[GENERAL_ID] == "Valid"
    assert channel.index(n, WID) == [(GENERAL_ID, b"general")]
    assert channel.resolve(n, WID, "general") == GENERAL_ID
    assert channel.resolve(n, WID, GENERAL_ID.hex()) == GENERAL_ID


def test_message_parks_until_exact_channel_arrives_then_wakes():
    m, ms = signed_message(MEMBER, WID, GENERAL_ID, b"hello", T0 + 3); mid = fact_id(m)
    n = node(WS, WS_SIG, *MEMBER.facts, m, ms)
    assert n.memo[mid] == "Parked" and feed(n, WID, GENERAL_ID) == []
    for f in (GENERAL, GENERAL_SIG): n.admit(encode(f))
    n.run()
    assert n.memo[mid] == "Valid"
    assert feed(n, WID, GENERAL_ID) == [b"hello"]
    assert {mid, fact_id(ms), GENERAL_ID, fact_id(GENERAL_SIG), WID,
            fact_id(WS_SIG)} <= n.closure(mid)


def test_messages_cannot_cross_channel_or_workspace_boundaries():
    random_bundle = signed_channel(MEMBER, WID, b"random", T0 + 3)
    RANDOM, RANDOM_SIG = random_bundle; rid = fact_id(RANDOM)
    gm = signed_message(MEMBER, WID, GENERAL_ID, b"in general", T0 + 4)
    rm = signed_message(MEMBER, WID, rid, b"in random", T0 + 5)
    n = node(WS, WS_SIG, *MEMBER.facts, GENERAL, GENERAL_SIG,
             RANDOM, RANDOM_SIG, *gm, *rm)
    assert feed(n, WID, GENERAL_ID) == [b"in general"]
    assert feed(n, WID, rid) == [b"in random"]

    # A channel fact in another workspace has the right id but the wrong scope,
    # so it cannot satisfy this workspace's message Require.
    ork, orpk = _c.ed25519_keygen(b"\x01" * 32)
    ows = workspace_mod.workspace(b"other", orpk, T0); owid = fact_id(ows)
    osig = signature(b"auth", orpk, owid, _c.ed25519_sign(ork, owid), T0)
    oaccept = invite_accepted(owid, bytes(32), bytes(32), b"", orpk, T0)
    other_member = member_context(owid, ork, orpk, b"bo", T0 + 1)
    other, other_sig = signed_channel(other_member, owid, b"general", T0 + 2)
    foreign, foreign_sig = signed_message(MEMBER, WID, fact_id(other), b"cross-scope", T0 + 6)
    for f in (oaccept, ows, osig, *other_member.facts, other, other_sig,
              foreign, foreign_sig): n.admit(encode(f))
    n.run()
    assert n.memo[fact_id(other)] == "Valid"
    assert n.memo[fact_id(foreign)] == "Parked"


def test_channel_projector_rejects_noncanonical_or_useless_channels():
    def signed(f, t):
        fid = fact_id(f)
        return f, signature(WID, MEMBER.pk, fid, _c.ed25519_sign(MEMBER.sk, fid), t)
    blank = signed(channel.channel(WID, b"", T0 + 4), T0 + 4)
    non_utf8 = signed(channel.channel(WID, b"\xff", T0 + 4), T0 + 4)
    extra = fact(channel.TAG, *GENERAL.atoms,
                 Atom(PROVIDE, b"alias", WID, Exact(b"general"), b"smuggled"))
    extra = signed(extra, T0 + 4)
    canonical_message = message(WID, GENERAL_ID, MEMBER.uid, b"hello", T0 + 5, bytes(32))
    forged_message = fact(b"content.message", *canonical_message.atoms,
                          Atom(PROVIDE, b"alias", WID, Exact(GENERAL_ID), b"smuggled"))
    forged_message = signed(forged_message, T0 + 5)
    n = node(WS, WS_SIG, *MEMBER.facts, GENERAL, GENERAL_SIG,
             *blank, *non_utf8, *extra, *forged_message)
    assert n.memo[fact_id(blank[0])] == "Invalid"
    assert n.memo[fact_id(non_utf8[0])] == "Invalid"
    assert n.memo[fact_id(extra[0])] == "Invalid"
    assert n.memo[fact_id(forged_message[0])] == "Invalid"
    assert channel.index(n, WID) == [(GENERAL_ID, b"general")]


def test_channel_must_be_signed_by_a_workspace_member():
    sk, pk = _c.ed25519_keygen(b"outsider".ljust(32, b"\x00"))
    forged = channel.channel(WID, b"outsider", T0 + 4); fid = fact_id(forged)
    forged_sig = signature(WID, pk, fid, _c.ed25519_sign(sk, fid), T0 + 4)
    n = node(WS, WS_SIG, *MEMBER.facts, forged, forged_sig)
    assert n.memo[fid] == "Invalid"


def test_local_creation_rejects_duplicate_names_but_ids_support_out_of_order():
    n = Node(ROOT)
    wid = workspace_mod.create(n, b"created", T0); n.run()
    cid = channel.resolve(n, wid, "general")
    try:
        channel.create(n, wid, b"general", T0 + 9)
        assert False, "duplicate name should be rejected at the authoring boundary"
    except RuntimeError as err:
        assert "already exists" in str(err)
    hex_name = b"a" * 64
    named = channel.create(n, wid, hex_name, T0 + 10); n.run()
    assert channel.resolve(n, wid, hex_name.decode()) == named  # known name wins over hex-id syntax
    future = bytes.fromhex("22" * 32)
    assert channel.resolve(n, wid, future.hex()) == future


if __name__ == "__main__":
    for t in (test_channel_is_a_workspace_backed_replicated_fact,
              test_message_parks_until_exact_channel_arrives_then_wakes,
              test_messages_cannot_cross_channel_or_workspace_boundaries,
              test_channel_projector_rejects_noncanonical_or_useless_channels,
              test_channel_must_be_signed_by_a_workspace_member,
              test_local_creation_rejects_duplicate_names_but_ids_support_out_of_order):
        t(); print(f"ok  {t.__name__}")
