"""Wire provenance is graph input, not an argument to family code.

The host labels an arrival as bare or as opened by a connection. Protected
families carry ordinary SuppressIf/Gather relationships for those engine-owned
rows, so
their first graph judgment decides whether the bytes may stand.  No unjudged
wire bytes are durable.
"""
import os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(HERE)
sys.path[:0] = [ROOT_DIR, os.path.join(ROOT_DIR, "bin"), HERE]

import crypto as c
from kernel import (Node, Store, WireOrigin, encode, fact, fact_id, frame,
                    remote_suppress)
from facts import ROOT
from facts.auth.workspace import workspace
from facts.auth import local_signer_secret as lss, endpoint as ep
from facts.auth import invite_accepted as ia, active_workspace as aw
from facts.auth.signature import signature
from facts.connection import close as cl, connection as conn
from facts.connection import ephemeral_secret as es, request as req
from facts.outbox import send as outsend
from facts.store import hydrate
from facts.sync import cadence, compare, need

RK, RPK = c.ed25519_keygen(bytes(32))
WS = workspace(b"acme", RPK, 1); WID = fact_id(WS)
CID, OTHER_CID = b"c" * 32, b"d" * 32


def _local_only():
    """One canonical fact from every family that suppresses all wire input."""
    sk, pk = c.ed25519_keygen(b"s" * 32)
    esk, epk = c.x25519_keygen(b"e" * 32)
    fsk, fpk = c.x25519_keygen(b"f" * 32)
    return {
        "auth.local_signer_secret": lss.secret(sk, pk, 1),
        "auth.endpoint": ep.endpoint(esk, epk, 1),
        "auth.invite_accepted": ia.invite_accepted(
            WID, b"i" * 32, b"x" * 32, b"127.0.0.1:9", epk, 1),
        "auth.active_workspace": aw.active_workspace(WID, 1),
        "connection.ephemeral_secret": es.ephemeral(fsk, fpk, 1),
        "connection.close": cl.close([CID], 1),
        "outbox.send": outsend.send(CID, b"payload", 1),
        "store.hydrate": hydrate.hydrate(),
        "sync.cadence": cadence.cadence(CID, b"", 500),
    }


def _request():
    eph, to, nonce = b"e" * 32, b"t" * 32, b"n" * 24
    env = frame(b"\x01", eph, to, nonce, b"ciphertext-tag!!")
    return req.request(env, to, eph, 1)


def _connection():
    eph, to, rid, nonce = b"e" * 32, b"t" * 32, b"r" * 32, b"n" * 24
    env = frame(b"\x01", eph, to, rid, nonce, b"ciphertext-tag!!")
    return conn.connection(env, rid)


def _wire(node, item, origin):
    fid = node.admit(encode(item), origin=origin)
    assert fid is not None
    node.run()
    return fid


def test_local_only_families_suppress_bare_and_connected_wire_input():
    for name, item in _local_only().items():
        for origin in (WireOrigin(), WireOrigin(CID)):
            node = Node(ROOT)
            fid = _wire(node, item, origin)
            assert fid not in node.facts, (name, origin)
            assert fid not in node.durable, (name, origin)
            assert fid not in node.pending_durable, (name, origin)
            assert not node.origins, (name, origin)


def test_the_same_local_only_shapes_stand_when_authored_locally():
    for name, item in _local_only().items():
        node = Node(ROOT)
        fid = node.admit(encode(item)); node.run()
        assert fid in node.facts, name
        assert node.memo[fid] in ("Valid", "Parked"), name


def test_sender_cannot_strip_a_family_provenance_relationship():
    for name, item in _local_only().items():
        stripped = fact(item.type_tag, *(a for a in item.atoms if a != remote_suppress))
        assert Node(ROOT).admit(encode(stripped), origin=WireOrigin(CID)) is None, name


def test_handshake_facts_accept_bare_but_not_connected_carriers():
    for item in (_request(), _connection()):
        bare = Node(ROOT); bare_id = _wire(bare, item, WireOrigin())
        assert bare_id in bare.facts
        connected = Node(ROOT); connected_id = _wire(connected, item, WireOrigin(CID))
        assert connected_id not in connected.facts


def test_sync_controls_require_a_matching_connection_carrier():
    controls = (
        need.need(CID, [b"f" * 32]),
        compare.compare(CID, [(b"fp", b"", compare.HI, b"fingerprint")]),
    )
    for item in controls:
        bare = Node(ROOT); bare_id = _wire(bare, item, WireOrigin())
        assert bare_id not in bare.facts

        right = Node(ROOT); right_id = _wire(right, item, WireOrigin(CID))
        assert right_id in right.facts and right.memo[right_id] == "Valid"

        wrong = Node(ROOT); wrong_id = _wire(wrong, item, WireOrigin(OTHER_CID))
        assert wrong_id not in wrong.facts


def test_shareable_content_crosses_an_authenticated_connection():
    target = b"t" * 32
    item = signature(WID, RPK, target, c.ed25519_sign(RK, target), 1)
    node = Node(ROOT); fid = _wire(node, item, WireOrigin(CID))
    assert fid in node.facts and fid in node.durable
    assert fid not in node.pending_durable and fid not in node.origins


def test_remote_local_fact_cannot_flush_or_resurrect_before_judgment():
    """A crash between admission and judgment must lose untrusted bytes."""
    from runtime import flush
    item = next(iter(_local_only().values()))
    fid, store, flushed = fact_id(item), Store(), set()
    node = Node(ROOT, store)
    assert node.admit(encode(item), origin=WireOrigin(CID)) == fid
    assert fid in node.pending_durable and fid not in node.durable
    flush(node, store, flushed)
    assert store.fact_bytes(fid) is None
    node.run(); flush(node, store, flushed)
    assert fid not in node.facts and store.fact_bytes(fid) is None

    rebooted = Node(ROOT, store)
    hydrate.demand(rebooted)
    assert fid not in rebooted.facts and fid not in rebooted.durable


def test_local_duplicate_upgrades_a_pending_wire_arrival():
    """A remote preplay cannot poison identical work genuinely authored here."""
    item = next(iter(_local_only().values()))
    node = Node(ROOT); fid = node.admit(encode(item), origin=WireOrigin(CID))
    assert fid in node.origins
    assert node.admit(encode(item)) == fid
    assert fid not in node.origins
    assert fid in node.durable and fid not in node.pending_durable
    node.run()
    assert fid in node.facts and fid in node.durable


def test_bad_origin_argument_is_rejected_before_node_mutation():
    item = next(iter(_local_only().values()))
    node = Node(ROOT)
    try:
        node.admit(encode(item), origin=CID)
    except TypeError:
        pass
    else:
        raise AssertionError("raw bytes are not a WireOrigin")
    assert not node.facts and not node.provides and not node.consumers
    assert not node.pending_durable
    try:
        WireOrigin(b"short")
    except ValueError:
        pass
    else:
        raise AssertionError("a connection origin must carry a FactId")


def test_remote_outbox_and_hydrate_cannot_trigger_host_work():
    node = Node(ROOT)
    _wire(node, outsend.send(CID, b"payload", 1), WireOrigin(CID))
    assert node.provided(b"send", b"outbox") == []

    secret = next(iter(_local_only().values()))
    store = Store(); store.add(encode(secret)); store.commit()
    cold = Node(ROOT, store)
    _wire(cold, hydrate.hydrate(), WireOrigin(CID))
    assert fact_id(secret) not in cold.facts


if __name__ == "__main__":
    for name, value in sorted(globals().items()):
        if name.startswith("test_"): value(); print(f"ok  {name}")
    print("\nall ingress tests passed")
