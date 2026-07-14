"""Handshake tests, in-process: two Nodes hand-carry the sealed request and
connection over a simulated wire and must derive the SAME connection_secret,
the responder's authoring must be deterministic across a reboot, and every forged
or mis-addressed variant must be refused. Mirrors poc-10
poc10_connection_handler_test.rs — secret agreement, responder determinism,
mis-addressed and bad-signature refusals — in TinyP2P's atom model."""
import os, sys
from dataclasses import replace
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from kernel import Node, decode, encode, fact, fact_id
from harness import reboot
from facts import ROOT
from facts.auth import endpoint, invite_accepted, local_signer_secret, workspace as wsmod
from facts.auth import user_invite
from facts.connection import request as req, connection as conn

def _node():
    n = Node(ROOT)
    endpoint.keygen(n, 1); local_signer_secret.keygen(n, 1); n.run()
    return n

def _wire(dst, src, tag):                # move every fact of a type from src to dst, admit
    moved = []
    for fid, f in list(src.facts.items()):
        if f.type_tag == tag:
            if dst.admit(src.durable.get(fid) or encode(f)): moved.append(fid)
    dst.run(); return moved

def _invited_workspace(host):
    """host founds a workspace and mints a bootstrap invite; returns
    (wid, secret, host_endpoint_pk)."""
    wid = wsmod.create(host, b"acme", 1); host.run()
    iid, secret = user_invite.invite(host, wid, 2); host.run()
    _, epk = endpoint.current(host)
    # the inviter keeps the bootstrap secret so it can authorize the request
    invite_accepted.accept(host, wid, iid, secret, b"127.0.0.1:9", epk, 2); host.run()
    return wid, secret, iid, epk

def _handshake(host, joiner):
    wid, secret, iid, host_ep = _invited_workspace(host)
    _, join_ep = endpoint.current(joiner)
    rid = req.bootstrap(joiner, wid, secret, iid, host_ep, b"127.0.0.1:9", b"127.0.0.1:7", 3)
    joiner.run()
    assert joiner.memo[rid] == "Valid", "joiner's own request must validate"
    # wire: request -> host; host authors the connection; connection -> joiner
    host.admit(joiner.durable[rid]); host.run()
    # only the addressee can open the request, so it responds (no receipt needed)
    cid = conn.respond(host, rid, b"127.0.0.1:7", 4); host.run()
    assert cid and host.memo[cid] == "Valid", "responder connection must validate"
    joiner.admit(encode(host.facts[cid])); joiner.run()
    assert joiner.memo[cid] == "Valid", "initiator connection must validate"
    return rid, cid

def test_both_sides_derive_the_same_secret():
    host, joiner = _node(), _node()
    rid, cid = _handshake(host, joiner)
    assert conn.secret(host, cid) == conn.secret(joiner, cid) is not None
    assert len(conn.secret(host, cid)) == 32
    assert joiner.memo[rid] == "Valid"           # request stays valid; answered retired its resend

def test_responder_authoring_is_deterministic():
    host, joiner = _node(), _node()
    _, cid1 = _handshake(host, joiner)
    # re-run respond on a freshly rebooted host: identical connection id
    host2 = reboot(host)
    rid = next(fid for fid, f in host.facts.items() if f.type_tag == req.TAG)
    cid2 = conn.respond(host2, rid, b"127.0.0.1:7", 4); host2.run()
    assert cid2 == cid1, "deterministic responder output: same connection id on replay"

def test_mis_addressed_request_never_responds():
    host, joiner, other = _node(), _node(), _node()
    wid, secret, iid, host_ep = _invited_workspace(host)
    _, wrong_ep = endpoint.current(other)        # seal to the wrong endpoint
    rid = req.bootstrap(joiner, wid, secret, iid, wrong_ep, b"127.0.0.1:9", b"127.0.0.1:7", 3)
    joiner.run()
    host.admit(joiner.durable[rid]); host.run()
    # host cannot open a request sealed to another endpoint: no respond, no connection
    assert conn.respond(host, rid, b"127.0.0.1:7", 4) is None
    assert host.memo.get(rid) in ("Parked", None)

def test_wrong_invite_signature_is_invalid():
    host, joiner = _node(), _node()
    wid, secret, iid, host_ep = _invited_workspace(host)
    # forge: sign the request with a random key, not keygen(secret). Patch the
    # binding the authoring code actually uses (req.sign), not crypto's export.
    import crypto
    bad, orig = crypto.ed25519_keygen()[0], req.sign
    try:
        req.sign = lambda sk, m: orig(bad, m)          # every request sig is forged
        rid = req.bootstrap(joiner, wid, secret, iid, host_ep, b"127.0.0.1:9", b"127.0.0.1:7", 3)
    finally:
        req.sign = orig
    host.admit(joiner.durable[rid]); host.run()
    assert host.memo[rid] == "Invalid", "a request not signed by the invite key is refused"

def test_tampered_request_ciphertext_is_inert():
    host, joiner = _node(), _node()
    wid, secret, iid, host_ep = _invited_workspace(host)
    rid = req.bootstrap(joiner, wid, secret, iid, host_ep, b"127.0.0.1:9", b"127.0.0.1:7", 3)
    joiner.run()
    original = decode(joiner.durable[rid])
    atoms = []
    for atom in original.atoms:
        if atom.name == b"sreq":
            value = bytearray(atom.value); value[-1] ^= 1  # flip the envelope's final ciphertext byte
            atom = replace(atom, value=bytes(value))
        atoms.append(atom)
    bad = encode(fact(original.type_tag, *atoms))
    # structural CHECK still passes (widths intact); the host opens -> fails -> Parked, never responds
    fid = host.admit(bad)
    if fid: host.run(); assert host.memo.get(fid) in ("Parked", "Invalid")

if __name__ == "__main__":
    for t in (test_both_sides_derive_the_same_secret,
              test_responder_authoring_is_deterministic,
              test_mis_addressed_request_never_responds,
              test_wrong_invite_signature_is_invalid,
              test_tampered_request_ciphertext_is_inert):
        t(); print(f"ok  {t.__name__}")
    print("\nall handshake tests passed")
