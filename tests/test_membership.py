"""Membership reconnect: once two nodes are members of a workspace and have
synced each other's device (endpoint binding), either can open a fresh
connection with NO invite — proving identity by its own signing key over its
endpoint_shared record, poc-10's membership-mode handshake. Also checks that
peers() reads the binding back as an auth column (member name, not anon)."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from kernel import Node, WireOrigin, encode
from facts import ROOT
from facts.auth import endpoint, local_signer_secret, user_invite, device
from facts.auth import user as usermod, workspace as wsmod
from facts.connection import request as req, connection as conn
from facts.sync import index as sidx

def _node():
    n = Node(ROOT)
    endpoint.keygen(n, 1); local_signer_secret.keygen(n, 1); n.run()
    return n

def _sync(dst, src):                     # ship every validated sync-leaf owner into dst
    for fid, b in list(src.durable.items()):
        if sidx.contains(src, fid): dst.admit(b)
    dst.run()

def _members(host, joiner):
    """host founds a workspace (founder user + device); joiner joins through the
    first invite (its own user + device); then both sync so each holds the
    other's device (endpoint binding)."""
    wid = wsmod.create(host, b"acme", 1); host.run()
    iid, secret = user_invite.invite(host, wid, 2); host.run()
    _sync(joiner, host)                  # joiner needs the workspace + invite to join
    usermod.join(joiner, wid, b"bo", 3, invite=(iid, secret)); joiner.run()
    _sync(host, joiner); _sync(joiner, host)   # each learns the other's device
    return wid

def test_membership_reconnect_without_invite():
    host, joiner = _node(), _node()
    wid = _members(host, joiner)
    _, host_ep = endpoint.current(host)
    # joiner reconnects with NO invite — a pure membership proof, signed by its member key
    rid = req.membership(joiner, wid, host_ep, b"127.0.0.1:9", b"127.0.0.1:7", 5); joiner.run()
    assert rid and joiner.memo[rid] == "Valid", "membership request validates on the initiator"
    host.admit(joiner.durable[rid], origin=WireOrigin()); host.run()
    cid = conn.respond(host, rid, b"127.0.0.1:7", 6); host.run()
    assert cid and host.memo[cid] == "Valid", "responder recognizes the member and connects"
    joiner.admit(encode(host.facts[cid]), origin=WireOrigin()); joiner.run()
    assert joiner.memo[cid] == "Valid"
    assert conn.secret(host, cid) == conn.secret(joiner, cid) is not None
    assert len(conn.secret(host, cid)) == 32

def test_non_member_endpoint_cannot_reconnect():
    host, joiner = _node(), _node()
    wid = _members(host, joiner)
    stranger = _node()                   # a node with an endpoint but no membership/device here
    _, host_ep = endpoint.current(host)
    assert req.membership(stranger, wid, host_ep, b"127.0.0.1:9", b"127.0.0.1:7", 5) is None, \
        "no device binding -> no membership proof -> no request"

def test_peers_shows_the_authenticated_member():
    host, joiner = _node(), _node()
    wid = _members(host, joiner)
    _, host_ep = endpoint.current(host)
    rid = req.membership(joiner, wid, host_ep, b"127.0.0.1:9", b"127.0.0.1:7", 5); joiner.run()
    host.admit(joiner.durable[rid], origin=WireOrigin()); host.run()
    cid = conn.respond(host, rid, b"127.0.0.1:7", 6); host.run()
    # the host sees the connection's peer endpoint resolve to the joining member 'bo'
    who = {ep: w for ep, _a, _c, w in conn.peers(host)}
    _, join_ep = endpoint.current(joiner)
    assert who.get(join_ep) == b"bo", who

if __name__ == "__main__":
    for t in (test_membership_reconnect_without_invite,
              test_non_member_endpoint_cannot_reconnect,
              test_peers_shows_the_authenticated_member):
        t(); print(f"ok  {t.__name__}")
    print("\nall membership tests passed")
