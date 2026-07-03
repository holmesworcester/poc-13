"""Close and purge (poc-10 close-purge): severing a live session flips its whole
cluster — the connection, its request, and the handshake ephemerals — to
Suppressed via the death key each carries, so the daemon drops the socket and
stops dialing; the close is durable, so a restart replays it and the peer stays
closed. Purge is the forward-secrecy sweep: once suppressed, the ephemeral
private keys are DELETEd from disk and dropped from memory, leaving no residue."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from kernel import Node, Store, encode
from facts import ROOT
from facts.auth import endpoint, invite_accepted, local_signer_secret, user_invite
from facts.auth import workspace as wsmod
from facts.connection import request as req, connection as conn, close

def _node():
    n = Node(ROOT)
    endpoint.keygen(n, 1); local_signer_secret.keygen(n, 1); n.run()
    return n

def _handshake(host, joiner):            # a full bootstrap handshake; returns (rid, cid) on the host
    wid = wsmod.create(host, b"acme", 1); host.run()
    iid, secret = user_invite.invite(host, wid, 2); host.run()
    _, host_ep = endpoint.current(host)
    invite_accepted.accept(host, wid, iid, secret, b"127.0.0.1:9", host_ep, 2); host.run()
    rid = req.bootstrap(joiner, wid, secret, iid, host_ep, b"127.0.0.1:9", b"127.0.0.1:7", 3); joiner.run()
    host.admit(joiner.durable[rid]); host.run()
    cid = conn.respond(host, rid, b"127.0.0.1:7", 4); host.run()
    joiner.admit(encode(host.facts[cid])); joiner.run()
    return rid, cid

def _ephemerals(node):
    return [k for k, f in node.facts.items() if f.type_tag == b"connection.ephemeral_secret"]

def test_sever_suppresses_the_whole_cluster():
    host, joiner = _node(), _node()
    rid, cid = _handshake(host, joiner)
    ephs = _ephemerals(host)
    assert host.memo[rid] == "Valid" and host.memo[cid] == "Valid" and ephs
    close.sever(host, cid, 5); host.run()
    assert host.memo[rid] == "Suppressed"                        # request killed: no more dialing
    assert host.memo[cid] == "Suppressed"                        # connection killed
    assert all(host.memo[e] == "Suppressed" for e in ephs)       # handshake secret killed

def test_restart_stays_closed():
    host, joiner = _node(), _node()
    rid, cid = _handshake(host, joiner)
    close.sever(host, cid, 5); host.run()
    m = host.replay()                                            # durable close replays
    assert m.memo[rid] == "Suppressed", "a severed peer stays closed across restart"

def test_purge_reclaims_the_ephemeral_secret():
    host, joiner = _node(), _node()
    rid, cid = _handshake(host, joiner)
    store = Store()
    for b in host.durable.values(): store.add(b)                 # persist the session
    store.commit()
    ephs = _ephemerals(host)
    close.sever(host, cid, 5); host.run()
    gone = close.purge(host, store, cid)
    assert set(gone) == set(ephs), "purge reclaims exactly the suppressed handshake secrets"
    assert all(store.db.execute("SELECT 1 FROM facts WHERE fid=?", (e,)).fetchone() is None
               for e in ephs), "secret bytes are gone from disk"
    assert all(e not in host.facts and e not in host.durable for e in ephs), "and from memory"

if __name__ == "__main__":
    for t in (test_sever_suppresses_the_whole_cluster, test_restart_stays_closed,
              test_purge_reclaims_the_ephemeral_secret):
        t(); print(f"ok  {t.__name__}")
    print("\nall close/purge tests passed")
