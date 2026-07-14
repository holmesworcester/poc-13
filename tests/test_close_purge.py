"""Close (poc-10 close-purge, now a kernel consequence): severing a live session
flips its whole cluster — the connection, its request, and the handshake
ephemerals — to Suppressed via the death key each carries, and suppression
purges: the cluster leaves memory and disk at the verdict itself, no sweep to
schedule. The daemon drops the socket and stops dialing; the durable close is
what a restart keeps — the peer stays closed because the request it would
re-dial from no longer exists."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from kernel import Node, Store, WireOrigin, encode, fact_id
from harness import reboot
from facts import ROOT
from facts.auth import endpoint, invite_accepted, local_signer_secret, user_invite
from facts.auth import workspace as wsmod
from facts.connection import request as req, connection as conn, close, ephemeral_secret
from facts.store import hydrate

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
    host.admit(joiner.durable[rid], origin=WireOrigin()); host.run()
    cid = conn.respond(host, rid, b"127.0.0.1:7", 4); host.run()
    joiner.admit(encode(host.facts[cid]), origin=WireOrigin()); joiner.run()
    return rid, cid

def _ephemerals(node):
    return [k for k, f in node.facts.items() if f.type_tag == b"connection.ephemeral_secret"]

def test_sever_purges_the_whole_cluster():
    host, joiner = _node(), _node()
    rid, cid = _handshake(host, joiner)
    ephs = _ephemerals(host)
    assert host.memo[rid] == "Valid" and host.memo[cid] == "Valid" and ephs
    close.sever(host, cid, 5); host.run()
    for fid in (rid, cid, *ephs):        # killed = gone whole: no dialing, no socket, no husk
        assert fid not in host.facts and fid not in host.durable and fid not in host.memo

def test_restart_stays_closed():
    host, joiner = _node(), _node()
    rid, cid = _handshake(host, joiner)
    close.sever(host, cid, 5); host.run()
    m = reboot(host)                     # the durable close reboots; the cluster it killed does not
    assert rid not in m.facts and cid not in m.facts, "a severed peer stays closed across restart"
    assert any(f.type_tag == b"connection.close" for f in m.facts.values())

def test_sever_reclaims_secrets_from_disk():
    host, joiner = _node(), _node()
    rid, cid = _handshake(host, joiner)
    store = Store()
    for b in host.durable.values(): store.add(b)                 # persist the session
    store.commit()
    host.store = store                   # production wires the store at boot (tinyd.py)
    ephs = _ephemerals(host)
    close.sever(host, cid, 5); host.run()
    assert set(host.purged) >= set(ephs), "the kernel reports what left disk, for flush bookkeeping"
    assert all(store.db.execute("SELECT 1 FROM facts WHERE fid=?", (e,)).fetchone() is None
               for e in ephs), "secret bytes are gone from disk the moment the session dies"
    assert all(e not in host.facts and e not in host.durable for e in ephs), "and from memory"

def test_cold_suppression_deletes_checked_store_fact():
    """A checked fault is already on disk, so a terminal first resident verdict
    must delete the SQLite owner rather than treating it like an unflushed arrival."""
    import crypto
    sk, pk = crypto.x25519_keygen(b"cold" * 8)
    victim = ephemeral_secret.ephemeral(sk, pk, 1); vid = fact_id(victim)
    killer = close.close([vid], 2)
    store = Store()
    for item in (victim, killer): store.add(encode(item))
    store.commit()
    node = Node(ROOT, store); hydrate.demand(node)
    assert vid not in node.facts and vid not in node.durable
    assert store.fact_bytes(vid) is None

if __name__ == "__main__":
    for t in (test_sever_purges_the_whole_cluster, test_restart_stays_closed,
              test_sever_reclaims_secrets_from_disk,
              test_cold_suppression_deletes_checked_store_fact):
        t(); print(f"ok  {t.__name__}")
    print("\nall close/purge tests passed")
