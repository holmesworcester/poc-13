"""Wire-ingress provenance: a fact family whose facts are node-private authority
(a private key, the endpoint secret, the workspace acceptance that anchors trust,
the local active-workspace selection, a handshake ephemeral, a session teardown)
is authored only by local commands. The daemon admits peer bytes with local=False,
and each such family's check refuses that origin — so a connected peer can never
inject one. Shareable content and the handshake are provenance-agnostic and still
cross. The enforcement is per-family (nothing generic derives it), so this test
enumerates the gated set: a family that forgets its check would slip through here."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import crypto as c
from kernel import Node, encode, fact_id
from facts import ROOT
from facts.auth.workspace import workspace
from facts.auth import local_signer_secret as lss, endpoint as ep
from facts.auth import invite_accepted as ia, active_workspace as aw
from facts.auth.signature import signature
from facts.connection import close as cl, ephemeral_secret as es

RK, RPK = c.ed25519_keygen(bytes(32))
WS = workspace(b"acme", RPK, 1); WID = fact_id(WS)

def _node_private():                     # one valid-shaped fact per node-private family
    sk, pk = c.ed25519_keygen(b"s" * 32)
    esk, epk = c.x25519_keygen(b"e" * 32)
    fsk, fpk = c.x25519_keygen(b"f" * 32)
    return {
        "local_signer_secret": lss.secret(sk, pk, 1),
        "endpoint": ep.endpoint(esk, epk, 1),
        "ephemeral_secret": es.ephemeral(fsk, fpk, 1),
        "invite_accepted": ia.invite_accepted(WID, b"i" * 32, b"x" * 32, b"", pk, 1),
        "active_workspace": aw.active_workspace(WID, 1),
        "close": cl.close([b"c" * 32], 1),
    }

def test_node_private_facts_are_refused_from_the_wire():
    for name, f in _node_private().items():
        b = encode(f)
        assert Node(ROOT).admit(b, local=False) is None, name    # a peer cannot inject it
        assert Node(ROOT).admit(b, local=True) is not None, name # local authorship admits the same bytes

def test_shareable_content_still_crosses_the_wire():
    # a signature is a shareable, synced fact: its gate verifies the crypto and is
    # provenance-agnostic, so it admits from a peer. (The handshake, the other
    # wire-legitimate arrival, is exercised end-to-end by test_pair / test_transport.)
    tgt = b"t" * 32
    s = signature(WID, RPK, tgt, c.ed25519_sign(RK, tgt), 1)
    assert Node(ROOT).admit(encode(s), local=False) is not None

if __name__ == "__main__":
    for t in (test_node_private_facts_are_refused_from_the_wire,
              test_shareable_content_still_crosses_the_wire):
        t(); print(f"ok  {t.__name__}")
    print("\nall ingress tests passed")
