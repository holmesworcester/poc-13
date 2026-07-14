"""Shared signed-content fixtures for tests that build facts directly: a
member enrolled via the invite chain, and (fact, signature) bundles authored
by that member. flat() splices bundles into an admission list."""
from types import SimpleNamespace

import crypto as _c
from kernel import fact_id
from facts.auth.signature import signature
from facts.auth.user import user
from facts.auth.user_invite import user_invite
from facts.content.channel import channel
from facts.content.message import message
from facts.content.message_deletion import deletion


def member_context(wid, root_sk, root_pk, name=b"al", t=100):
    isk, ipk = _c.ed25519_keygen(b"i" * 32)
    msk, mpk = _c.ed25519_keygen(b"m" * 32)
    inv = user_invite(wid, ipk, t); iid = fact_id(inv)
    u = user(wid, name, mpk, iid, t + 1); uid = fact_id(u)
    facts = (inv, signature(wid, root_pk, iid, _c.ed25519_sign(root_sk, iid), t),
             u, signature(wid, ipk, uid, _c.ed25519_sign(isk, uid), t + 1))
    return SimpleNamespace(uid=uid, sk=msk, pk=mpk, facts=facts)


def signed_message(member, wid, channel, body, t):
    m = message(wid, channel, member.uid, body, t)
    mid = fact_id(m)
    return m, signature(wid, member.pk, mid, _c.ed25519_sign(member.sk, mid), t)


def signed_channel(member, wid, name, t):
    c = channel(wid, name, t)
    cid = fact_id(c)
    return c, signature(wid, member.pk, cid, _c.ed25519_sign(member.sk, cid), t)


def signed_deletion(member, wid, target_id, t):
    d = deletion(wid, target_id, t)
    did = fact_id(d)
    return d, signature(wid, member.pk, did, _c.ed25519_sign(member.sk, did), t)


def flat(bundles):
    return [f for b in bundles for f in b]
