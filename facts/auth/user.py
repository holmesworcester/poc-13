"""facts/auth/user.py — workspace membership, bound to authority. A user offers
its name and its OWN durable public key, and is valid only if the key that
SIGNED it (pulled in as b"pk" context) equals a pk the authority chain blessed:
either the founder root (b"root" — the founder self-joins, signing with the same
key it rooted) or one specific user_invite's pk (b"invite" — a joiner signs the
membership with the INVITE key from the link, and the invite blessed that key).
So the user fact IS the invite acceptance: it carries the member's own pk, and
the invite key vouches for it by signing the whole fact (id covers every atom).
From then on the member signs with their own key, now a blessed member key.

Folding acceptance into the user fact (vs a separate invite_accepted family) is
the lower-LOC honest call: the signature already ties invite key -> this fact,
and Requiring the blesser ships it in the sync closure. Wrong signer key is
Out("Invalid") — a real refusal, distinct from parking on a missing signature."""
from kernel import (Atom, Exact, NEED, OFFER, Out, REQUIRE, SELF, by, encode,
                    fact, now, ts_atom)
from facts.auth import local_signer_secret, signature
from ed25519 import keygen
from facts.store import hydrate

TAG = b"auth.user"

# SHAPE — the canonical atom set; the only place atoms are chosen. invite_id
# names the user_invite blessing this join; None is the founder self-join path.
def user(workspace_id, name, pk, invite_id, t):
    bless = (Atom(NEED, b"invite", workspace_id, Exact(invite_id), effect=REQUIRE)
             if invite_id else Atom(NEED, b"root", b"auth", Exact(workspace_id), effect=REQUIRE))
    return fact(TAG, ts_atom(t, workspace_id), bless,
                Atom(NEED, b"pk", workspace_id, SELF, effect=REQUIRE),
                Atom(OFFER, b"member", workspace_id, SELF, name),
                Atom(OFFER, b"key", workspace_id, Exact(workspace_id), pk))

# EXTRACT — content-pure: (durable, shareable).
def extract(f): return True, True

# PROJECT — the only place this family's meaning lives.
def project(f, ctx, sl):                 # signer must equal a blessed pk: root or the named invite
    blessed = {r[2].value for r in by(ctx, b"root") + by(ctx, b"invite")}
    if not blessed & {r[2].value for r in by(ctx, b"pk")}: return Out("Invalid")
    return Out(offers=tuple(a for a in f.atoms if a.role in (b"member", b"key")))

# COMMANDS — build a fact, admit it, stop. invite=(invite_id, invite_secret).
def join(node, workspace_id, name, t, invite=None):
    local = local_signer_secret.current(node)
    if not local: raise RuntimeError("no local signer key: run auth.local_signer_secret.keygen first")
    _, member_pk = local
    if invite:
        iid, secret = invite; sk, pk = keygen(secret)   # sign the membership with the invite key
    else:
        iid, (sk, pk) = None, local                     # founder self-join: local key IS the root
    uid = node.admit(encode(user(workspace_id, name, member_pk, iid, t)))
    signature.attest(node, workspace_id, sk, pk, uid, t)
    return uid

# QUERIES — observations over validated state only, ordered by (ts, owner).
def roster(node, workspace_id):
    hydrate.demand(node, b"member", workspace_id); node.run()
    return [a.value for o, t, a in sorted(node.watched(b"member", workspace_id),
                                          key=lambda r: (r[1], r[0]))]

# CLI — string boundary over COMMANDS/QUERIES. An invite link is "invite_id:secret";
# with no link, join is the founder self-join (sign with the local root key).
CLI = {"join": lambda n, wid, name, t=None, link=None:
           join(n, bytes.fromhex(wid), name.encode(), int(t or now()),
                invite=_link(link)).hex(),
       "roster": lambda n, wid: b"\n".join(roster(n, bytes.fromhex(wid))).decode()}

def _link(arg):                          # "invite_id:secret" -> (id bytes, secret bytes)
    if not arg: return None
    iid, secret = arg.split(":"); return bytes.fromhex(iid), bytes.fromhex(secret)
