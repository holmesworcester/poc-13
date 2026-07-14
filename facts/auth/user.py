"""facts/auth/user.py — workspace membership, bound to authority. A user provides
its name and its OWN durable public key, and is valid only if the key that
SIGNED it (pulled in as b"pk" context) equals a pk one specific user_invite
blessed (b"invite" — a joiner signs the membership with the INVITE key from the
link, and the invite blessed that key). So the user fact IS the membership
credential: it carries the member's own pk, and the invite key vouches for it by
signing the whole fact (id covers every atom). From then on the member signs
with their own key, now a blessed member key. There is no founder self-join
path: the creator joins via the workspace's own first invite (see workspace.py),
so every member — founder included — reaches authority the same way.

Wrong signer key is Out("Invalid") — a real refusal, distinct from parking on a
missing signature. Acceptance (auth.invite_accepted) is authored alongside the
join: it is what makes the joined workspace Valid on this node."""
from kernel import (Atom, Exact, PROVIDE, Out, REQUIRE, SELF, by, encode,
                    fact, now, ts_atom)
from facts.auth import invite_accepted, local_signer_secret, signature
from crypto import ed25519_keygen as keygen
from facts.store import hydrate

TAG = b"auth.user"

# SHAPE — the canonical atom set; the only place atoms are chosen. invite_id
# names the user_invite blessing this join.
def user(workspace_id, name, pk, invite_id, t):
    return fact(TAG, ts_atom(t, workspace_id),
                Atom(REQUIRE, b"invite", workspace_id, Exact(invite_id)),
                Atom(REQUIRE, b"pk", workspace_id, SELF),
                Atom(PROVIDE, b"member", workspace_id, SELF, name),
                Atom(PROVIDE, b"key", workspace_id, Exact(workspace_id), pk))

# EXTRACT — content-pure durability.
def extract(f): return True
from facts.sync.index import sync_leaf

# PROJECT — the only place this family's meaning lives.
def project(f, ctx):                 # signer must equal the pk the named invite blessed
    blessed = {r[2].value for r in by(ctx, b"invite")}
    if not blessed & {r[2].value for r in by(ctx, b"pk")}: return Out("Invalid")
    return Out(provides=tuple(a for a in f.atoms if a.name in (b"member", b"key")) + (sync_leaf(),))

# COMMANDS — build a fact, admit it, stop. invite=(invite_id, invite_secret);
# authoring the acceptance is what makes the joined workspace Valid on this node.
def join(node, workspace_id, name, t, invite):
    from facts.auth import device
    local = local_signer_secret.current(node)
    if not local: raise RuntimeError("no local signer key: run auth.local_signer_secret.keygen first")
    _, member_pk = local
    iid, secret = invite; sk, pk = keygen(secret)       # sign the membership with the invite key
    invite_accepted.accept(node, workspace_id, iid, secret, b"", member_pk, t); node.run()
    uid = node.admit(encode(user(workspace_id, name, member_pk, iid, t)))
    signature.attest(node, workspace_id, sk, pk, uid, t); node.run()
    device.bind(node, workspace_id, name, t)            # bind this node's endpoint (self-attested)
    return uid

# QUERIES — observations over validated state only, ordered by (ts, owner).
def roster(node, workspace_id):
    hydrate.demand(node, b"member", workspace_id)
    return [a.value for o, t, a in sorted(node.provided(b"member", workspace_id),
                                          key=lambda r: (r[1], r[0]))]

# CLI — string boundary over COMMANDS/QUERIES. An invite link is "invite_id:secret"
# (the founder is enrolled by workspace.create; everyone else joins via a link).
CLI = {"join": lambda n, wid, name, link, t=None:
           join(n, bytes.fromhex(wid), name.encode(), int(t or now()),
                invite=_link(link)).hex(),
       "roster": lambda n, wid: b"\n".join(roster(n, bytes.fromhex(wid))).decode()}

def _link(arg):                          # "invite_id:secret" -> (id bytes, secret bytes)
    iid, secret = arg.split(":"); return bytes.fromhex(iid), bytes.fromhex(secret)
