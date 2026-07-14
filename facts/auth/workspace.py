"""facts/auth/workspace.py — the namespace root AND the authority root: the
workspace fact embeds the founding (root) public key (poc-10 tag 131 carries
`public_key`, and has no separate founder fact). Two things gate its validity,
so it is never self-trusting: a `pk` signature by the root key over the
workspace id (you only found a workspace with the key you hold), and a LOCAL
`workspace_accepted` from an auth.invite_accepted — a workspace fact received
over sync is inert until THIS node accepted an invite to it (or created it). Its
validated `root` Provide is the trust anchor the whole chain climbs to; user,
user_invite, and admin value-compare a signer against it.

The root private key is temporary to create(): it signs the workspace, the
first invite, and the bootstrap admin, then is dropped — never a durable fact.
After that grant, authority flows only through existing member/admin facts."""
from kernel import (Atom, Exact, PROVIDE, Out, REQUIRE, SELF, by, encode,
                    fact, now, ts_atom)
from facts.store import hydrate

TAG = b"auth.workspace"

# SHAPE — the canonical atom set; the only place atoms are chosen.
def workspace(name, root_pk, t):
    return fact(TAG, ts_atom(t, b"auth"),
                Atom(REQUIRE, b"pk", b"auth", SELF),               # root self-signature
                Atom(REQUIRE, b"workspace_accepted", b"auth", SELF),  # local acceptance
                Atom(PROVIDE, b"workspace", b"auth", SELF, name),
                Atom(PROVIDE, b"root", b"auth", SELF, root_pk))

# EXTRACT — content-pure durability.
def extract(f): return True
from facts.sync.index import sync_leaf

# PROJECT — valid only if the embedded root key signed it (and it is accepted).
def project(f, ctx):
    root_pk = {a.value for a in f.atoms if a.name == b"root"}
    if not root_pk & {r[2].value for r in by(ctx, b"pk")}: return Out("Invalid")
    return Out(provides=tuple(a for a in f.atoms if a.name in (b"workspace", b"root"))
                       + (sync_leaf(),))

# COMMANDS — the full bootstrap DAG, all signed by an ephemeral root then dropped.
def create(node, name, t):
    from facts.auth import (admin, invite_accepted, local_signer_secret, signature,
                            user, user_invite)
    from crypto import ed25519_keygen as keygen
    rsk, rpk = keygen()                              # the ephemeral workspace root key
    wid = node.admit(encode(workspace(name, rpk, t)))
    signature.attest(node, b"auth", rsk, rpk, wid, t)           # root signs the workspace
    if not local_signer_secret.current(node):        # this node's durable member identity
        local_signer_secret.keygen(node, t); node.run()
    _, member_pk = local_signer_secret.current(node)
    isk, ipk = keygen()                              # the first invite key (root-blessed)
    iid = node.admit(encode(user_invite.user_invite(wid, ipk, t)))
    signature.attest(node, wid, rsk, rpk, iid, t); node.run()   # root signs the first invite
    secret = isk                                     # the invite secret IS the invite key seed
    invite_accepted.accept(node, wid, iid, secret, b"", member_pk, t)   # local acceptance
    node.run()
    uid = user.join(node, wid, b"founder", t, invite=(iid, secret))     # founder joins via it
    aid = node.admit(encode(admin.admin(wid, uid, t)))
    signature.attest(node, wid, rsk, rpk, aid, t)               # root signs the bootstrap admin
    node.run()
    from facts.content import channel
    channel.create(node, wid, b"general", t); node.run() # replicated default, not a local alias
                                                        # rsk/rpk fall out of scope here: dropped
    return wid

# QUERIES — observations over validated state only, ordered by (ts, owner).
def index(node):
    hydrate.demand(node, b"workspace", b"auth")
    return [(o, a.value) for o, t, a in sorted(node.provided(b"workspace", b"auth"),
                                               key=lambda r: (r[1], r[0]))]

def root(node, workspace_id):
    hydrate.demand(node, b"root", b"auth")
    return next((a.value for _, _, a in node.provided(b"root", b"auth")
                 if a.target == Exact(workspace_id)), None)

# CLI — string boundary over COMMANDS/QUERIES.
CLI = {"create": lambda n, name, t=None: create(n, name.encode(), int(t or now())).hex(),
       "index": lambda n: "\n".join(f"{o.hex()} {v.decode()}" for o, v in index(n)),
       "root": lambda n, wid: (root(n, bytes.fromhex(wid)) or b"").hex()}
