"""facts/auth/founder.py — the authority root's public key. The workspace fact
is a pure function of its name (its id must stay deterministic for sync), so it
cannot carry a key; the founder fact is where a key roots the workspace. It
declares the founder pk, Requires its own signature by that same pk (you only
root a key you actually hold), and Requires the workspace so it parks until the
root it scopes exists. Its b"root" offer is what user/user_invite/admin
value-compare a signer against — the trust anchor the whole chain climbs to.

Pinning is trust-on-first-use: with a keyless workspace id nothing stops a
second founder fact declaring a rival root, but a member only validates against
a root it can see, and legitimately-invited members chain to the founder whose
key signed their invite — a rival root roots only its own disjoint tree."""
from kernel import Atom, Exact, NEED, OFFER, Out, REQUIRE, SELF, by, encode, fact, now, ts_atom
from facts.auth import local_signer_secret, signature
from facts.store import hydrate

TAG = b"auth.founder"

# SHAPE — the canonical atom set; the only place atoms are chosen.
def founder(workspace_id, pk, t):
    return fact(TAG, ts_atom(t, workspace_id),
                Atom(NEED, b"workspace", b"auth", Exact(workspace_id), effect=REQUIRE),
                Atom(NEED, b"pk", workspace_id, SELF, effect=REQUIRE),
                Atom(OFFER, b"root", b"auth", Exact(workspace_id), pk))

# EXTRACT — content-pure: (durable, shareable).
def extract(f): return True, True

# PROJECT — the only place this family's meaning lives.
def project(f, ctx, sl):                 # a root is real only if signed by the key it names
    declared = {a.value for a in f.atoms if a.role == b"root"}
    if not declared & {r[2].value for r in by(ctx, b"pk")}: return Out("Invalid")
    return Out(offers=tuple(a for a in f.atoms if a.role == b"root"))

# COMMANDS — build a fact, admit it, stop.
def claim(node, workspace_id, t):
    if not local_signer_secret.current(node):
        local_signer_secret.keygen(node, t); node.run()   # validate the new key before we read it
    sk, pk = local_signer_secret.current(node)
    fid = node.admit(encode(founder(workspace_id, pk, t)))
    signature.attest(node, workspace_id, sk, pk, fid, t)
    return fid

# QUERIES — observations over validated state only.
def root(node, workspace_id):
    hydrate.demand(node, b"root", b"auth"); node.run()
    return next((a.value for _, _, a in node.watched(b"root", b"auth")
                 if a.target == Exact(workspace_id)), None)

# CLI — string boundary over COMMANDS/QUERIES.
CLI = {"claim": lambda n, wid, t=None: claim(n, bytes.fromhex(wid), int(t or now())).hex(),
       "root": lambda n, wid: (root(n, bytes.fromhex(wid)) or b"").hex()}
