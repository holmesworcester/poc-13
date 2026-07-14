"""facts/auth/signature.py — a detached Ed25519 signature over another fact's
id. Offers b"pk" (the signer's public key) and b"sig" at the target's id in the
workspace scope. A signed fact Requires b"pk" at its own id, so the signer key
lands in the projector's context and the authority chain can value-compare it
against the pk it blessed (either order — out-of-order safe). The gate proves
SOME key signed; that compare is what binds the key to workspace authority. The
signature is checked once at the admission gate (the
CHECK part) over exactly the 32-byte target id: the id IS the whole canonical
fact, so signing it covers everything. Wrong math is falsy at the gate — an
inert miss, never a bad fact, and replay never re-verifies. Durable and
shareable: a signature must travel with what it signs, and being a Require
dep it ships automatically under dep-aware sync.

A pk offer IS an authority claim ("this key signed that id"), so the fact must
carry nothing beyond the one claim the gate verified: extra atoms could smuggle
an unverified pk at a foreign id past the one check. Canonical form is enforced
by rebuilding through SHAPE and comparing — the builder is the only shape
authority, so the gate can never drift from it."""
from kernel import Atom, Exact, OFFER, Out, by, encode, fact, now, ts_atom, ts_of
from crypto import ed25519_sign as sign, ed25519_verify as verify
from facts.store import hydrate

TAG = b"auth.signature"

# SHAPE — the canonical atom set; the only place atoms are chosen.
def signature(workspace_id, pk, target_id, sig, t):
    return fact(TAG, ts_atom(t, workspace_id),
                Atom(OFFER, b"pk", workspace_id, Exact(target_id), pk),
                Atom(OFFER, b"sig", workspace_id, Exact(target_id), sig))

# EXTRACT — content-pure: (durable, shareable).
def extract(f): return True, True
from facts.sync.index import settle      # opt in: these facts replicate (one line is the whole choice)

# CHECK — optional self-verification at the admission gate: a pure function
# of the fact's own bytes, run once and never on replay.
def _canonical(f):                       # the free parameters, or None if f is not
    try:                                 # exactly SHAPE over them (tag included)
        pk = next(a for a in f.atoms if a.role == b"pk")
        sig = next(a for a in f.atoms if a.role == b"sig")
        tgt = pk.target[0]               # SELF is (): the miss lands in the except
        if f != signature(pk.scope, pk.value, tgt, sig.value, ts_of(f)): return None
        ok = len(pk.value) == 32 and len(sig.value) == 64 and len(tgt) == 32
        return (pk, sig, tgt) if ok else None
    except Exception:
        return None

def check(f):                            # verify over the exact target a Require will match
    parts = _canonical(f)
    return bool(parts and verify(parts[0].value, parts[2], parts[1].value))

# PROJECT — the only place this family's meaning lives.
def project(f, ctx):                     # publish only the canonical signer pk and sig
    parts = _canonical(f)
    return Out(offers=parts[:2]) if parts else Out("Invalid")
# a fact Requires b"pk" at its own id to pull WHO signed it into ctx, then a
# projector value-compares that pk against the pk its authority chain blessed.

# The signing context a member-gated projector compares against: who signed
# this fact (b"pk" at its id), and every member's blessed key by member id.
def blessed(ctx):
    return ({r[2].value for r in by(ctx, b"pk")},
            {r[0]: r[2].value for r in by(ctx, b"key")})

# COMMANDS — build a fact, admit it, stop.
def attest(node, workspace_id, sk, pk, target_id, t):
    return node.admit(encode(signature(workspace_id, pk, target_id, sign(sk, target_id), t)))

# Author a member-signed fact: the local signer must be an enrolled member of
# the workspace; the fact is admitted and its signature attested in one step.
def signed_admit(node, workspace_id, build, t):
    from facts.auth import local_signer_secret
    local = local_signer_secret.current(node)
    if not local: raise RuntimeError("no local signer key: run auth.local_signer_secret.keygen first")
    sk, pk = local
    hydrate.demand(node, b"key", workspace_id)
    member_id = next((o for o, _, a in node.watched(b"key", workspace_id)
                      if a.target == Exact(workspace_id) and a.value == pk), None)
    if member_id is None: raise RuntimeError("local signer is not a workspace member")
    fid = node.admit(encode(build(member_id)))
    attest(node, workspace_id, sk, pk, fid, t)
    return fid

# QUERIES — observations over validated state only.
def signed(node, workspace_id, target_id):
    hydrate.demand(node, b"sig", workspace_id)
    return [a.value for _, _, a in node.watched(b"sig", workspace_id)
            if a.target == Exact(target_id)]

# CLI — string boundary over COMMANDS/QUERIES.
CLI = {"signed": lambda n, wid, tid:
           "\n".join(s.hex() for s in signed(n, bytes.fromhex(wid), bytes.fromhex(tid)))}
