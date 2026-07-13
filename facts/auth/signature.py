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
dep it ships automatically under dep-aware sync."""
from kernel import Atom, Exact, OFFER, Out, encode, fact, now, ts_atom
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

# CHECK — optional self-verification at the admission gate: a pure function
# of the fact's own bytes, run once and never on replay.
def check(f):                            # verify over the sig offer's own target —
    pk = sig = tgt = None                # exactly the id a Require will match on
    for a in f.atoms:
        if a.role == b"pk": pk = a.value
        elif a.role == b"sig" and a.target and a.target[0] == a.target[1]: sig, tgt = a.value, a.target[1]
    return bool(pk and sig and tgt and verify(pk, tgt, sig))

# PROJECT — the only place this family's meaning lives.
def project(f, ctx):                 # publish both the signer pk and the sig:
    return Out(offers=tuple(a for a in f.atoms if a.role in (b"pk", b"sig")))
# a fact Requires b"pk" at its own id to pull WHO signed it into ctx, then a
# projector value-compares that pk against the pk its authority chain blessed.

# COMMANDS — build a fact, admit it, stop.
def attest(node, workspace_id, sk, pk, target_id, t):
    return node.admit(encode(signature(workspace_id, pk, target_id, sign(sk, target_id), t)))

# QUERIES — observations over validated state only.
def signed(node, workspace_id, target_id):
    hydrate.demand(node, b"sig", workspace_id)
    return [a.value for _, _, a in node.watched(b"sig", workspace_id)
            if a.target == Exact(target_id)]

# CLI — string boundary over COMMANDS/QUERIES.
CLI = {"signed": lambda n, wid, tid:
           "\n".join(s.hex() for s in signed(n, bytes.fromhex(wid), bytes.fromhex(tid)))}
