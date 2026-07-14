"""facts/auth/invite_accepted.py — the record that THIS node accepted an invite
to a workspace (poc-10 tag 146), the trust anchor for the whole cascade. Local
only: it never syncs, and its `workspace_accepted` Provide is what gates the
workspace fact's validity, so a workspace received over sync stays inert until
its node holds one of these. It also carries the replayable bootstrap context
from the invite link — the secret (keyed by its bootstrap_hash, mixed into the
handshake IKM and whose keygen signs the joiner's request) plus the inviter's
address and endpoint — so it doubles as the bootstrap-reconnect source. Both the
creator (self-accepting its own first invite) and every joiner author one."""
from kernel import (Atom, Exact, H, PROVIDE, Out, encode, fact, frame, now,
                    remote_suppress, ts_atom, ts_of, unframe, _rd)

TAG = b"auth.invite_accepted"
TOKEN = b"tinyp2p-bootstrap-token-v1"
bootstrap_hash = lambda secret: H(frame(TOKEN, secret))

# SHAPE — the canonical atom set; the only place atoms are chosen.
def invite_accepted(workspace_id, invite_id, secret, addr, endpoint_pk, t):
    bh = bootstrap_hash(secret)
    return fact(TAG, ts_atom(t, b"local"),
                remote_suppress,
                Atom(PROVIDE, b"workspace_accepted", b"auth", Exact(workspace_id)),
                Atom(PROVIDE, b"invite_secret", b"local", Exact(bh), secret),
                Atom(PROVIDE, b"invite_ref", b"local", Exact(bh),
                     frame(workspace_id, invite_id, addr, endpoint_pk)))

# EXTRACT — content-pure durability. Acceptance projects no sync marker.
def extract(f): return True

# CHECK — exact shape, including the secret/hash and reference mirrors.
def check(f):
    try:
        accepted = next(a for a in f.atoms if a.name == b"workspace_accepted")
        secret = next(a for a in f.atoms if a.name == b"invite_secret")
        ref = next(a for a in f.atoms if a.name == b"invite_ref")
        workspace_id, invite_id, addr, endpoint_pk = unframe(ref.value)
        return (bool(secret.value) and accepted.target == Exact(workspace_id)
                and secret.target == ref.target == Exact(bootstrap_hash(secret.value))
                and f == invite_accepted(workspace_id, invite_id, secret.value,
                                         addr, endpoint_pk, ts_of(f)))
    except Exception:
        return False

# PROJECT — publish acceptance + the bootstrap context.
def project(f, ctx):
    return Out(provides=tuple(a for a in f.atoms
                            if a.name in (b"workspace_accepted", b"invite_secret", b"invite_ref")))

# COMMANDS — build a fact, admit it, stop; create() and every join() call this.
def accept(node, workspace_id, invite_id, secret, addr, endpoint_pk, t):
    return node.admit(encode(invite_accepted(workspace_id, invite_id, secret, addr, endpoint_pk, t)))

# QUERIES — the (workspace, invite, addr, endpoint) a bootstrap secret unlocks.
def ref(node, secret):                       # -> (workspace_id, invite_id, addr, endpoint_pk) | None
    node.run()
    bh = bootstrap_hash(secret)
    v = next((a.value for _, _, a in node.provided(b"invite_ref", b"local")
              if a.target[1] == bh), None)
    if v is None: return None
    out, i = [], 0
    for _ in range(4): x, i = _rd(v, i); out.append(x)
    return tuple(out)

def workspaces(node):                        # the workspace ids this node has accepted
    node.run()
    return sorted({a.target[1] for _, _, a in node.provided(b"workspace_accepted", b"auth")})

# CLI — no verbs: acceptance is authored by the create/join flow, not by hand.
CLI = {}
