"""facts/auth/invite_accepted.py — the record that THIS node accepted an invite
to a workspace (poc-10 tag 146), the trust anchor for the whole cascade. Local
only: it never syncs, and its `workspace_accepted` offer is what gates the
workspace fact's validity, so a workspace received over sync stays inert until
its node holds one of these. It also carries the replayable bootstrap context
from the invite link — the secret (keyed by its bootstrap_hash, mixed into the
handshake IKM and whose keygen signs the joiner's request) plus the inviter's
address and endpoint — so it doubles as the bootstrap-reconnect source. Both the
creator (self-accepting its own first invite) and every joiner author one."""
from kernel import Atom, Exact, H, OFFER, Out, encode, fact, frame, now, ts_atom, _rd

TAG = b"auth.invite_accepted"
TOKEN = b"tinyp2p-bootstrap-token-v1"
bootstrap_hash = lambda secret: H(frame(TOKEN, secret))

# SHAPE — the canonical atom set; the only place atoms are chosen.
def invite_accepted(workspace_id, invite_id, secret, addr, endpoint_pk, t):
    bh = bootstrap_hash(secret)
    return fact(TAG, ts_atom(t, b"local"),
                Atom(OFFER, b"workspace_accepted", b"auth", Exact(workspace_id)),
                Atom(OFFER, b"invite_secret", b"local", Exact(bh), secret),
                Atom(OFFER, b"invite_ref", b"local", Exact(bh),
                     frame(workspace_id, invite_id, addr, endpoint_pk)))

# EXTRACT — content-pure: (durable, LocalOnly). Acceptance is a local decision.
def extract(f): return True, False

# CHECK — the bootstrap_hash it keys by must be the hash of the secret it carries.
def check(f):
    v = {a.role: (a.target, a.value) for a in f.atoms}
    (tgt, secret) = v.get(b"invite_secret", (None, None))
    return bool(secret) and tgt == Exact(bootstrap_hash(secret))

# PROJECT — publish acceptance + the bootstrap context.
def project(f, ctx):
    return Out(offers=tuple(a for a in f.atoms
                            if a.role in (b"workspace_accepted", b"invite_secret", b"invite_ref")))

# COMMANDS — build a fact, admit it, stop; create() and every join() call this.
def accept(node, workspace_id, invite_id, secret, addr, endpoint_pk, t):
    return node.admit(encode(invite_accepted(workspace_id, invite_id, secret, addr, endpoint_pk, t)))

# QUERIES — the (workspace, invite, addr, endpoint) a bootstrap secret unlocks.
def ref(node, secret):                       # -> (workspace_id, invite_id, addr, endpoint_pk) | None
    node.run()
    bh = bootstrap_hash(secret)
    v = next((a.value for _, _, a in node.watched(b"invite_ref", b"local")
              if a.target[1] == bh), None)
    if v is None: return None
    out, i = [], 0
    for _ in range(4): x, i = _rd(v, i); out.append(x)
    return tuple(out)

def workspaces(node):                        # the workspace ids this node has accepted
    node.run()
    return sorted({a.target[1] for _, _, a in node.watched(b"workspace_accepted", b"auth")})

# CLI — no verbs: acceptance is authored by the create/join flow, not by hand.
CLI = {}
