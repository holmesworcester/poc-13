"""facts/auth/invite_secret.py — the bootstrap secret behind an invite, held
locally by BOTH sides of a bootstrap handshake (poc-10 folds tags 129 creator
+ 146 acceptor into this one). The inviter retains it when it mints the invite;
the joiner admits it from the link. Durable + LocalOnly: it is the shared secret
mixed into the bootstrap handshake IKM, and the Ed25519 key `keygen(secret)`
signs the joiner's request — it must never sync. It offers the secret keyed by
its bootstrap_hash (the rendezvous the sealed request Watches to authorize the
bootstrap branch) plus the peer address+endpoint the joiner needs to redial."""
from kernel import Atom, Exact, H, OFFER, Out, encode, fact, frame, now, ts_atom

TAG = b"auth.invite_secret"
TOKEN = b"poc13-bootstrap-token-v1"
bootstrap_hash = lambda secret: H(frame(TOKEN, secret))

# SHAPE — the canonical atom set; the only place atoms are chosen.
def invite_secret(secret, invite_id, addr, endpoint_pk, t):
    bh = bootstrap_hash(secret)
    return fact(TAG, ts_atom(t, b"local"),
                Atom(OFFER, b"invite_secret", b"local", Exact(bh), secret),
                Atom(OFFER, b"invite_ref", b"local", Exact(bh),
                     frame(invite_id, addr, endpoint_pk)))

# EXTRACT — content-pure: (durable, LocalOnly). The bootstrap secret never syncs.
def extract(f): return True, False

# CHECK — the hash it keys by must be the hash of the secret it carries.
def check(f):
    v = {a.role: (a.target, a.value) for a in f.atoms}
    (tgt, secret) = v.get(b"invite_secret", (None, None))
    return bool(secret) and tgt[0] == 0 and tgt[1] == bootstrap_hash(secret)

# PROJECT — the only place this family's meaning lives.
def project(f, ctx, sl):
    return Out(offers=tuple(a for a in f.atoms if a.role in (b"invite_secret", b"invite_ref")))

# COMMANDS — build a fact, admit it, stop; both invite() and join() call this.
def keep(node, secret, invite_id, addr, endpoint_pk, t):
    return node.admit(encode(invite_secret(secret, invite_id, addr, endpoint_pk, t)))

# QUERIES — the (invite_id, addr, endpoint) the joiner dials for a bootstrap.
def ref(node, secret):                       # -> (invite_id, addr, endpoint_pk) | None
    node.run()
    bh = bootstrap_hash(secret)
    v = next((a.value for _, _, a in node.watched(b"invite_ref", b"local")
              if a.target[1] == bh), None)
    if v is None: return None
    from kernel import _rd
    a, i = _rd(v, 0); b, i = _rd(v, i); c, i = _rd(v, i)
    return a, b, c

# CLI — no verbs: invite_secret is authored by the invite/join commands.
CLI = {}
