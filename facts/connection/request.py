"""facts/connection/request.py — the sealed first-contact fact (poc-10 tag 48),
one shape for both bootstrap and membership handshakes. Its sealed bytes ARE the
request id. The public envelope carries the seal version, the initiator's
ephemeral X25519 public key, the responder endpoint it is sealed to, and the
nonce; the ciphertext hides the full field set (mode, both static endpoints, a
transcript nonce, dial/return addresses, the invite or endpoint-shared proof,
the branch signature, and the initiator ephemeral id/key).

Decryption happens in PROJECT, not at the gate: CHECK is pure of context and can
only see the envelope, so it validates structure; the opening key and the
authority proof arrive as validated offers the fact Watches (the responder opens
with its static endpoint secret, the initiator with its own ephemeral — the
X25519 box is symmetric). A failed open or a bad branch signature is Invalid; a
missing key or absent proof is Parked until it lands. On success the projector
publishes the decrypted plaintext as `req_open` (the connection fact's transcript
input), re-offers the wire bytes as a `send` while the initiator is unanswered
(the resend loop the pump dials), and — on the addressee, once a receipt proves
the request arrived — a host-watched `respond` naming the reply route."""
from kernel import (Atom, Exact, NEED, OFFER, Out, Range, SELF, SUPPRESS, WATCH,
                    by, encode, fact, frame, now, ts_atom, _rd)
from crypto import open_x25519
from ed25519 import keygen, verify
from facts.auth import endpoint, invite_secret as ish
from facts.store import hydrate

TAG = b"connection.request"
SC = b"conn"
SEAL_VERSION = 1
REQUEST_PURPOSE = b"poc13-sealed-connection-request-v2"
BOOTSTRAP, MEMBERSHIP = 1, 2
LOCAL_FULL = Range(b"", b"\xff" * 64)    # a range Watch that covers any Exact key
AUTH_FULL = Range(b"", b"\xff" * 64)

# --- plaintext codec (shared with connection.py) --------------------------------
_F = ("mode", "from_ep", "to_ep", "nonce", "dialed_addr", "init_addr", "invite_id",
      "bootstrap_hash", "esid", "sig", "init_eph_id", "init_eph_pk")

def encode_pt(**k):
    return frame(bytes([k["mode"]]), k["from_ep"], k["to_ep"], k["nonce"],
                 k["dialed_addr"], k["init_addr"], k["invite_id"], k["bootstrap_hash"],
                 k["esid"], k["sig"], k["init_eph_id"], k["init_eph_pk"])

def decode_pt(pt):
    out, i = {}, 0
    for name in _F:
        v, i = _rd(pt, i); out[name] = v
    out["mode"] = out["mode"][0]
    return out

def sig_bytes(F):                        # the plaintext the branch signature covers
    return encode_pt(**{**F, "sig": b""})

_env = lambda ct, eph, to, nc: frame(bytes([SEAL_VERSION]), eph, to, nc, ct)
def _unenv(env):
    ver, i = _rd(env, 0); eph, i = _rd(env, i); to, i = _rd(env, i)
    nc, i = _rd(env, i); ct, i = _rd(env, i)
    return ver[0], eph, to, nc, ct
_header = lambda eph, to, nc: frame(bytes([SEAL_VERSION]), eph, to, nc)

# SHAPE — the canonical atom set; the only place atoms are chosen.
def request(env, to_ep, init_eph_pk, t):
    return fact(TAG, ts_atom(t, SC),
                Atom(OFFER, b"sreq", SC, SELF, env),
                Atom(NEED, b"esk", b"local", Exact(to_ep), effect=WATCH),        # responder opens
                Atom(NEED, b"ephsk", SC, Exact(init_eph_pk), effect=WATCH),      # initiator opens
                Atom(NEED, b"invite_secret", b"local", LOCAL_FULL, effect=WATCH),
                Atom(NEED, b"endpoint_shared", b"auth", AUTH_FULL, effect=WATCH),
                Atom(NEED, b"endpoint", b"local", LOCAL_FULL, effect=WATCH),     # am I addressee?
                Atom(NEED, b"receipt", SC, SELF, effect=WATCH),                  # arrival + origin
                Atom(NEED, b"answered", SC, SELF, effect=WATCH),                 # retire resend
                Atom(NEED, b"closed", SC, SELF, effect=SUPPRESS))

# EXTRACT — content-pure: (durable, LocalOnly). First contact is never synced.
def extract(f): return True, False

# CHECK — structural only: the envelope parses to the right widths (no context).
def check(f):
    env = next((a.value for a in f.atoms if a.role == b"sreq"), None)
    if env is None: return False
    try: ver, eph, to, nc, ct = _unenv(env)
    except Exception: return False
    return ver == SEAL_VERSION and len(eph) == 32 and len(to) == 32 and len(nc) == 24 and len(ct) >= 16

# PROJECT — decrypt, verify authority, then publish. Pure given ctx; replay-safe.
def project(f, ctx, sl):
    env = next(a.value for a in f.atoms if a.role == b"sreq")
    ver, init_eph_pk, to_ep, nonce, ct = _unenv(env)
    hdr = _header(init_eph_pk, to_ep, nonce)
    pt = None
    for r in by(ctx, b"esk"):            # responder: static secret + initiator ephemeral pub
        pt = open_x25519(r[2].value, init_eph_pk, REQUEST_PURPOSE, hdr, nonce, ct)
        if pt: break
    for r in (by(ctx, b"ephsk") if pt is None else ()):   # initiator: own ephemeral + responder pub
        pt = open_x25519(r[2].value, to_ep, REQUEST_PURPOSE, hdr, nonce, ct)
        if pt: break
    if pt is None: return Out("Parked")  # opening key not resident yet
    try: F = decode_pt(pt)
    except Exception: return Out("Invalid")
    if F["mode"] == BOOTSTRAP:
        secrets = {ish.bootstrap_hash(r[2].value): r[2].value for r in by(ctx, b"invite_secret")}
        s = secrets.get(F["bootstrap_hash"])
        if s is None: return Out("Parked") # invite secret not present yet
        if not verify(keygen(s)[1], sig_bytes(F), F["sig"]): return Out("Invalid")
    elif F["mode"] == MEMBERSHIP:
        share = {r[2].target[1]: r[2].value for r in by(ctx, b"endpoint_shared")}.get(F["esid"])
        if share is None: return Out("Parked")
        ep, spk, _wid = (lambda v: (_rd(v, 0)[0],) + _split2(_rd(v, 0)[1]))(share)
        if ep != F["from_ep"] or not verify(spk, sig_bytes(F), F["sig"]): return Out("Invalid")
    else: return Out("Invalid")
    offers = [Atom(OFFER, b"req_open", SC, SELF, pt)]
    mine = {r[2].target[1] for r in by(ctx, b"endpoint")}
    if to_ep in mine:                    # responder: reply once the request has arrived
        rc = by(ctx, b"receipt")
        if rc:
            _p, origin, _h = _split3(rc[0][2].value)
            offers.append(Atom(OFFER, b"respond", SC, SELF, origin))
    elif not by(ctx, b"answered") and F["dialed_addr"]:   # initiator: resend until answered
        offers.append(Atom(OFFER, b"send", b"outbox", Exact(F["dialed_addr"]), env))
    return Out(offers=tuple(offers))

def _split2(v): a, i = _rd(v, 0); b, _ = _rd(v, i); return a, b
def _split3(v): a, i = _rd(v, 0); b, i = _rd(v, i); c, _ = _rd(v, i); return a, b, c

# COMMANDS — author the sealed first-contact fact (+ its ephemeral). Bootstrap and
# membership differ only in which proof/signature fills the branch fields.
def _seal(node, mode, from_ep, to_ep, dialed_addr, init_addr, branch, sk, t):
    from crypto import x25519_keygen, seal_x25519
    from facts.connection import ephemeral_secret as eph
    import os
    esk, epk = x25519_keygen()
    eid = eph.mint(node, esk, epk, t); node.run()
    nonce = os.urandom(24)
    base = dict(mode=mode, from_ep=from_ep, to_ep=to_ep, nonce=os.urandom(32),
                dialed_addr=dialed_addr, init_addr=init_addr, invite_id=b"",
                bootstrap_hash=b"", esid=b"", sig=b"", init_eph_id=eid, init_eph_pk=epk)
    base.update(branch)
    base["sig"] = sk(sig_bytes(base))    # sign the plaintext with its branch empty
    pt = encode_pt(**base)
    ct = seal_x25519(esk, to_ep, REQUEST_PURPOSE, _header(epk, to_ep, nonce), nonce, pt)
    return node.admit(encode(request(_env(ct, epk, to_ep, nonce), to_ep, epk, t)))

def bootstrap(node, secret, invite_id, to_ep, dialed_addr, init_addr, t):
    ish.keep(node, secret, invite_id, dialed_addr, to_ep, t); node.run()   # joiner keeps the secret too
    esk, epk = endpoint.current(node)
    isk = keygen(secret)[0]              # the invite key signs the request
    return _seal(node, BOOTSTRAP, epk, to_ep, dialed_addr, init_addr,
                 dict(invite_id=invite_id, bootstrap_hash=ish.bootstrap_hash(secret)),
                 lambda m: __import__("ed25519").sign(isk, m), t)

# QUERIES — the requests still awaiting a connection (the resend set).
def unanswered(node):
    hydrate.demand(node, b"send", b"outbox"); node.run()
    return [o for o, _, a in node.watched(b"send", b"outbox")]

# CLI — no verbs: requests are authored by the connect flow, not by hand.
CLI = {}
