"""facts/connection/connection.py — the sealed handshake result (poc-10 tag 49);
its fact id is the connection id and its canonical bytes ARE the wire message, so
the responder authors it and the initiator admits the identical bytes. The sealed
envelope hides the connection plaintext, which carries both static endpoints, the
request id, the return addresses, the responder ephemeral, and — the payload of
the whole exchange — the handshake_hash and the per-session connection_secret.

The projector never trusts the carried secret: it opens the envelope (the
initiator with its own static endpoint secret, the responder with its ephemeral),
recomputes the X25519 handshake material from the request transcript it Requires
as `req_open`, and refuses (Invalid) unless the recomputed handshake_hash and
connection_secret match the carried ones. On success it publishes the peer
identity/address as `connection`, the session key as a validated in-memory
`conn_secret` offer (never synced, rebuilt by replay), and `answered` to retire
the request's resend loop. respond() is the responder's authoring command: a
deterministic ephemeral and seal nonce derived from the static secret over the
request id make re-performance byte-identical, so a replayed or duplicated
request produces one and the same connection."""
from kernel import (Atom, Exact, FULL, H, NEED, OFFER, Out, REQUIRE, SELF,
                    SUPPRESS, WATCH, by, encode, fact, frame, ts_of, unframe)
from crypto import dh, hkdf_sha256, keyed_hash, open_x25519, seal_x25519, x25519_pk
from facts.auth import endpoint, invite_accepted as ish
from facts.connection import ephemeral_secret as eph
from facts.connection import request as req
from facts.outbox.send import send

TAG = b"connection.connection"
SC = b"conn"
SEAL_VERSION = 1
CONNECTION_PURPOSE = b"tinyp2p-sealed-connection-v2"
BOOTSTRAP_PURPOSE = b"tinyp2p-connection-bootstrap-handshake-v2"
MEMBERSHIP_PURPOSE = b"tinyp2p-connection-membership-handshake-v2"
SECRET_PURPOSE = b"tinyp2p-connection-secret-v2"
TRANSCRIPT_LABEL = b"tinyp2p-connection-handshake-transcript-v2"
RESP_EPH_LABEL = b"tinyp2p:create-connection:responder-ephemeral:v1"
NONCE_LABEL = b"tinyp2p:create-connection:seal-nonce:v1"

# --- connection plaintext codec + handshake math --------------------------------
_C = ("from_ep", "to_ep", "request_id", "resp_addr", "init_addr", "init_eph_id",
      "resp_eph_id", "resp_eph_pk", "handshake_hash", "connection_secret")

def _encode_cpt(**k): return frame(*(k[n] for n in _C))
def _decode_cpt(pt):
    parts = unframe(pt)
    if len(parts) != len(_C): raise ValueError("bad connection plaintext")
    return dict(zip(_C, parts))

_cenv = lambda ct, eph_pk, to, rid, nc: frame(bytes([SEAL_VERSION]), eph_pk, to, rid, nc, ct)
def _uncenv(env):
    ver, ep, to, rid, nc, ct = unframe(env); return ver[0], ep, to, rid, nc, ct
_cheader = lambda eph_pk, to, rid, nc: frame(bytes([SEAL_VERSION]), eph_pk, to, rid, nc)

def _transcript(req_pt, resp_eph_pk, resp_addr, init_addr):
    return frame(TRANSCRIPT_LABEL, req_pt, resp_eph_pk, resp_addr, init_addr)

def _material(F, req_pt, secret, ee, es, resp_eph_pk, resp_addr, init_addr):
    tr = _transcript(req_pt, resp_eph_pk, resp_addr, init_addr)
    if F["mode"] == req.BOOTSTRAP:
        ikm, purpose = secret + F["bootstrap_hash"] + ee + es, BOOTSTRAP_PURPOSE
    else:
        ikm, purpose = ee + es, MEMBERSHIP_PURPOSE
    rk = hkdf_sha256(ikm, purpose, tr)
    hh = H(tr)
    return hh, hkdf_sha256(rk, SECRET_PURPOSE, hh)

# SHAPE — deterministic given (env, request_id): both sides build identical bytes.
def connection(env, request_id):
    return fact(TAG,
                Atom(OFFER, b"sconn", SC, Exact(request_id), env),
                Atom(NEED, b"req_open", SC, Exact(request_id), effect=REQUIRE),
                Atom(NEED, b"esk", b"local", FULL, effect=WATCH),
                Atom(NEED, b"ephsk", SC, FULL, effect=WATCH),
                Atom(NEED, b"invite_secret", b"local", FULL, effect=WATCH),
                Atom(NEED, b"closed", SC, SELF, effect=SUPPRESS))

# EXTRACT — content-pure: volatile + LocalOnly. A session dies with the process.
def extract(f): return False, False

# PROJECT — open, recompute, verify, publish. Pure over ctx; rebuilt by replay.
def project(f, ctx):
    env = next(a.value for a in f.atoms if a.role == b"sconn")
    ver, resp_eph_pk, to_ep_conn, request_id, nonce, ct = _uncenv(env)
    hdr = _cheader(resp_eph_pk, to_ep_conn, request_id, nonce)
    esks = {r[2].target[1]: r[2].value for r in by(ctx, b"esk")}
    ephs = {r[2].target[1]: r[2].value for r in by(ctx, b"ephsk")}
    pt = None
    if to_ep_conn in esks:               # initiator: own static + responder ephemeral
        pt = open_x25519(esks[to_ep_conn], resp_eph_pk, CONNECTION_PURPOSE, hdr, nonce, ct)
    if pt is None and resp_eph_pk in ephs:   # responder: own ephemeral + initiator static
        pt = open_x25519(ephs[resp_eph_pk], to_ep_conn, CONNECTION_PURPOSE, hdr, nonce, ct)
    if pt is None: return Out("Parked")  # opening key not resident yet
    C = _decode_cpt(pt)
    req_pt = next((r[2].value for r in by(ctx, b"req_open")), None)
    if req_pt is None: return Out("Parked")
    F = req.decode_pt(req_pt)
    secret = {ish.bootstrap_hash(r[2].value): r[2].value
              for r in by(ctx, b"invite_secret")}.get(F["bootstrap_hash"], b"")
    if F["mode"] == req.BOOTSTRAP and not secret: return Out("Parked")
    if F["to_ep"] in esks and resp_eph_pk in ephs:        # responder recompute
        ee, es = dh(ephs[resp_eph_pk], F["init_eph_pk"]), dh(esks[F["to_ep"]], F["init_eph_pk"])
        peer_ep, peer_addr = F["from_ep"], C["init_addr"]
    elif F["init_eph_pk"] in ephs:                        # initiator recompute
        ee, es = dh(ephs[F["init_eph_pk"]], resp_eph_pk), dh(ephs[F["init_eph_pk"]], F["to_ep"])
        peer_ep, peer_addr = F["to_ep"], C["resp_addr"]
    else: return Out("Parked")
    if ee is None or es is None: return Out("Invalid")
    hh, cs = _material(F, req_pt, secret, ee, es, resp_eph_pk, C["resp_addr"], C["init_addr"])
    if hh != C["handshake_hash"] or cs != C["connection_secret"]: return Out("Invalid")
    return Out(offers=(Atom(OFFER, b"connection", SC, SELF, frame(peer_ep, peer_addr)),
                       Atom(OFFER, b"conn_secret", SC, SELF, cs),
                       Atom(OFFER, b"answered", SC, Exact(request_id))))

# COMMANDS — the responder authors the connection (poc-10 create_connection).
def respond(node, request_id, origin, t):
    ro = next((r[2].value for r in _valid(node, b"req_open", Exact(request_id))), None)
    if ro is None: return None
    if _valid(node, b"answered", Exact(request_id)):     # already answered: re-ship the response (re-dial)
        cid = _for_request(node, request_id)
        if cid: node.admit(encode(send(origin, encode(node.facts[cid]), t)))
        return cid
    F = req.decode_pt(ro)
    esk, epk = endpoint.current(node)
    if epk != F["to_ep"]: return None    # not addressed to this endpoint
    resp_eph_sk = keyed_hash(esk, RESP_EPH_LABEL, request_id)   # deterministic: replay-identical
    resp_eph_pk = x25519_pk(resp_eph_sk)
    reid = eph.mint(node, resp_eph_sk, resp_eph_pk, ts_of(node.facts[request_id])); node.run()
    secret = _invite_secret(node, F["bootstrap_hash"]) if F["mode"] == req.BOOTSTRAP else b""
    if F["mode"] == req.BOOTSTRAP and not secret: return None
    ee, es = dh(resp_eph_sk, F["init_eph_pk"]), dh(esk, F["init_eph_pk"])
    resp_addr, init_addr = F["dialed_addr"], (F["init_addr"] or origin)
    hh, cs = _material(F, ro, secret, ee, es, resp_eph_pk, resp_addr, init_addr)
    cpt = _encode_cpt(from_ep=F["to_ep"], to_ep=F["from_ep"], request_id=request_id,
                      resp_addr=resp_addr, init_addr=init_addr, init_eph_id=F["init_eph_id"],
                      resp_eph_id=reid, resp_eph_pk=resp_eph_pk, handshake_hash=hh,
                      connection_secret=cs)
    nonce = keyed_hash(esk, NONCE_LABEL, request_id + H(cpt))[:24]
    hdr = _cheader(resp_eph_pk, F["from_ep"], request_id, nonce)
    ct = seal_x25519(resp_eph_sk, F["from_ep"], CONNECTION_PURPOSE, hdr, nonce, cpt)
    cbytes = encode(connection(_cenv(ct, resp_eph_pk, F["from_ep"], request_id, nonce), request_id))
    cid = node.admit(cbytes)
    if cid: node.admit(encode(send(init_addr, cbytes, t)))   # ship the response to the initiator via the pump
    return cid

# QUERIES — observations over validated state only.
def secret(node, cid):                   # the session key for an established connection
    return next((r[2].value for r in _valid(node, b"conn_secret", Exact(cid))), None)

def _for_request(node, request_id):
    return next((o for o, _, a in node.watched(b"answered", SC)
                 if a.target[1] == request_id), None)

def peers(node):                         # (peer endpoint, addr, connection id, who) per live session
    binds = _bindings(node)              # endpoint -> member name | b"auth", from synced device facts
    out = []
    for o, _, a in node.watched(b"connection", SC):
        ep, addr = unframe(a.value)
        out.append((ep, addr, o, binds.get(ep, b"anon")))
    return sorted(out, key=lambda r: r[:3])

def _bindings(node):                     # endpoint pk -> the member it belongs to (auth), via device facts
    out = {}
    for _, _, a in node.watched(b"endpoint_shared", b"auth"):
        ep, spk, wid = unframe(a.value)
        uid = next((o for o, _, k in node.watched(b"key", wid) if k.value == spk), None)
        name = next((m.value for o, _, m in node.watched(b"member", wid) if o == uid), None)
        out[ep] = name or b"auth"
    return out

def route(node, cid):                    # (peer addr, session secret) for a live connection | None
    for o, _, a in node.watched(b"connection", SC):
        if o == cid:
            _ep, addr = unframe(a.value); s = secret(node, cid)
            return (addr, s) if s else None
    return None

def _valid(node, role, target):          # clean rows matching an exact/target need
    return [r for r in node.clean.get((role, SC), ()) if r[2].target == target]

def _invite_secret(node, bh):
    return next((a.value for _, _, a in node.watched(b"invite_secret", b"local")
                 if ish.bootstrap_hash(a.value) == bh), b"")

# CLI — string boundary over QUERIES.
CLI = {"peers": lambda n: "\n".join("%s %s %s %s" % (a.decode(), ep.hex(), c.hex(), w.decode())
                                    for ep, a, c, w in peers(n))}
