"""facts/connection/close.py — ends a session by naming what it retires. Durable
+ LocalOnly: a closed peer stays closed across restart, and the decision never
syncs. It offers `closed` at each id it kills; request, connection, and
ephemeral_secret all Suppress-need `closed@SELF` (the death key they carry), so
admitting a close flips them to Suppressed — the daemon drops the socket and
stops dialing. `sever` closes the whole cluster (the connection, its request,
and both handshake ephemerals) from a single connection id. Suppression is not
deletion: the atoms remain until `purge` reclaims the secret-bearing rows —
poc-10's close-purge, the forward-secrecy sweep that removes the ephemeral
private keys from disk once their session is dead."""
from kernel import Atom, Exact, OFFER, Out, encode, fact, now, ts_atom

TAG = b"connection.close"
SC = b"conn"

# SHAPE — the canonical atom set; the only place atoms are chosen. One closed
# offer per id this close retires.
def close(targets, t):
    return fact(TAG, ts_atom(t, SC),
                *(Atom(OFFER, b"closed", SC, Exact(i)) for i in targets))

# EXTRACT — content-pure: durable + LocalOnly, exactly like the request it kills.
def extract(f): return True, False

# PROJECT — the only place this family's meaning lives.
def project(f, ctx, sl):
    return Out(offers=tuple(a for a in f.atoms if a.role == b"closed"))

# COMMANDS — build a fact, admit it, stop.
def stop(node, request_id, t):           # close a single request (the CLI verb)
    return node.admit(encode(close((request_id,), t)))

def sever(node, cid, t):                 # close the whole cluster from a connection id
    from facts.connection import connection as conn, request as req
    cf = node.facts.get(cid)
    if cf is None: return None
    env = next((a.value for a in cf.atoms if a.role == b"sconn"), None)
    rid = next((a.target[1] for a in cf.atoms if a.role == b"sconn"), None)
    if env is None or rid is None: return None
    targets = {cid, rid}
    try: resp_eph_pk = conn._uncenv(env)[1]          # responder ephemeral: in the public envelope
    except Exception: resp_eph_pk = None
    ro = next((a.value for o, _, a in node.watched(b"req_open", SC)
               if a.target == Exact(rid)), None)     # initiator ephemeral: in the request plaintext
    init_eph_pk = req.decode_pt(ro)["init_eph_pk"] if ro else None
    for pk in (resp_eph_pk, init_eph_pk):
        eid = _eph_id(node, pk) if pk else None
        if eid: targets.add(eid)
    return node.admit(encode(close(tuple(sorted(targets)), t)))

def purge(node, store, cid):             # forward secrecy: reclaim the severed session's secrets
    gone = []
    for fid in [k for k, f in node.facts.items()
                if f.type_tag == b"connection.ephemeral_secret" and node.memo.get(k) == "Suppressed"]:
        store.delete(fid)
        for m in (node.durable, node.facts, node.memo): m.pop(fid, None)
        gone.append(fid)
    store.commit()
    return gone

def _eph_id(node, eph_pk):
    return next((o for o, _, a in node.watched(b"ephsk", SC) if a.target == Exact(eph_pk)), None)

# QUERIES — none: a close is observed only through what it suppresses.

# CLI — string boundary over COMMANDS. (purge needs the store: daemon-only.)
CLI = {"close": lambda n, rid, t=None: stop(n, bytes.fromhex(rid), int(t or now())).hex(),
       "sever": lambda n, cid, t=None: (sever(n, bytes.fromhex(cid), int(t or now())) or b"").hex()}
