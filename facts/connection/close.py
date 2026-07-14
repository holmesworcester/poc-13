"""facts/connection/close.py — ends a session by naming what it retires. Durable
+ marker-free: a closed peer stays closed across restart, and the decision never
syncs. It provides `closed` at each id it kills; request, connection, and
ephemeral_secret all carry `SuppressIf closed@SELF` (their death key), so
admitting a close flips them to Suppressed — the daemon drops the socket and
stops dialing. `sever` closes the whole cluster (the connection, its request,
and both handshake ephemerals) from a single connection id. Suppression IS
deletion: the kernel purges a suppressed fact whole — memory, and its rows on
disk — at the verdict itself, so the ephemeral private keys are gone the moment
the session dies (poc-10's close-purge, now a kernel consequence, not a sweep).
What persists is the close fact: the relationship that keeps the peer dead."""
from kernel import Atom, Exact, PROVIDE, Out, encode, fact, now, remote_suppress, ts_atom, ts_of

TAG = b"connection.close"
SC = b"conn"

# SHAPE — the canonical atom set; the only place atoms are chosen. One closed
# Provide per id this close retires.
def close(targets, t):
    return fact(TAG, ts_atom(t, SC),
                remote_suppress,
                *(Atom(PROVIDE, b"closed", SC, Exact(i)) for i in targets))

# EXTRACT — content-pure durability. A local close projects no sync marker.
def extract(f): return True

# CHECK — exact shape; remote authorship is a graph suppression.
def check(f):
    try:
        targets = [a.target[0] for a in f.atoms if a.name == b"closed"
                   and a.target[0] == a.target[1]]
        return bool(targets) and f == close(targets, ts_of(f))
    except Exception:
        return False

# PROJECT — the only place this family's meaning lives.
def project(f, ctx):
    return Out(provides=tuple(a for a in f.atoms if a.name == b"closed"))

# COMMANDS — build a fact, admit it, stop.
def stop(node, request_id, t):           # close a single request (the CLI verb)
    return node.admit(encode(close((request_id,), t)))

def sever(node, cid, t):                 # close the whole cluster from a connection id
    from facts.connection import connection as conn, request as req
    cf = node.facts.get(cid)
    if cf is None: return None
    env = next((a.value for a in cf.atoms if a.name == b"sconn"), None)
    rid = next((a.target[1] for a in cf.atoms if a.name == b"sconn"), None)
    if env is None or rid is None: return None
    targets = {cid, rid}
    try: resp_eph_pk = conn._uncenv(env)[1]          # responder ephemeral: in the public envelope
    except Exception: resp_eph_pk = None
    ro = next((a.value for o, _, a in node.provided(b"req_open", SC)
               if a.target == Exact(rid)), None)     # initiator ephemeral: in the request plaintext
    init_eph_pk = req.decode_pt(ro)["init_eph_pk"] if ro else None
    for pk in (resp_eph_pk, init_eph_pk):
        eid = _eph_id(node, pk) if pk else None
        if eid: targets.add(eid)
    return node.admit(encode(close(tuple(sorted(targets)), t)))

def _eph_id(node, eph_pk):
    return next((o for o, _, a in node.provided(b"ephsk", SC) if a.target == Exact(eph_pk)), None)

# QUERIES — none: a close is observed only through what it suppresses.

# CLI — string boundary over COMMANDS.
CLI = {"close": lambda n, rid, t=None: stop(n, bytes.fromhex(rid), int(t or now())).hex(),
       "sever": lambda n, cid, t=None: (sever(n, bytes.fromhex(cid), int(t or now())) or b"").hex()}
