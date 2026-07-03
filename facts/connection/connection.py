"""facts/connection/connection.py — a live session as a fact, authored by the
DAEMON (host out) when a peer's hello verifies. Volatile + LocalOnly: sessions
die with the process and never sync. It records the peer's advertised address and
the identity public key its hello proved possession of. Whether that key is a
workspace-authorized member/device key is a query-side value-compare against the
keys the auth chain blessed (the `auth` column of peers) — never a hard Require,
so two fresh nodes still talk (trust on first use, matching Authority's stance)."""
from kernel import Atom, OFFER, Out, SELF, encode, fact, now, ts_atom

TAG = b"connection.connection"
SC = b"conn"

# SHAPE — the canonical atom set; the only place atoms are chosen.
def connection(peer_pk, addr, t):
    return fact(TAG, ts_atom(t, SC),
                Atom(OFFER, b"session", SC, SELF, addr),
                Atom(OFFER, b"peerkey", SC, SELF, peer_pk))

# EXTRACT — content-pure: volatile + LocalOnly. A session vanishes on restart.
def extract(f): return False, False

# PROJECT — the only place this family's meaning lives.
def project(f, ctx, sl):
    return Out(offers=tuple(a for a in f.atoms if a.role in (b"session", b"peerkey")))

# COMMANDS — the daemon records one per verified hello. Build a fact, admit, stop.
def observe(node, peer_pk, addr, t):
    return node.admit(encode(connection(peer_pk, addr, t)))

# QUERIES — observations over validated state only.
def peers(node):                         # (addr, peer key, authorized?) per live session
    addr = {o: a.value for o, t, a in node.watched(b"session", SC)}
    key = {o: a.value for o, t, a in node.watched(b"peerkey", SC)}
    blessed = {r[2].value for (role, sc), rows in node.clean.items()   # member keys, any workspace
               if role == b"key" for r in rows}
    return sorted((addr[o], key[o], key[o] in blessed) for o in addr if o in key)

# CLI — string boundary over COMMANDS/QUERIES.
CLI = {"peers": lambda n: "\n".join(f"{a.decode()} {k.hex()} {'auth' if ok else 'anon'}"
                                    for a, k, ok in peers(n))}
