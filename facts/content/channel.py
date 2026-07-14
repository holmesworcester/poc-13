"""facts/content/channel.py — a named, member-signed workspace channel.
The fact id is the channel id: names are display data, never routing keys.
Messages Require the validated `channel` offer at this id, so an arbitrary
label cannot create a feed and a message arriving before its channel parks
until the channel's workspace-backed identity arrives. Channels are durable,
shareable structural state and are pulled whole by channel queries. Any
workspace member may create one; its signature travels with the channel."""
from kernel import (Atom, Exact, NEED, OFFER, Out, REQUIRE, SELF, encode,
                    fact, now, ts_atom, ts_of)
from facts.auth import signature
from facts.store import hydrate

TAG = b"content.channel"
MAX_NAME_BYTES = 64

def _valid_name(name):
    if not isinstance(name, bytes) or not name or len(name) > MAX_NAME_BYTES: return False
    try: name.decode("utf-8")
    except UnicodeDecodeError: return False
    return True

# SHAPE — the canonical atom set; the only place atoms are chosen.
def channel(workspace_id, name, t):
    return fact(TAG, ts_atom(t, workspace_id),
                Atom(NEED, b"workspace", b"auth", Exact(workspace_id), effect=REQUIRE),
                Atom(NEED, b"pk", workspace_id, SELF, effect=REQUIRE),
                Atom(NEED, b"key", workspace_id, Exact(workspace_id), effect=REQUIRE),
                Atom(OFFER, b"channel", workspace_id, SELF, name))

# EXTRACT — content-pure: (durable, shareable). Channels are replicated
# structural state, not local aliases.
def extract(f): return True, True
from facts.sync.index import settle      # opt in: these facts replicate (one line is the whole choice)

# PROJECT — accept exactly SHAPE and a useful bounded name.
def project(f, ctx):
    try:
        row = next(a for a in f.atoms if a.role == b"channel")
        if not _valid_name(row.value): return Out("Invalid")
        if f != channel(row.scope, row.value, ts_of(f)): return Out("Invalid")
    except Exception:
        return Out("Invalid")
    signer, members = signature.blessed(ctx)
    if not signer & set(members.values()): return Out("Invalid")
    return Out(offers=(row,))

# COMMANDS — names are unique at the local authoring boundary. Concurrent
# same-name channels remain distinct facts and resolve as ambiguous by id/name.
def create(node, workspace_id, name, t):
    if not _valid_name(name):
        raise RuntimeError(f"channel name must be 1..{MAX_NAME_BYTES} bytes of UTF-8")
    matches = [(cid, n) for cid, n in index(node, workspace_id) if n == name]
    if matches: raise RuntimeError(f"channel already exists: {name.decode(errors='replace')}")
    return signature.signed_admit(
        node, workspace_id, lambda _mid: channel(workspace_id, name, t), t)

# QUERIES — the sidebar is structural state, so asking for any channel first
# faults the complete validated channel set for the workspace resident.
def index(node, workspace_id):
    hydrate.demand(node, b"channel", workspace_id)
    return [(o, a.value) for o, t, a in sorted(node.watched(b"channel", workspace_id),
                                               key=lambda r: (r[1], r[0]))]

def resolve(node, workspace_id, ref):
    """Resolve a CLI-style name or 64-hex fact id to a channel id.

    Explicit ids may name a channel that has not arrived yet, preserving the
    protocol's order-independent park-then-wake behavior. Names resolve only
    through validated channel facts and fail closed when concurrent creation
    made the display name ambiguous.
    """
    if isinstance(ref, bytes): ref = ref.decode(errors="strict")
    matches = [cid for cid, name in index(node, workspace_id)
               if name.decode() == ref]
    if len(matches) > 1: raise RuntimeError(f"ambiguous channel name; use an id: {ref}")
    if matches: return matches[0]
    if len(ref) == 64:
        try: return bytes.fromhex(ref)
        except ValueError: pass
    raise RuntimeError(f"unknown channel: {ref}")

# CLI — string boundary over COMMANDS/QUERIES.
CLI = {"create": lambda n, wid, name, t=None:
           create(n, bytes.fromhex(wid), name.encode(), int(t or now())).hex(),
       "list": lambda n, wid:
           "\n".join(f"{cid.hex()} {name.decode()}"
                     for cid, name in index(n, bytes.fromhex(wid))),
       "id": lambda n, wid, ref: resolve(n, bytes.fromhex(wid), ref).hex()}
