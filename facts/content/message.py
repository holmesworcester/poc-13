"""facts/content/message.py — a member-signed message in a real channel.
The channel id is the id of a validated `content.channel` fact, not a
caller-chosen label; this fact Requires that channel and therefore inherits
its workspace dependency. Its own signature and workspace member keys bind
the posted author id to the member whose blessed key signed the fact. It also
carries its own death key (`SuppressIf dead@SELF`).

Every message carries a per-message `file_secret`: the symmetric key its
attachments are encrypted under (see `content.file`). It lives in the message
fact, not beside it, so a message deletion shreds it (cryptographic erase of the
attachment bytes) and — the point of putting it here — whatever confidentiality
a future layer gives the message body covers the file key for free: encrypt the
message, and its files are encrypted the same way."""
from kernel import (Atom, Exact, PROVIDE, Out, REQUIRE, SELF, SUPPRESS_IF,
                    encode, fact, frame, now, ts_atom, ts_of)
from facts.auth import local_signer_secret, signature
from facts.content import channel as channels
from facts.store import hydrate
import cliargs, crypto

TAG = b"content.message"

# SHAPE — the canonical atom set; the only place atoms are chosen.
def message(workspace_id, channel_id, author_id, body, t, file_secret):
    return fact(TAG, ts_atom(t, workspace_id),
                Atom(REQUIRE, b"channel", workspace_id, Exact(channel_id)),
                Atom(REQUIRE, b"pk", workspace_id, SELF),
                Atom(REQUIRE, b"key", workspace_id, Exact(workspace_id)),
                Atom(PROVIDE, b"msg", workspace_id, Exact(channel_id), body),
                Atom(PROVIDE, b"posted", workspace_id, SELF, author_id),
                Atom(PROVIDE, b"file_secret", workspace_id, SELF, file_secret),
                Atom(SUPPRESS_IF, b"dead", workspace_id, SELF))

# EXTRACT — content-pure durability.
def extract(f): return True
from facts.sync.index import sync_leaf

# PROJECT — the only place this family's meaning lives.
def project(f, ctx):
    try:
        m = next(a for a in f.atoms if a.name == b"msg")
        p = next(a for a in f.atoms if a.name == b"posted")
        s = next(a for a in f.atoms if a.name == b"file_secret")
        if len(m.target[0]) != 32: return Out("Invalid")
        if f != message(m.scope, m.target[0], p.value, m.value, ts_of(f), s.value): return Out("Invalid")
    except Exception:
        return Out("Invalid")
    signer, members = signature.blessed(ctx)
    if members.get(p.value) not in signer: return Out("Invalid")   # the author signed it
    return Out(provides=(m, p, s, sync_leaf()))                     # publish the key for members to decrypt

# COMMANDS — build a fact, admit it, stop. Authorship is the local signer's
# membership; the signature travels with the message.
def file_secret(node, workspace_id, channel_id, body, t):
    """The per-message attachment key. Derived from the author's signer secret so
    resending the same message is idempotent (same key -> same fact id), yet it is
    not computable from the plaintext by anyone lacking that secret — the key
    rides the message fact and inherits whatever confidentiality the message body
    has, which is the point of keeping it here."""
    local = local_signer_secret.current(node)
    if not local: raise RuntimeError("no local signer key: run auth.local_signer_secret.keygen first")
    return crypto.keyed_hash(local[0], b"tinyp2p.message.file_secret",
                             frame(workspace_id, channel_id, body, t.to_bytes(8, "big")))

def send(node, workspace_id, channel_id, body, t):
    secret = file_secret(node, workspace_id, channel_id, body, t)
    return signature.signed_admit(
        node, workspace_id, lambda mid: message(workspace_id, channel_id, mid, body, t, secret), t)

# QUERIES — observations over validated state only, ordered by (ts, owner).
# Queries author volatile demand (never durable facts) and drain before reading.
def feed(node, workspace_id, channel_id):
    hydrate.demand(node, b"msg", workspace_id)
    return [a.value for o, t, a in sorted(node.provided(b"msg", workspace_id),
                                          key=lambda r: (r[1], r[0]))
            if a.target == Exact(channel_id)]

def view(node, workspace_id, channel):
    from facts.content import file as filemod
    hydrate.demand(node, b"msg", workspace_id)
    attachments = {}
    for item in filemod.files(node, workspace_id):
        attachments.setdefault(item["message_id"], []).append(item)
    lines = []
    for owner, t, atom in sorted(node.provided(b"msg", workspace_id), key=lambda r: (r[1], r[0])):
        if atom.target != Exact(channel):
            continue
        lines.append(atom.value.decode())
        for item in attachments.get(owner, ()):
            state = "complete" if item["complete"] else \
                "%d/%d slices" % (item["slices_received"], item["total_slices"])
            lines.append("  file: %s (%d bytes, %s)" %
                         (item["filename"].decode(), item["blob_bytes"], state))
    return lines

# CLI — string boundary over COMMANDS/QUERIES. Grammar: `[wid=] <channel>
# <body> [t=]`; the author is always the local signer, the body is one token
# (quote it if it has spaces). A read whose workspace or channel is not yet
# resident is an empty feed, so polling can observe either arrival.
def _read(node, kv, ref, run):
    wid = cliargs.wid_of(node, kv, missing_ok=True)
    if wid is None: return ""             # no workspace resolvable yet: nothing to show
    try: channel_id = channels.resolve(node, wid, ref)
    except RuntimeError as e:
        if str(e).startswith("unknown channel:"): return ""
        raise
    return run(wid, channel_id)

def _cli_send(n, *argv):
    kv, pos = cliargs.split(argv)
    if len(pos) != 2: raise RuntimeError("usage: content.message.send [wid=<id>] <channel> <body> [t=<n>]")
    wid = cliargs.wid_of(n, kv)
    channel_id = channels.resolve(n, wid, pos[0])
    return send(n, wid, channel_id, pos[1].encode(), cliargs.t_of(kv)).hex()

def _cli_feed(n, *argv):
    kv, pos = cliargs.split(argv)
    if len(pos) != 1: raise RuntimeError("usage: content.message.feed [wid=<id>] <channel>")
    return _read(n, kv, pos[0], lambda wid, cid: b"\n".join(feed(n, wid, cid)).decode())

def _cli_view(n, *argv):
    kv, pos = cliargs.split(argv)
    if len(pos) != 1: raise RuntimeError("usage: content.message.view [wid=<id>] <channel>")
    return _read(n, kv, pos[0], lambda wid, cid: "\n".join(view(n, wid, cid)))

CLI = {"send": _cli_send, "feed": _cli_feed, "view": _cli_view}
