"""facts/content/message.py — a workspace message, member-signed. Requires its
workspace, its own signature (b"pk" at its id), and the member keys, then the
projector binds them: the posted author id must name a member whose blessed key
signed this fact. Offers a feed row and a `posted` marker at its own id for
reactions to Require, and carries its own death key (Suppress on SELF). Scope is
the workspace id alone — channel rides as the feed offer's target, which beats a
composite scope on LOC. Canonical form is enforced by rebuilding through SHAPE:
`posted` is an authorship claim, so a fact must carry exactly the one claim the
signer gate vouches for."""
from kernel import (Atom, Exact, NEED, OFFER, Out, REQUIRE, SELF, SUPPRESS,
                    encode, fact, now, ts_atom, ts_of)
from facts.auth import signature
from facts.store import hydrate

TAG = b"content.message"

# SHAPE — the canonical atom set; the only place atoms are chosen.
def message(workspace_id, channel, author_id, body, t):
    return fact(TAG, ts_atom(t, workspace_id),
                Atom(NEED, b"workspace", b"auth", Exact(workspace_id), effect=REQUIRE),
                Atom(NEED, b"pk", workspace_id, SELF, effect=REQUIRE),
                Atom(NEED, b"key", workspace_id, Exact(workspace_id), effect=REQUIRE),
                Atom(OFFER, b"msg", workspace_id, Exact(channel), body),
                Atom(OFFER, b"posted", workspace_id, SELF, author_id),
                Atom(NEED, b"dead", workspace_id, SELF, effect=SUPPRESS))

# EXTRACT — content-pure: (durable, shareable).
def extract(f): return True, True
from facts.sync.index import settle      # opt in: these facts replicate (one line is the whole choice)

# PROJECT — the only place this family's meaning lives.
def project(f, ctx):
    try:
        m = next(a for a in f.atoms if a.role == b"msg")
        p = next(a for a in f.atoms if a.role == b"posted")
        if f != message(m.scope, m.target[0], p.value, m.value, ts_of(f)): return Out("Invalid")
    except Exception:
        return Out("Invalid")
    signer, members = signature.blessed(ctx)
    if members.get(p.value) not in signer: return Out("Invalid")   # the author signed it
    return Out(offers=(m, p))

# COMMANDS — build a fact, admit it, stop. Authorship is the local signer's
# membership; the signature travels with the message.
def send(node, workspace_id, channel, body, t):
    return signature.signed_admit(
        node, workspace_id, lambda mid: message(workspace_id, channel, mid, body, t), t)

# QUERIES — observations over validated state only, ordered by (ts, owner).
# Queries author volatile demand (never durable facts) and drain before reading.
def feed(node, workspace_id, channel):
    hydrate.demand(node, b"msg", workspace_id)
    return [a.value for o, t, a in sorted(node.watched(b"msg", workspace_id),
                                          key=lambda r: (r[1], r[0]))
            if a.target == Exact(channel)]

def view(node, workspace_id, channel):
    from facts.content import file as filemod
    hydrate.demand(node, b"msg", workspace_id)
    attachments = {}
    for item in filemod.files(node, workspace_id):
        attachments.setdefault(item["message_id"], []).append(item)
    lines = []
    for owner, t, atom in sorted(node.watched(b"msg", workspace_id), key=lambda r: (r[1], r[0])):
        if atom.target != Exact(channel):
            continue
        lines.append(atom.value.decode())
        for item in attachments.get(owner, ()):
            state = "complete" if item["complete"] else \
                "%d/%d slices" % (item["slices_received"], item["total_slices"])
            lines.append("  file: %s (%d bytes, %s)" %
                         (item["filename"].decode(), item["blob_bytes"], state))
    return lines

# CLI — string boundary over COMMANDS/QUERIES. The author is the local signer;
# the `who` slot is accepted and ignored for wire-compat until the CLI rework.
CLI = {"send": lambda n, wid, ch, who, body, t=None:
           send(n, bytes.fromhex(wid), ch.encode(), body.encode(), int(t or now())).hex(),
       "feed": lambda n, wid, ch:
           b"\n".join(feed(n, bytes.fromhex(wid), ch.encode())).decode(),
       "view": lambda n, wid, ch:
           "\n".join(view(n, bytes.fromhex(wid), ch.encode()))}
