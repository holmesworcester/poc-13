"""facts/content/retention_policy.py — the retention window for a workspace,
as an ordinary validated offer: the query takes the latest (ts, owner) row,
so last-write-wins is a read-side fold, not kernel state. Admin-signed (poc-10
parity: members post, admins govern): the projector demands the signer be a
member the admin tier names. Recording only — the purge machinery that enforces
the window is a later family (DESIGN.md, Retention and purge)."""
from kernel import (Atom, Exact, NEED, OFFER, Out, REQUIRE, Range, SELF, by,
                    encode, fact, now, ts_atom, ts_of)
from facts.auth import signature
from facts.store import hydrate
import cliargs

TAG = b"content.retention_policy"
IDS = Range(b"", b"\xff" * 32)           # any admin grant in the workspace

# SHAPE — the canonical atom set; the only place atoms are chosen.
def policy(workspace_id, ttl, t):
    return fact(TAG, ts_atom(t, workspace_id),
                Atom(NEED, b"pk", workspace_id, SELF, effect=REQUIRE),
                Atom(NEED, b"key", workspace_id, Exact(workspace_id), effect=REQUIRE),
                Atom(NEED, b"admin", workspace_id, IDS, effect=REQUIRE),
                Atom(OFFER, b"retention", workspace_id, Exact(b"window"),
                     ttl.to_bytes(8, "little")))

# EXTRACT — content-pure: (durable, shareable).
def extract(f): return True, True
from facts.sync.index import settle      # opt in: these facts replicate (one line is the whole choice)

# PROJECT — the only place this family's meaning lives.
def project(f, ctx):
    try:
        r = next(a for a in f.atoms if a.role == b"retention")
        if f != policy(r.scope, int.from_bytes(r.value, "little"), ts_of(f)): return Out("Invalid")
    except Exception:
        return Out("Invalid")
    signer, members = signature.blessed(ctx)
    admins = {row[2].target[0] for row in by(ctx, b"admin") if row[2].target[0]}  # empty span never indexes
    if not signer & {members[a] for a in admins if a in members}: return Out("Invalid")
    return Out(offers=(r,))

# COMMANDS — build a fact, admit it, stop. The client-side admin check names the
# refusal; the projector is what a forged fact meets.
def set_window(node, workspace_id, ttl, t):
    hydrate.demand(node, b"admin", workspace_id)
    admins = {a.target[0] for _, _, a in node.watched(b"admin", workspace_id)}
    def build(member_id):
        if member_id not in admins: raise RuntimeError("local signer is not a workspace admin")
        return policy(workspace_id, ttl, t)
    return signature.signed_admit(node, workspace_id, build, t)

# QUERIES — observations over validated state only. LWW at read time:
def window(node, workspace_id):                       # the latest (ts, owner) row wins
    hydrate.demand(node, b"retention", workspace_id)
    row = max(node.watched(b"retention", workspace_id), key=lambda r: (r[1], r[0]), default=None)
    return int.from_bytes(row[2].value, "little") if row else None

# CLI — string boundary over COMMANDS/QUERIES. Grammar: `[wid=] <ttl> [t=]`.
def _cli_set(n, *argv):
    kv, pos = cliargs.split(argv)
    if len(pos) != 1: raise RuntimeError("usage: content.retention_policy.set [wid=<id>] <ttl> [t=<n>]")
    return set_window(n, cliargs.wid_of(n, kv), int(pos[0]), cliargs.t_of(kv)).hex()

def _cli_window(n, *argv):
    kv, pos = cliargs.split(argv)
    if pos: raise RuntimeError("usage: content.retention_policy.window [wid=<id>]")
    return str(window(n, cliargs.wid_of(n, kv)) or "")

CLI = {"set": _cli_set, "window": _cli_window}
