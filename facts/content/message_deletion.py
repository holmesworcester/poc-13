"""facts/content/message_deletion.py — semantic deletion, member-signed. A
valid `dead` Provide at the target's id flips every fact carrying that death key
to Suppressed. Target-free on purpose: a suppressor that depended on the thing
it must kill could be raced by it. The pk/key Requires gate the deleter — any
enrolled member may delete; per-author deletion is a policy for a later wave."""
from kernel import (Atom, Exact, PROVIDE, Out, REQUIRE, SELF, encode, fact,
                    now, ts_atom, ts_of)
from facts.auth import signature
import cliargs

TAG = b"content.message_deletion"

# SHAPE — the canonical atom set; the only place atoms are chosen.
def deletion(workspace_id, target_id, t):
    return fact(TAG, ts_atom(t, workspace_id),
                Atom(REQUIRE, b"pk", workspace_id, SELF),
                Atom(REQUIRE, b"key", workspace_id, Exact(workspace_id)),
                Atom(PROVIDE, b"dead", workspace_id, Exact(target_id)))

# EXTRACT — content-pure durability.
def extract(f): return True
from facts.sync.index import sync_leaf

# PROJECT — the only place this family's meaning lives.
def project(f, ctx):
    try:
        d = next(a for a in f.atoms if a.name == b"dead")
        if f != deletion(d.scope, d.target[0], ts_of(f)): return Out("Invalid")
    except Exception:
        return Out("Invalid")
    signer, members = signature.blessed(ctx)
    if not signer & set(members.values()): return Out("Invalid")   # a member signed it
    return Out(provides=(d, sync_leaf()))

# COMMANDS — build a fact, admit it, stop.
def delete(node, workspace_id, target_id, t):
    return signature.signed_admit(
        node, workspace_id, lambda _mid: deletion(workspace_id, target_id, t), t)

# QUERIES — none yet.

# CLI — string boundary over COMMANDS/QUERIES. Grammar: `[wid=] <message-id> [t=]`.
def _cli_delete(n, *argv):
    kv, pos = cliargs.split(argv)
    if len(pos) != 1: raise RuntimeError("usage: content.message_deletion.delete [wid=<id>] <message-id> [t=<n>]")
    return delete(n, cliargs.wid_of(n, kv), bytes.fromhex(pos[0]), cliargs.t_of(kv)).hex()

CLI = {"delete": _cli_delete}
