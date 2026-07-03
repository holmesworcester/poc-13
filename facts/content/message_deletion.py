"""facts/content/message_deletion.py — semantic deletion. A valid `dead`
offer at the target's id flips every fact carrying that death key to
Suppressed. Require-free on purpose: a suppressor that could park could be
raced by the thing it must kill."""
from kernel import Atom, Exact, OFFER, Out, encode, fact, now, ts_atom

TAG = b"content.message_deletion"

# SHAPE — the canonical atom set; the only place atoms are chosen.
def deletion(workspace_id, target_id, t):
    return fact(TAG, ts_atom(t, workspace_id),
                Atom(OFFER, b"dead", workspace_id, Exact(target_id)))

# EXTRACT — content-pure: (durable, shareable). Deletions must travel.
def extract(f): return True, True

# PROJECT — the only place this family's meaning lives.
def project(f, ctx, sl):
    return Out(offers=tuple(a for a in f.atoms if a.role == b"dead"))

# COMMANDS — build a fact, admit it, stop.
def delete(node, workspace_id, target_id, t):
    return node.admit(encode(deletion(workspace_id, target_id, t)))

# QUERIES — none yet.

# CLI — string boundary over COMMANDS/QUERIES.
CLI = {"delete": lambda n, wid, tid, t=None:
           delete(n, bytes.fromhex(wid), bytes.fromhex(tid), int(t or now())).hex()}
