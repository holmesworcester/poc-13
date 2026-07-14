"""facts/auth/active_workspace.py — node-private workspace selection for the CLI.
This is UI state, not shared authority: it names which workspace a verb uses
when `wid=` is omitted. Durable so the choice survives a daemon restart, but
marker-free so it never syncs and never touches the kernel's authority story. It
Requires the workspace it names, so a selection self-heals — a workspace that is
gone parks its selection and the reader falls back to the sole/only workspace.
The latest selection wins by the ordinary (ts, owner) read-side fold."""
from kernel import (Atom, Exact, PROVIDE, Out, REQUIRE, encode, fact, now,
                    remote_suppress, ts_atom, ts_of)
from facts.store import hydrate

TAG = b"auth.active_workspace"
KEY = b"current"

# SHAPE — the canonical atom set; the only place atoms are chosen.
def active_workspace(workspace_id, t):
    return fact(TAG, ts_atom(t, b"local"),
                remote_suppress,
                Atom(REQUIRE, b"workspace", b"auth", Exact(workspace_id)),
                Atom(PROVIDE, b"active_workspace", b"local", Exact(KEY), workspace_id))

# EXTRACT — content-pure durability. The projector emits no sync marker.
def extract(f): return True

# CHECK — exact family shape. Wire provenance is expressed by remote_suppress.
def check(f):
    try:
        row = next(a for a in f.atoms if a.name == b"active_workspace")
        return f == active_workspace(row.value, ts_of(f))
    except Exception:
        return False

# PROJECT — accept exactly SHAPE (the workspace Require gates validity upstream).
def project(f, ctx):
    try:
        row = next(a for a in f.atoms if a.name == b"active_workspace")
        if f != active_workspace(row.value, ts_of(f)): return Out("Invalid")
    except Exception:
        return Out("Invalid")
    return Out(provides=(row,))

# COMMANDS — select a workspace as the default. Idempotent per (ts, wid).
def use(node, workspace_id, t):
    return node.admit(encode(active_workspace(workspace_id, t)))

# QUERIES — the current selection (latest valid wins), and the resolved default.
def current(node):
    hydrate.demand(node, b"active_workspace", b"local")
    row = max(node.provided(b"active_workspace", b"local"),
              key=lambda r: (r[1], r[0]), default=None)
    return row[2].value if row else None

def default(node, missing_ok=False):
    from facts.auth import workspace
    cur = current(node)
    if cur is not None: return cur
    idx = workspace.index(node)          # no selection: a lone workspace is unambiguous
    if len(idx) == 1: return idx[0][0]
    if not idx:                          # cold / not yet synced: a read may treat this as empty
        if missing_ok: return None
        raise RuntimeError("no workspace yet; create or join one, or pass wid=<id>")
    raise RuntimeError("multiple workspaces; select one with auth.active_workspace.use <wid>, or pass wid=<id>")

# CLI — string boundary over COMMANDS/QUERIES.
CLI = {"use": lambda n, wid, t=None: use(n, bytes.fromhex(wid), int(t or now())).hex(),
       "current": lambda n: (current(n) or b"").hex()}
