"""cliargs.py — the shared token grammar for the content CLIs. Ambient context
never rides a positional's shape: the workspace and the timestamp are keyed
tokens (`wid=<64hex>`, `t=<int>`) whose VALUE must be well-formed to be read as
that token — a token whose value does not parse (`t=5pm`, `wid=nope`) stays a
positional, so it can never crash a verb or silently vanish. Everything else is
a positional in the verb's declared order. An omitted `wid=` falls back to the
active workspace; an omitted `t=` to now(). A message body is a single
positional (quote it if it has spaces): only a body that is *exactly* a
well-formed `t=<int>` or `wid=<64hex>` token is ambiguous, which is why body
words are not split on `=`."""
from kernel import now

def _ok_wid(v):
    try: return len(bytes.fromhex(v)) == 32
    except ValueError: return False

def _ok_t(v):
    return v[1:].isdigit() if v[:1] == "-" else v.isdigit()

VALID = {"wid": _ok_wid, "t": _ok_t}     # a keyed token counts only if its value parses

def split(argv, keys=VALID):
    """(argv) -> (kv, positionals). A token 'k=v' is keyed only when k is a known
    key AND v is well-formed for it; otherwise it stays a positional (so a body
    like 't=5pm' or a stray '=' is text, never a swallowed flag or a crash)."""
    kv, pos = {}, []
    for a in argv:
        k, sep, v = a.partition("=")
        if sep and k in keys and k not in kv and keys[k](v): kv[k] = v
        else: pos.append(a)
    return kv, pos

def wid_of(node, kv, missing_ok=False):  # explicit wid=, else the active workspace
    if "wid" in kv: return bytes.fromhex(kv["wid"])    # split() already checked 32 bytes
    from facts.auth import active_workspace
    return active_workspace.default(node, missing_ok=missing_ok)

def t_of(kv):                            # explicit t=, else now()
    return int(kv["t"]) if "t" in kv else now()
