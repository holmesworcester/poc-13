"""cliargs.py — the shared token grammar for the content CLIs. Ambient context
never rides a positional's shape: the workspace and the timestamp are keyed
tokens (`wid=<64hex>`, `t=<int>`) that may appear anywhere in the argument list,
and everything else is a positional in the verb's declared order. An omitted
`wid=` falls back to the active workspace; an omitted `t=` to now(). This is the
whole demo grammar — no aliases, no per-verb sniffing, so no token is ever read
for what it happens to look like (a numeric body is a body, a 64-hex channel
name is a channel name)."""
from kernel import now

KEYS = ("wid", "t")

def split(argv, keys=KEYS):
    """(argv) -> (kv, positionals). A token 'k=v' whose k is a known key is
    keyed; anything else (no '=', or an unknown key) stays a positional, so a
    body may still contain '='."""
    kv, pos = {}, []
    for a in argv:
        k, sep, v = a.partition("=")
        if sep and k in keys and k not in kv: kv[k] = v
        else: pos.append(a)
    return kv, pos

def wid_of(node, kv):                    # explicit wid=, else the active workspace
    if "wid" in kv:
        try: b = bytes.fromhex(kv["wid"])
        except ValueError: b = b""
        if len(b) != 32: raise RuntimeError("wid= must be 64 hex chars")
        return b
    from facts.auth import active_workspace
    return active_workspace.default(node)

def t_of(kv):                            # explicit t=, else now()
    return int(kv["t"]) if "t" in kv else now()
