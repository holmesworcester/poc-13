"""runtime — the host turn as a socket-free unit the daemon and tests share.

The daemon is I/O around three pure steps: `cycle` admits an inbox of fact bytes
and drains one bounded turn, presenting the wire's flush reports (so a courier that
Watches shipped reaps); `outbox` is the validated send/ship rows a pump ships;
`pump` groups those rows by owner, resolves each owner's route and its ship-ids to
durable bytes, hands the inners to a `deliver` callback, and returns the owners that
fired — the next cycle's `shipped`. No sockets and no sync/handshake logic live
here: the daemon supplies `route` (connection -> addr+secret) and `deliver` (pack,
seal, enqueue), so this stays testable with plain callbacks. `load`/`flush` bookend
the turn with the durable store: `load` replays it on startup, `flush` persists each
turn's new durable facts (a flushed set keeps the repeat scan cheap)."""
import os, sys
BIN = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [BIN, os.path.dirname(BIN)]
from kernel import unframe

BOUND = 64                               # admits/steps per turn; the engine drain bound

def load(node, store):                   # full replay: own db passed the gate once
    for fb in store.all(): node.admit(fb, checked=True)
    node.run()

def flush(node, store, flushed):         # one transaction per host turn. durable is
    if len(flushed) == len(node.durable): return   # append-only, so the unflushed facts are a
    new = []                             # contiguous tail: scan back from newest until an already-
    for fid in reversed(node.durable):   # flushed id, never the whole set (that repeat scan was O(n^2)).
        if fid in flushed: break
        new.append(fid)
    for fid in reversed(new): store.add(node.durable[fid], hot=True); flushed.add(fid)
    store.commit()

def cycle(node, inbox, now_ms, shipped, bound=BOUND):
    """Admit each fact in `inbox`, then drain one bounded turn presenting `shipped`."""
    for b in inbox: node.admit(b)
    node.turn(now_ms, shipped, bound)
    return node

def outbox(node):                        # the one out door: validated send/ship rows at the outbox keys
    return node.watched(b"send", b"outbox") + node.watched(b"ship", b"outbox")

def next_wake(node, now_ms, cap):        # seconds until the earliest wake@clock alarm, capped at `cap`
    ds = [int.from_bytes(a.target[1], "big") for _, _, a in node.watched(b"wake", b"clock")]
    return max(0.0, min(cap, min((d - now_ms for d in ds), default=cap * 1000) / 1000.0))

def pump(node, route, deliver, shipped):
    """Ship each not-yet-flushed owner's send/ship rows. route(cid)->(addr,secret)|None;
    deliver(cid, addr, secret, inners)->bool (True = handed to the link). Returns the
    set of owner fids that fired, to feed the next cycle as `shipped`."""
    rows = {}
    for o, _, a in outbox(node):
        if o not in shipped: rows.setdefault(o, []).append(a)     # edge-drain: skip already-flushed
    fired = set()
    for o, atoms in sorted(rows.items()):
        cid = atoms[0].target[1]; r = route(cid)
        if not r: continue                                        # no route yet: the offer stands (park)
        addr, secret = r
        inners = []
        for a in sorted(atoms, key=lambda a: (a.role, a.value)):
            if a.role == b"send": inners.append(a.value)          # inline control frame
            else: inners += [node.durable[x] for x in unframe(a.value) if x in node.durable]  # by-reference bulk
        if deliver(cid, addr, secret, inners): fired.add(o)
    return fired
