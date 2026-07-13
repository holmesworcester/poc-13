"""runtime — the host turn as a socket-free unit the daemon and tests share.

The daemon is I/O around three pure steps: `cycle` admits an inbox of fact bytes
and drains one bounded turn, presenting the wire's flush reports (so a courier that
Watches shipped reaps); `outbox` is the validated send/ship rows a pump ships;
`pump` groups those rows by owner, resolves each owner's route and its ship-ids to
durable bytes, hands the inners to a `deliver` callback, and returns the owners that
fired — the next cycle's `shipped`. No sockets and no sync/handshake logic live
here: the daemon supplies `route` (connection -> addr+secret) and `deliver` (pack,
seal, enqueue), so this stays testable with plain callbacks. `flush` persists each
turn's new durable facts (a flushed set keeps the repeat scan cheap). There is no
load: boot is a fact — store.hydrate's total demand faults the db resident."""
import os, sys
BIN = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [BIN, os.path.dirname(BIN)]
from kernel import unframe, H

BOUND = 64                               # admits/steps per turn; the engine drain bound

def flush(node, store, flushed):         # one transaction per host turn. durable is
    if len(flushed) == len(node.durable): return   # append-only, so the unflushed facts are a
    new = []                             # contiguous tail: scan back from newest until an already-
    for fid in reversed(node.durable):   # flushed id, never the whole set (that repeat scan was O(n^2)).
        if fid in flushed: break
        new.append(fid)
    for fid in reversed(new): store.add(node.durable[fid]); flushed.add(fid)
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

def pump(node, route, deliver, shipped, sent=None):
    """Ship each not-yet-flushed owner's send/ship rows. route(cid)->(addr,secret)|None;
    deliver(cid, addr, secret, inners)->int, the count of inners it actually enqueued (a
    prefix — it stops at a full outbox). Returns the set of owner fids that fired, to
    feed the next cycle as `shipped`.

    `sent` (optional {cid: set(fid)}) is a per-connection SOURCE-side wire memory: a
    fact already shipped to a cid is not re-shipped when a re-descend re-asks for it
    while it is still in flight (unadmitted on the peer). Without it a bulk catch-up
    ships each fact once per re-descend — O(n) re-descends over an O(n) diff = O(n^2)
    wire bytes. `send` CONTROL frames (compares/handshake) are deduped the same way, by
    content HASH: a compare is content-addressed (ts is fixed), so a static source that
    re-authors the same split every cadence tick, or re-answers the same range on every
    re-descend, ships it ONCE — that redundant re-emission was the other half of the
    O(n^2). Both fids and content hashes are 32-byte digests, so one per-cid set holds
    both. Marks a key sent only for the prefix deliver enqueued,
    so a short count leaves the unsent tail unmarked. An owner is fired only when fully
    delivered; a partial/empty count leaves it standing to ship its still-unmarked
    remainder next turn (the marked prefix is skipped), so a big need drains across
    turns and a full outbox is a cheap select-driven wait — never a re-seal spin
    (deliver skips sealing when there is no room). The daemon clears `sent` for a peer
    on its socket break, so a reconnect re-ships in full."""
    rows = {}
    for o, _, a in outbox(node):
        if o not in shipped: rows.setdefault(o, []).append(a)     # edge-drain: skip already-flushed
    fired = set()
    for o, atoms in sorted(rows.items()):
        cid = atoms[0].target[1]; r = route(cid)
        if not r: continue                                        # no route yet: the offer stands (park)
        addr, secret = r
        seen = sent.setdefault(cid, set()) if sent is not None else None
        of = node.facts.get(o); sync_owner = of is not None and of.type_tag.startswith(b"sync.")
        inners, keys = [], []                                     # keys parallel to inners: fid | content-hash | None
        for a in sorted(atoms, key=lambda a: (a.role, a.value)):
            if a.role == b"send":                                 # inline control frame: dedup sync compares by content
                h = H(a.value) if (seen is not None and sync_owner) else None   # handshake frames must always resend
                if h is not None and h in seen: continue          # this exact compare already went to this peer
                inners.append(a.value); keys.append(h)
            else:
                for x in unframe(a.value):                        # by-reference bulk: skip already-shipped
                    if x not in node.durable or (seen is not None and x in seen): continue
                    inners.append(node.durable[x]); keys.append(x)
        if not inners: fired.add(o); continue                     # nothing new (need/compare already sent): reap
        count = deliver(cid, addr, secret, inners)
        if seen is not None:
            for k in keys[:count]:                                # record only the prefix that went out
                if k is not None: seen.add(k)
        fired.add(o)                                              # always reap the owner — a standing need bloats
                                                                  # the source outbox (its scan is O(len)); the
                                                                  # unmarked overflow tail is re-asked by the next
                                                                  # re-descend and ships then (not re-decoded twice)
    return fired
