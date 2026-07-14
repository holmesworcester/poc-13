"""runtime — the host turn as a socket-free unit the daemon and tests share.

The daemon is I/O around three pure steps: `cycle` admits an inbox of fact bytes
and drains one bounded turn, presenting the wire's flush reports (so a courier that
Gathers shipped reaps); `outbox` is the validated send/ship rows a pump ships;
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

SENT_TTL = 3000                          # ms a sent digest suppresses an identical re-send. Strictly less
                                         # than the anchor cadence period (facts/sync/cadence.ANCHOR_W), so
                                         # the unconditional re-open always reaches the wire: dedup may only
                                         # DELAY a send, never veto it.

class TTLSet:
    """Dedup memory that forgets. `k in s` holds only while k's entry is younger than
    `ttl`, so membership can only delay a re-send by <= ttl — liveness never trusts
    this set (the anchor cadence re-derives and re-sends after it expires). It exists
    to collapse bytes that are duplicates right now: in-flight re-asks, the mirrored
    first cascade, a re-authored identical split. Compares equal to the set of its
    live keys, so tests read it like the plain set it replaced."""
    __slots__ = ("ttl", "now", "d")
    def __init__(self, ttl=SENT_TTL): self.ttl, self.now, self.d = ttl, 0, {}
    def __contains__(self, k):
        e = self.d.get(k); return e is not None and e > self.now
    def add(self, k):
        self.d[k] = self.now + self.ttl
        if len(self.d) > 65536:          # amortized sweep; correctness never depends on it
            self.d = {x: e for x, e in self.d.items() if e > self.now}
    def __eq__(self, other): return {k for k, e in self.d.items() if e > self.now} == other

def flush(node, store, flushed):         # one transaction per host turn.
    if node.purged:                      # the kernel already DELETEd these rows: commit that, and
        for fid in node.purged:          # forget the fids so a re-arrival re-enters the unflushed
            flushed.discard(fid)         # tail instead of hiding behind its old flush mark
        node.purged.clear(); store.commit()
    last = next(reversed(node.durable), None)      # durable appends at the tail (purge only pops),
    if last is None or last in flushed: return     # so newest-already-flushed means nothing new
    new = []                             # unflushed facts are a contiguous tail: scan back from newest
    for fid in reversed(node.durable):   # until an already-flushed id, never the whole set (that
        if fid in flushed: break         # repeat scan was O(n^2))
        new.append(fid)
    for fid in reversed(new): store.add(node.durable[fid]); flushed.add(fid)
    store.commit()

def cycle(node, inbox, now_ms, shipped, bound=BOUND):
    """Admit locally-authored `inbox`, then drain one bounded turn presenting `shipped`.
    The daemon admits wire facts itself so each carries its bare/connection origin."""
    for b in inbox: node.admit(b)
    node.turn(now_ms, shipped, bound)
    return node

def outbox(node):                        # the one out door: validated send/ship rows at the outbox keys
    return node.provided(b"send", b"outbox") + node.provided(b"ship", b"outbox")

def next_wake(node, now_ms, cap):        # seconds until the earliest wake@clock alarm, capped at `cap`
    ds = [int.from_bytes(a.target[1], "big") for _, _, a in node.provided(b"wake", b"clock")]
    return max(0.0, min(cap, min((d - now_ms for d in ds), default=cap * 1000) / 1000.0))

def pump(node, route, deliver, shipped, sent=None, now=0):
    """Ship each not-yet-flushed owner's send/ship rows. route(cid)->(addr,secret)|None;
    deliver(cid, addr, secret, inners)->int, the count of inners it actually enqueued (a
    prefix — it stops at a full outbox). Returns the set of owner fids that fired, to
    feed the next cycle as `shipped`.

    `sent` (optional {cid: TTLSet}) is a per-connection SOURCE-side wire memory,
    TTL-scoped at `now`: a fact already shipped to a cid is not re-shipped when a
    re-descend re-asks for it while it is still in flight (unadmitted on the peer).
    Without it a bulk catch-up ships each fact once per re-descend — O(n) re-descends
    over an O(n) diff = O(n^2) wire bytes. `send` CONTROL frames (compares) are
    deduped the same way, by content HASH: a compare is content-addressed (ts is
    fixed), so a static source that re-authors the same split every cadence tick
    ships it ONCE. Handshake frames are exempt (must always resend). The TTL is the
    load-bearing inequality (SENT_TTL < the anchor period): the anchor's healing
    re-open is byte-identical to a lost original, so a memory that never expired
    would suppress recovery forever — dedup may delay a send by at most the TTL,
    never veto it. Marks a key sent only for the prefix deliver enqueued, so a short
    count leaves the unsent tail unmarked to re-ship on the next re-descend. The
    daemon still clears a peer's set on its socket break, so a reconnect re-ships
    at once instead of after the TTL."""
    rows = {}
    for o, _, a in outbox(node):
        if o not in shipped: rows.setdefault(o, []).append(a)     # edge-drain: skip already-flushed
    fired = set()
    for o, atoms in sorted(rows.items()):
        cid = atoms[0].target[1]; r = route(cid)
        if not r: continue                                        # no route yet: the Provide stands (park)
        addr, secret = r
        seen = sent.setdefault(cid, TTLSet()) if sent is not None else None
        if seen is not None: seen.now = now
        of = node.facts.get(o); sync_owner = of is not None and of.type_tag.startswith(b"sync.")
        inners, keys = [], []                                     # keys parallel to inners: fid | content-hash | None
        for a in sorted(atoms, key=lambda a: (a.name, a.value)):
            if a.name == b"send":                                 # inline control frame: dedup sync compares by content
                h = H(a.value) if (seen is not None and sync_owner) else None   # handshake frames must always resend
                if h is not None and h in seen: continue          # this exact compare already went to this peer
                inners.append(a.value); keys.append(h)
            else:
                for x in unframe(a.value):                        # by-reference bulk: skip already-shipped
                    if x not in node.durable or (seen is not None and x in seen): continue
                    inners.append(node.durable[x]); keys.append(x)
        if not inners: fired.add(o); continue                     # nothing new (request/compare already sent): reap
        count = deliver(cid, addr, secret, inners)
        if seen is not None:
            for k in keys[:count]:                                # record only the prefix that went out
                if k is not None: seen.add(k)
        fired.add(o)                                              # always reap the owner — a standing request bloats
                                                                  # the source outbox (its scan is O(len)); the
                                                                  # unmarked overflow tail is re-asked by the next
                                                                  # re-descend and ships then (not re-decoded twice)
    return fired
