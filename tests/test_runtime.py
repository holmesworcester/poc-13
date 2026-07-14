"""The runtime seam (bin/runtime.py), socket-free: cycle admits an inbox and drains
a turn presenting flush reports; outbox exposes the send/ship rows; pump resolves
each owner through route+deliver and reports which fired. Plain callbacks stand in
for the daemon's sockets, so the host turn is testable without a wire."""
import os, sys
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT_DIR = os.path.dirname(HERE)
sys.path[:0] = [ROOT_DIR, os.path.join(ROOT_DIR, "bin")]
from kernel import Node, encode, fact_id
from facts import ROOT
from facts.outbox.send import send
from runtime import cycle, outbox, pump

def test_cycle_stages_then_reaps():
    n = Node(ROOT)
    s1, s2 = send(b"peer", b"hello", 1), send(b"peer", b"world", 2)
    cycle(n, [encode(s1), encode(s2)], 1000, ())
    assert {o for o, _, _ in outbox(n)} == {fact_id(s1), fact_id(s2)}   # two send rows staged
    cycle(n, [], 1001, (fact_id(s1), fact_id(s2)))                       # daemon reports the flush
    assert not outbox(n)                                                 # rows gone
    assert fact_id(s1) not in n.facts and fact_id(s2) not in n.facts     # one-shot couriers reaped

def test_pump_routes_and_fires():
    n = Node(ROOT); s = send(b"1.2.3.4:9", b"payload", 1)
    cycle(n, [encode(s)], 1000, ())
    got = []
    def deliver(cid, addr, secret, inners): got.append((addr, inners)); return len(inners)
    fired = pump(n, lambda cid: (cid, b""), deliver, set())             # send targets Exact(dest) -> cid==dest
    assert fired == {fact_id(s)}
    assert got and got[0][0] == b"1.2.3.4:9" and b"payload" in got[0][1]

def test_pump_parks_without_route():
    n = Node(ROOT); s = send(b"nowhere", b"x", 1); cycle(n, [encode(s)], 1000, ())
    assert pump(n, lambda cid: None, lambda *a: True, set()) == set() and outbox(n)   # no route -> stands

def test_pump_reaps_even_when_outbox_refuses():
    """A full outbox (deliver enqueues 0) still fires the owner: pump never leaves a
    send standing to re-pump, so the source outbox cannot bloat during catch-up (its
    scan is O(len)). The dropped bytes heal on the next re-descend, not a pump retry."""
    n = Node(ROOT); s = send(b"addr", b"x", 1); cycle(n, [encode(s)], 1000, ())
    assert pump(n, lambda cid: (cid, b""), lambda *a: 0, set()) == {fact_id(s)}   # reaped despite 0 enqueued

def test_pump_dedup_ships_each_fid_once_per_connection():
    """Source-side sent-set: a fid a re-descend re-asks for while it is in flight is
    not re-shipped (the O(n^2) catch-up amplifier), yet each distinct fid ships once
    and the re-asking owner still fires (its need reaps)."""
    from facts.sync.need import need
    n = Node(ROOT)
    f1, f2, f3 = b"\x01" * 32, b"\x02" * 32, b"\x03" * 32
    for f, b in ((f1, b"A"), (f2, b"B"), (f3, b"C")): n.durable[f] = b   # stand-in durable bodies
    cid, sent = b"conn1", {}
    cycle(n, [encode(need(cid, [f1, f2])), encode(need(cid, [f2, f3]))], 1000, ())  # two overlapping needs
    def run(sink):
        return pump(n, lambda c: (c, b"sec"),
                    lambda c, a, s, inn: (sink.extend(inn), len(inn))[1], set(), sent)
    got = []; fired = run(got)
    assert sorted(got) == [b"A", b"B", b"C"]            # f2 shipped once despite two needs naming it
    assert sent[cid] == {f1, f2, f3} and len(fired) == 2
    got2 = []; fired2 = run(got2)                       # a re-descend re-pumps the same rows
    assert got2 == [] and len(fired2) == 2              # nothing re-ships; owners still fire (reap)

def test_pump_overflow_tail_is_unmarked_and_reships():
    """A full outbox stops deliver mid-batch: only the enqueued prefix is marked, the
    owner stands (not fired), and the still-unmarked tail ships next turn — the drop-
    heal a bounded outbox needs, without re-shipping the prefix."""
    from facts.sync.need import need
    n = Node(ROOT)
    f1, f2 = b"\x01" * 32, b"\x02" * 32
    n.durable[f1], n.durable[f2] = b"A", b"B"
    cid, sent, cap = b"c", {}, [1]
    cycle(n, [encode(need(cid, [f1, f2]))], 1000, ())
    def deliver(c, a, s, inn, got): k = min(cap[0], len(inn)); got.extend(inn[:k]); return k
    g1 = []; fired1 = pump(n, lambda c: (c, b"sec"), lambda *a: deliver(*a, g1), set(), sent)
    assert g1 == [b"A"] and sent[cid] == {f1} and len(fired1) == 1   # only the prefix is marked (tail unsent)
    cap[0] = 9; g2 = []
    fired2 = pump(n, lambda c: (c, b"sec"), lambda *a: deliver(*a, g2), set(), sent)
    assert g2 == [b"B"] and sent[cid] == {f1, f2} and len(fired2) == 1  # unmarked tail re-ships, never the prefix

def test_flush_forgets_purged_fids():
    """Purge undoes "on disk": the fid must leave the flushed set, or its
    re-arrival hides behind the stale mark and every fact admitted earlier in
    the same cycle silently misses the disk (the tail scan stops at it)."""
    from kernel import Store
    from runtime import flush
    from facts.content.message import message
    from facts.content.message_deletion import deletion
    wid = b"\x07" * 32
    store, flushed = Store(), set()
    n = Node(ROOT, store)
    m = message(wid, b"g", b"al", b"doomed", 5); mid = fact_id(m)
    cycle(n, [encode(m)], 1000, ())
    flush(n, store, flushed)
    assert mid in flushed                                  # on disk, marked
    cycle(n, [encode(deletion(wid, mid, 6))], 1001, ())    # the death key bites: purged
    x = message(wid, b"g", b"al", b"new", 7)
    cycle(n, [encode(x), encode(m)], 1002, (), bound=0)    # re-arrival lands BEHIND x, both unstepped
    flush(n, store, flushed)                               # the purge unmarked mid, so the tail scan
    assert store.db.execute("SELECT 1 FROM facts WHERE fid=?",
                            (fact_id(x),)).fetchone(), "the newer fact reached disk"
    n.run(); flush(n, store, flushed)                      # the re-arrival dies on arrival...
    assert store.db.execute("SELECT 1 FROM facts WHERE fid=?", (mid,)).fetchone() is None
    assert mid not in n.facts and mid not in n.durable     # ...and leaves no residue anywhere

if __name__ == "__main__":
    for t in (test_cycle_stages_then_reaps, test_pump_routes_and_fires,
              test_pump_parks_without_route, test_pump_reaps_even_when_outbox_refuses,
              test_pump_dedup_ships_each_fid_once_per_connection,
              test_pump_overflow_tail_is_unmarked_and_reships,
              test_flush_forgets_purged_fids):
        t(); print("ok ", t.__name__)
