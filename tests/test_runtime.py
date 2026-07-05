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
    def deliver(cid, addr, secret, inners): got.append((addr, inners)); return True
    fired = pump(n, lambda cid: (cid, b""), deliver, set())             # send targets Exact(dest) -> cid==dest
    assert fired == {fact_id(s)}
    assert got and got[0][0] == b"1.2.3.4:9" and b"payload" in got[0][1]

def test_pump_parks_without_route():
    n = Node(ROOT); s = send(b"nowhere", b"x", 1); cycle(n, [encode(s)], 1000, ())
    assert pump(n, lambda cid: None, lambda *a: True, set()) == set() and outbox(n)   # no route -> stands

def test_pump_backpressure_does_not_fire():
    n = Node(ROOT); s = send(b"addr", b"x", 1); cycle(n, [encode(s)], 1000, ())
    assert pump(n, lambda cid: (cid, b""), lambda *a: False, set()) == set() and outbox(n)  # deliver refused

if __name__ == "__main__":
    for t in (test_cycle_stages_then_reaps, test_pump_routes_and_fires,
              test_pump_parks_without_route, test_pump_backpressure_does_not_fire):
        t(); print("ok ", t.__name__)
