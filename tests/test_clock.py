"""Clock tests: ticks wake exactly the facts whose bounded Watch windows cover
them, past ticks are visible state (a late-authored fact sees them at first
projection — no missed-wake race), same-bucket strikes are idempotent, and the
alarm query orders the daemon's wake schedule."""
import os, sys, types
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from kernel import Atom, Exact, NEED, Node, OFFER, Out, Router, WATCH, encode, fact
from facts import ROOT
from facts.clock import tick as clock

# A toy family: Watches a tick window, offers `seen` = how many ticks are in ctx,
# and a standing alarm at its deadline. The observable is the seen-count.
def _toy_family():
    def project(f, ctx, sl):
        n = len([r for k, rs in ctx.items() if k.role == b"tick" for r in rs])
        return Out(offers=(Atom(OFFER, b"seen", b"toy", (1,), bytes([n])),  # SELF target
                           *[a for a in f.atoms if a.role == b"alarm"]))
    return types.SimpleNamespace(extract=lambda f: (False, False), project=project)

def _node():
    return Node(Router({b"clock": __import__("facts.clock", fromlist=["SCOPE"]).SCOPE,
                        b"toy": Router({b"t": _toy_family()}, depth=1)}))

def _toy(first_ms, last_ms, deadline_ms):
    return fact(b"toy.t", clock.tick_watch(first_ms, last_ms), clock.alarm_atom(deadline_ms))

def _seen(n, tid):
    return next(a.value[0] for o, _, a in n.watched(b"seen", b"toy") if o == tid)

def test_tick_wakes_only_covered_windows():
    n = _node()
    tid = n.admit(encode(_toy(500, 1000, 500))); n.run()
    assert _seen(n, tid) == 0
    clock.strike(n, 400); n.run()                    # before the window: no wake into ctx
    assert _seen(n, tid) == 0
    clock.strike(n, 650); n.run()                    # inside: the tick lands in ctx
    assert _seen(n, tid) == 1
    clock.strike(n, 1000 + clock.GRACE + 100); n.run()   # past grace: never wakes it
    assert _seen(n, tid) == 1

def test_late_authored_fact_sees_past_ticks():
    n = _node()
    clock.strike(n, 650); n.run()                    # the tick lands first
    tid = n.admit(encode(_toy(500, 1000, 500))); n.run()
    assert _seen(n, tid) == 1                        # first projection already sees it

def test_same_bucket_strike_is_idempotent():
    n = _node()
    a = clock.strike(n, 650); n.run()
    before = len(n.facts)
    assert clock.strike(n, 699) == a                 # same 100ms bucket: same fact
    assert len(n.facts) == before
    assert clock.strike(n, 700) != a                 # next bucket: a new tick
    n.run()

def test_alarm_query_orders_the_schedule():
    n = _node()
    assert clock.next_alarm(n) is None               # zero alarms: zero ticks, ever
    n.admit(encode(_toy(500, 1000, 900))); n.run()
    n.admit(encode(_toy(200, 800, 300))); n.run()
    assert clock.next_alarm(n) == 300
    assert [d for _, d in clock.alarms(n)] == [300, 900]

def test_clock_family_routes_under_root():
    n = Node(ROOT)                                   # the real tree carries the family
    fid = clock.strike(n, 12345); n.run()
    assert n.memo[fid] == "Valid"
    assert n.root.extract(n.facts[fid]) == (False, False)   # volatile, unshareable

if __name__ == "__main__":
    for t in (test_tick_wakes_only_covered_windows, test_late_authored_fact_sees_past_ticks,
              test_same_bucket_strike_is_idempotent, test_alarm_query_orders_the_schedule,
              test_clock_family_routes_under_root):
        t(); print(f"ok  {t.__name__}")
    print("\nall clock tests passed")
