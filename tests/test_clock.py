"""Clock tests: time is not a fact family — the host hands `now` to the turn
(`turn(now)`), which presents it as one transient offer at the NOW key. A
time-waiting fact carries a Watch need over [deadline, ∞); it wakes exactly when
now reaches its deadline, nothing accumulates, and durable state never depends
on now (replay with any now rebuilds it identically)."""
import os, sys, types
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from kernel import (Atom, NEED, Node, OFFER, Out, Router, SELF, WATCH, encode,
                    fact, now_need, now_of)

# A toy family: Watches now over [deadline, ∞), offers `fired` = the now it saw
# once the deadline passes. The observable is whether/when it fired.
def _toy_family():
    def project(f, ctx):
        n = now_of(ctx)
        deadline = int.from_bytes(next(a.value for a in f.atoms if a.role == b"d"), "big")
        if n is None or n < deadline: return Out(offers=())      # not due yet
        return Out(offers=(Atom(OFFER, b"fired", b"toy", SELF, n.to_bytes(8, "big")),))
    return types.SimpleNamespace(extract=lambda f: (False, False), project=project)

def _node():
    return Node(Router({b"toy": Router({b"t": _toy_family()}, depth=1)}))

def _toy(deadline_ms):                    # a fact waiting until deadline_ms
    from kernel import Exact
    return fact(b"toy.t", Atom(OFFER, b"d", b"toy", SELF, deadline_ms.to_bytes(8, "big")),
                now_need(deadline_ms))

def _fired(n, tid):
    return next((int.from_bytes(a.value, "big") for o, _, a in n.watched(b"fired", b"toy")
                 if o == tid), None)

def test_wakes_when_now_reaches_deadline():
    n = _node()
    tid = n.admit(encode(_toy(500))); n.turn(now=400)     # before the deadline
    assert _fired(n, tid) is None
    n.turn(now=450); assert _fired(n, tid) is None        # still early
    n.turn(now=500); assert _fired(n, tid) == 500         # deadline reached: wakes
    n.turn(now=900); assert _fired(n, tid) == 900         # later now re-projects

def test_now_does_not_accumulate():
    n = _node()
    n.admit(encode(_toy(100)))
    for t in range(100, 100000, 100): n.turn(now=t)       # many turns, advancing now
    # one clean-twin slot for NOW, no facts admitted for time
    assert len(n.facts) == 1                               # only the toy fact
    assert len(n.clean.get((b"now", b"clock"), [])) == 1  # exactly one now-offer

def test_replay_is_now_independent():
    # A durable fact must not depend on now: a time-waiting toy is volatile, so
    # replay (any now) rebuilds identical durable-derived state.
    n = _node()
    n.admit(encode(_toy(500))); n.turn(now=600); n.turn()
    assert n.durable == {}                                 # the toy is volatile

def test_turn_without_now_is_time_free():
    n = _node()
    tid = n.admit(encode(_toy(500)))
    n.turn(); n.turn(bound=64)                             # no now handed in
    assert _fired(n, tid) is None                          # never fires without a clock

if __name__ == "__main__":
    for t in (test_wakes_when_now_reaches_deadline, test_now_does_not_accumulate,
              test_replay_is_now_independent, test_turn_without_now_is_time_free):
        t(); print(f"ok  {t.__name__}")
    print("\nall clock tests passed")
