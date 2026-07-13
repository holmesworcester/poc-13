"""The reconciliation treap (facts.sync.index.Treap): a clamping-invariant, history-independent
range fingerprint. These pin the properties peers depend on — a range fingerprint is a
canonical function of the in-range SET alone (so two peers agree with an ordinary hash),
and every set-derived op matches a brute force over that set."""
import os, random, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from kernel import H
from facts.sync.index import Treap

R = random.Random(4242)
DOM = (b"", b"\xff" * 41)                                # below all / above all 40-byte keys

def gen(n, ts_bits=64):                                  # distinct (key, leaf-hash) pairs
    d = {}
    while len(d) < n:
        ts = R.getrandbits(ts_bits)
        k = (ts % (1 << 64)).to_bytes(8, "big") + R.getrandbits(256).to_bytes(32, "big")
        d[k] = R.getrandbits(256).to_bytes(32, "big")
    return list(d.items())

def build(items):
    t = Treap()
    for k, h in items: t.insert(k, h)
    return t

def fresh_fp(items, lo, hi):                             # reference: a FRESH treap over ONLY the in-range items
    return build([(k, h) for k, h in items if lo <= k < hi]).fp(*DOM)

def rand_range(keys):
    if keys and R.random() < 0.7:                        # bias toward bounds on/near real keys
        a, b = R.choice(keys), R.choice(keys)
    else:                                                # random bounds of varied length (incl. short ones)
        a = bytes(R.randrange(256) for _ in range(R.choice((1, 8, 40))))
        b = bytes(R.randrange(256) for _ in range(R.choice((1, 8, 40))))
    lo, hi = min(a, b), max(a, b)
    return lo, (hi + b"\x00" if lo == hi else hi)


def test_clamping_invariance():
    # fp(lo,hi) == fingerprint of a fresh treap built from just the in-range items,
    # regardless of what else the big treap holds — this IS cross-peer agreement.
    for n in (0, 1, 2, 8, 9, 200, 2000):
        items = gen(n); t = build(items); keys = sorted(k for k, _ in items)
        for _ in range(60):
            lo, hi = rand_range(keys)
            assert t.fp(lo, hi) == fresh_fp(items, lo, hi), (n, lo, hi)

def test_two_peers_agree_across_neighbours():
    # same in-range set + DIFFERENT out-of-range populations => identical range fingerprint.
    base = gen(400); keys = sorted(k for k, _ in base)
    lo, hi = keys[120], keys[300]
    inr = [(k, h) for k, h in base if lo <= k < hi]
    A = build(inr + [(k, h) for k, h in base if not (lo <= k < hi)])
    B = build(inr + [(k, h) for k, h in gen(600) if not (lo <= k < hi)])
    assert A.fp(lo, hi) == B.fp(lo, hi)

def test_history_independence():
    items = gen(1500)
    a = build(items); sh = items[:]; R.shuffle(sh); b = build(sh)
    assert a.fp(*DOM) == b.fp(*DOM)
    keys = sorted(k for k, _ in items)
    for _ in range(40):
        lo, hi = rand_range(keys)
        assert a.fp(lo, hi) == b.fp(lo, hi)

def test_same_ts_burst_balances_and_agrees():
    # every fact shares ts=0 (distinct fids): the search key is fid-ordered but the
    # priority (leaf hash) still balances, and clamping still agrees.
    items = [((0).to_bytes(8, "big") + R.getrandbits(256).to_bytes(32, "big"),
              R.getrandbits(256).to_bytes(32, "big")) for _ in range(1000)]
    t = build(items); keys = sorted(k for k, _ in items)
    for _ in range(40):
        lo, hi = rand_range(keys)
        assert t.fp(lo, hi) == fresh_fp(items, lo, hi)

def test_setops_match_bruteforce():
    for n in (0, 1, 8, 9, 500):
        items = gen(n); t = build(items); keys = sorted(k for k, _ in items)
        assert t.keys == keys
        for _ in range(50):
            lo, hi = rand_range(keys)
            ir = [k for k in keys if lo <= k < hi]
            assert t.count(lo, hi) == len(ir)
            assert t.small(lo, hi) == (len(ir) <= t.T)
            assert t.fids(lo, hi) == [k[8:] for k in ir]      # in key order
            if len(ir) > t.T:                                  # parts is only called on non-small ranges
                m = len(ir)
                want = [lo] + [ir[(p * m) // t.B] for p in range(1, t.B)] + [hi]
                want = [(a, b) for a, b in zip(want, want[1:]) if a != b]
                assert t.parts(lo, hi) == want
                assert all(a < b for a, b in t.parts(lo, hi))  # boundaries strictly increasing

def test_deletion_reconciles():
    items = gen(800); t = build(items)
    keys = [k for k, _ in items]; R.shuffle(keys)
    victims, kept = set(keys[:400]), {k: h for k, h in items if k not in set(keys[:400])}
    for k in list(victims): t.remove(k)
    assert t.keys == sorted(kept)
    ref = list(kept.items())
    for _ in range(40):
        lo, hi = rand_range(sorted(kept))
        assert t.fp(lo, hi) == fresh_fp(ref, lo, hi)
    for k in list(victims)[:50]: t.remove(k)                   # removing absent keys is a no-op
    assert t.keys == sorted(kept)

def test_edges():
    assert Treap().fp(*DOM) == Treap.EMPTY                     # empty tree -> empty label
    assert Treap().parts(*DOM) == [] and Treap().fids(*DOM) == []
    t = build(gen(5))                                          # count==0 range (all keys share ts=... below?)
    hi_only = (b"\xff" * 8 + b"\xff" * 32, b"\xff" * 41)       # a range above every key
    assert t.count(*hi_only) == 0
    assert t.parts(*hi_only) == []                             # no None bounds on an empty range
    assert t.fids(*hi_only) == []
    one = build(gen(1))
    assert one.count(*DOM) == 1 and one.fp(*DOM) != Treap.EMPTY

def test_degenerate_spine_no_crash():
    # priority == leaf hash; make it monotone in key order => a height-n spine. Honest
    # hashes never do this, but a range read must cost O(n) time, not overflow the stack.
    t = Treap()
    for i in range(3000):
        t.insert(i.to_bytes(8, "big") + b"\x00" * 32, i.to_bytes(32, "big"))
    assert t.count(*DOM) == 3000
    _ = t.fp(*DOM)                                             # must not raise RecursionError
    _ = t.fids(b"", (10).to_bytes(8, "big") + b"\x00" * 32)
    assert len(t.keys) == 3000
    mid = (1500).to_bytes(8, "big") + b"\x00" * 32
    assert t.fp(b"", mid) == build([(i.to_bytes(8, "big") + b"\x00" * 32, i.to_bytes(32, "big"))
                                    for i in range(1500)]).fp(*DOM)   # clamp still canonical on a spine

if __name__ == "__main__":
    for t in (test_clamping_invariance, test_two_peers_agree_across_neighbours,
              test_history_independence, test_same_ts_burst_balances_and_agrees,
              test_setops_match_bruteforce, test_deletion_reconciles, test_edges,
              test_degenerate_spine_no_crash):
        t(); print(f"ok  {t.__name__}")
    print("\nall tests passed")
