"""Sync scope: range-based set reconciliation (RBSR), decomposed into two volatile
families. `compare` bundles fingerprint/id claims over key ranges and descends by
equal-count split; a small range's id list that names ids the peer lacks is pulled
by one batched `need`, which ships those facts. Both are marker-free session state,
excluded from the leaves they reconcile, and target responses at the connection's
outbox key — so sync has no daemon reaction, only projectors on the one send path.
`index` holds the set they reconcile: the treap in the b"sync" register, fed by
validated `leaf@sync` provides emitted by replicating projectors and read via the
`summary` Gather."""
from kernel import Router
from . import index, compare, need, cadence

SCOPE = Router({b"compare": compare, b"need": need, b"cadence": cadence}, depth=1)
