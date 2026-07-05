"""Sync scope: range-based set reconciliation (RBSR), decomposed into two volatile
families. `compare` bundles fingerprint/id claims over key ranges and descends by
equal-count split; a small range's id list that names ids the peer lacks is pulled
by one batched `need`, which ships those facts. Both are unshareable session state,
excluded from the leaves they reconcile, and target responses at the connection's
outbox key — so sync has no daemon reaction, only projectors on the one send path."""
from kernel import Router
from . import compare, need, cadence

SCOPE = Router({b"compare": compare, b"need": need, b"cadence": cadence}, depth=1)
