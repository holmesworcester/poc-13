"""Sync scope: dependency-aware negentropy reconciliation as a fact family.
Compare frames are volatile, unshareable session state — excluded from the
leaves they reconcile; the daemon ships them explicitly, they never ride sync."""
from kernel import Router
from . import compare

SCOPE = Router({b"compare": compare}, depth=1)
