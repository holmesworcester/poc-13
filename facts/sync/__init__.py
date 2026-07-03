"""Sync scope: dependency-aware negentropy reconciliation as a fact family.
Compare frames are volatile, unshareable session state — excluded from the
leaves they reconcile; a `reply` stages a compare's answer at the outbox keys
for the daemon's pump, so even sync's own frames ride the one send path."""
from kernel import Router
from . import compare, reply

SCOPE = Router({b"compare": compare, b"reply": reply}, depth=1)
