"""Outbox scope: queues and effects as vocabulary. An intent offers at a
host-watched key; the performed effect is a fact the intent Watches.
Exactly-once is not a core property."""
from kernel import Router
from . import intent, performed

SCOPE = Router({b"intent": intent, b"performed": performed}, depth=1)
