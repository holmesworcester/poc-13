"""Outbox scope: queues and effects as vocabulary. An intent offers at a
host-watched key; the performed effect is a fact the intent Watches; a `sent`
receipt is the volatile variant that retires session senders (any family may
offer at the outbox keys — the pump serves them all alike).
Exactly-once is not a core property."""
from kernel import Router
from . import intent, performed, sent

SCOPE = Router({b"intent": intent, b"performed": performed, b"sent": sent}, depth=1)
