"""Outbox scope: the wire's staging queue as vocabulary. A send offers its
payload at the host-watched `send`/`ship` keys; the daemon flushes it and
reports the flush by presenting shipped@SELF (a kernel signal, like now), on
which the sender reaps. Any family may offer at the outbox keys — the pump
serves them all alike. The wire is best-effort; exactly-once is not a core
property."""
from kernel import Router
from . import send

SCOPE = Router({b"send": send}, depth=1)
