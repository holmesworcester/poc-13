"""Chat scope: user-visible messages and their deletion vocabulary."""
from kernel import Router
from . import note, tombstone

SCOPE = Router({b"note": note, b"tombstone": tombstone}, depth=1)
