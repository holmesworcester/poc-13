"""Store scope: demand over the durable index — hydration now; pins,
compaction, and the real (sqlite) index are later waves."""
from kernel import Router
from . import hydrate

SCOPE = Router({b"hydrate": hydrate}, depth=1)
