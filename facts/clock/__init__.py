"""Clock scope: host time as facts. One family — volatile `tick` facts the
daemon admits while standing `alarm` offers demand them (see tick.py for the
retry idiom every awaiting family reuses)."""
from kernel import Router
from . import tick

SCOPE = Router({b"tick": tick}, depth=1)
