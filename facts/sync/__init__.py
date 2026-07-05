"""Sync scope: dependency-aware negentropy reconciliation, decomposed into three
tiny volatile families. `compare` descends one key-prefix range (split on
fingerprint mismatch); at a resolved leaf it advertises what it holds as `have`
frames; a `have` the receiver lacks is answered with a `need`, which ships that
one fact by id. All three are unshareable session state, excluded from the leaves
they reconcile, and target their responses at the connection's outbox key — so
sync has no daemon reaction, only projectors emitting the one send path."""
from kernel import Router
from . import compare, have, need

SCOPE = Router({b"compare": compare, b"have": have, b"need": need}, depth=1)
