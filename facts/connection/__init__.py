"""Connection scope: peer sessions as facts. A durable, LocalOnly `request`
names an address to dial (and `close` retires it by suppression); a volatile
`hello` binds a session to an identity key at the gate; a volatile `connection`
records the live peer; and a `frame` bundle packs many facts into one wire frame.
Only request/close persist — the rest are ephemeral transport, never synced."""
from kernel import Router
from . import close, connection, frame, hello, request

SCOPE = Router({b"request": request, b"close": close, b"connection": connection,
                b"hello": hello, b"frame": frame}, depth=1)
