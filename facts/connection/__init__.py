"""Connection scope: the transport is a fact family. A sealed `request` is
first contact and the key-agreement opener; a `connection` is the sealed
handshake result carrying the per-session secret; `ephemeral_secret` holds the
handshake's X25519 keypair; `close` retires a session by suppression; and a
`frame` bundle packs many facts into one wire frame. Only request/ephemeral
persist locally — the rest are ephemeral transport, never synced."""
from kernel import Router
from . import close, connection, ephemeral_secret, fact_receipt, frame, request

SCOPE = Router({b"request": request, b"close": close, b"connection": connection,
                b"ephemeral_secret": ephemeral_secret, b"fact_receipt": fact_receipt,
                b"frame": frame}, depth=1)
