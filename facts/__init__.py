"""The root router — a table of contents that is itself the projector the
kernel runs. Scopes narrow to families; no policy lives at this level."""
from kernel import Router
from . import auth, content, outbox, sync

ROOT = Router({b"auth": auth.SCOPE, b"content": content.SCOPE,
               b"outbox": outbox.SCOPE, b"sync": sync.SCOPE})
