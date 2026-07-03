"""The root router — a table of contents that is itself the projector the
kernel runs. Scopes narrow to families; no policy lives at this level."""
from kernel import Router
from . import chat, outbox

ROOT = Router({b"chat": chat.SCOPE, b"outbox": outbox.SCOPE})
