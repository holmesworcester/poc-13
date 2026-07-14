"""Content scope: workspace data — channels, messages, their deletion
vocabulary, reactions, and the retention window."""
from kernel import Router
from . import channel, message, message_deletion, reaction, retention_policy

SCOPE = Router({b"channel": channel, b"message": message,
                b"message_deletion": message_deletion,
                b"reaction": reaction, b"retention_policy": retention_policy}, depth=1)
