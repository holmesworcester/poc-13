"""Content scope: workspace data — messages, attachments, their deletion
vocabulary, reactions, and the retention window."""
from kernel import Router
from . import (file, file_slice, message, message_deletion, reaction,
               retention_policy)

SCOPE = Router({b"file": file, b"file_slice": file_slice, b"message": message,
                b"message_deletion": message_deletion, b"reaction": reaction,
                b"retention_policy": retention_policy}, depth=1)
