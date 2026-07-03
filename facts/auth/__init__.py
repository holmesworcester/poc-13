"""Auth scope: the workspace authority root, membership, and admin grants."""
from kernel import Router
from . import admin, user, workspace

SCOPE = Router({b"workspace": workspace, b"user": user, b"admin": admin}, depth=1)
