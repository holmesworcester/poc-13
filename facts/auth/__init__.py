"""Auth scope: the workspace authority root, membership, admin grants, the
local signer secret, and detached signatures over facts."""
from kernel import Router
from . import admin, local_signer_secret, signature, user, workspace

SCOPE = Router({b"workspace": workspace, b"user": user, b"admin": admin,
                b"signature": signature, b"local_signer_secret": local_signer_secret}, depth=1)
