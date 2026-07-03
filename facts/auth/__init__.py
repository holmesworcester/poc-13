"""Auth scope: the workspace namespace root and its authority root (founder),
membership and admin grants, the user/device invite chain, the local signer
secret, and detached signatures over facts. Every shared authority fact climbs,
via a signer value-compare, to the founder root."""
from kernel import Router
from . import (admin, device, device_invite, endpoint, founder, invite_secret,
               local_signer_secret, signature, user, user_invite, workspace)

SCOPE = Router({b"workspace": workspace, b"founder": founder, b"user": user,
                b"user_invite": user_invite, b"admin": admin, b"device": device,
                b"device_invite": device_invite, b"signature": signature,
                b"endpoint": endpoint, b"invite_secret": invite_secret,
                b"local_signer_secret": local_signer_secret}, depth=1)
