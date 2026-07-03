"""Auth scope: the workspace namespace-and-authority root (its fact embeds the
root key), local invite acceptance (the trust anchor gating workspace validity),
membership and admin grants, the user/device invite chain, the local signer
secret, the static endpoint keypair, and detached signatures over facts. Every
shared authority fact climbs, via a signer value-compare, to the workspace root."""
from kernel import Router
from . import (admin, device, device_invite, endpoint, invite_accepted,
               local_signer_secret, signature, user, user_invite, workspace)

SCOPE = Router({b"workspace": workspace, b"user": user, b"user_invite": user_invite,
                b"admin": admin, b"device": device, b"device_invite": device_invite,
                b"signature": signature, b"endpoint": endpoint,
                b"invite_accepted": invite_accepted,
                b"local_signer_secret": local_signer_secret}, depth=1)
