"""Ed25519 (RFC 8032) over PyNaCl/libsodium: keygen, detached sign, verify.
The API is the whole contract: a 32-byte seed is the secret, its 32-byte
public key the identity, a 64-byte detached sig — no ASN.1, no key format of
our own. verify() never raises on attacker bytes: malformed points, wrong
lengths, or out-of-range scalars return False, never an error. The RFC 8032
vectors in tests/test_sigs.py pin this wrapper to the old pure-Python module
it replaced."""
import os

try:
    from nacl.signing import SigningKey, VerifyKey
except ImportError as e:                               # the repo's one dependency
    raise ImportError("poc-13 needs PyNaCl (pip install pynacl)") from e


def keygen(seed=None):                                 # (sk, pk); sk is the seed
    sk = os.urandom(32) if seed is None else seed
    return sk, bytes(SigningKey(sk).verify_key)


def sign(sk, msg):
    return SigningKey(sk).sign(msg).signature


def verify(pk, msg, sig):
    try:
        VerifyKey(pk).verify(msg, sig)
        return True
    except Exception:
        return False
