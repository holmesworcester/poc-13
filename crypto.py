"""poc-13 crypto facade over PyNaCl/libsodium (poc-10: src/core/crypto.rs).

Primitives only — no protocol labels; every derivation label lives in the
fact family that owns it. The suite: BLAKE2b-256 keyed hashing (the repo's
BLAKE3 stand-in, matching kernel.H) for deterministic derivations, X25519 for
DH, HKDF-SHA256 (stdlib hmac, RFC 5869) for key derivation, and
XChaCha20-Poly1305 (24-byte nonce) as the one AEAD. The open/dh sides never
raise on attacker bytes: a bad point, wrong tag, or truncated input is None,
never an error — a projector treats None as Invalid, not a crash."""
import hashlib, hmac, os

try:
    from nacl import bindings as _na
except ImportError as e:                               # the repo's one dependency
    raise ImportError("poc-13 needs PyNaCl (pip install pynacl)") from e

from kernel import H, frame

X25519_KEY_INFO = b"poc13 x25519 xchacha20poly1305 key"


def keyed_hash(key32, domain, info):                   # deterministic derivation
    return hashlib.blake2b(frame(domain, info), digest_size=32, key=key32).digest()


# --- X25519 ---------------------------------------------------------------------
def x25519_keygen(seed=None):                          # (sk, pk); sk is the seed
    sk = os.urandom(32) if seed is None else seed
    return sk, _na.crypto_scalarmult_base(sk)


def x25519_pk(sk):
    return _na.crypto_scalarmult_base(sk)


def dh(sk, pk):                                        # shared secret | None
    if len(sk) != 32 or len(pk) != 32: return None     # the raw binding won't check
    try:
        return _na.crypto_scalarmult(sk, pk)           # low-order peer point: None
    except Exception:
        return None


# --- HKDF-SHA256 (RFC 5869, one 32-byte block) ------------------------------------
def hkdf_sha256(ikm, salt, info):
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    return hmac.new(prk, info + b"\x01", hashlib.sha256).digest()


# --- XChaCha20-Poly1305 AEAD ------------------------------------------------------
def aead_seal(key, nonce24, aad, pt):
    return _na.crypto_aead_xchacha20poly1305_ietf_encrypt(pt, aad, nonce24, key)


def aead_open(key, nonce24, aad, ct):                  # plaintext | None
    try:
        return _na.crypto_aead_xchacha20poly1305_ietf_decrypt(ct, aad, nonce24, key)
    except Exception:
        return None


# --- X25519 sealed box: DH -> HKDF -> AEAD ----------------------------------------
def seal_x25519(sk, peer_pk, purpose, aad, nonce24, pt):   # ciphertext | None
    s = dh(sk, peer_pk)
    return None if s is None else aead_seal(hkdf_sha256(s, purpose, X25519_KEY_INFO),
                                            nonce24, aad, pt)


def open_x25519(sk, peer_pk, purpose, aad, nonce24, ct):   # plaintext | None
    s = dh(sk, peer_pk)
    return None if s is None else aead_open(hkdf_sha256(s, purpose, X25519_KEY_INFO),
                                            nonce24, aad, ct)
