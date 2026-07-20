"""TinyP2P crypto facade over PyNaCl/libsodium (poc-10: src/core/crypto.rs).

Primitives only — no protocol labels; every derivation label lives in the
fact family that owns it. The suite: BLAKE3-256 keyed hashing (matching
kernel.H) for deterministic derivations, X25519 for DH, HKDF-SHA256 (stdlib
hmac, RFC 5869) for key derivation, and XChaCha20-Poly1305 (24-byte nonce) as
the one AEAD. The open/dh sides never raise on attacker bytes: a bad point,
wrong tag, or truncated input is None, never an error — a projector treats
None as Invalid, not a crash."""
import hashlib, hmac, os

try:
    from blake3 import blake3 as _b3
    from nacl import bindings as _na
    from nacl.signing import SigningKey, VerifyKey
except ImportError as e:                               # PyNaCl + blake3
    raise ImportError("TinyP2P needs PyNaCl and blake3 (pip install pynacl blake3)") from e

from kernel import H, frame

X25519_KEY_INFO = b"tinyp2p x25519 xchacha20poly1305 key"


def keyed_hash(key32, domain, info):                   # deterministic derivation (BLAKE3 keyed)
    return _b3(frame(domain, info), key=key32).digest()


# --- Ed25519 (RFC 8032): the fact-authority signature ---------------------------
def ed25519_keygen(seed=None):                         # (sk, pk); sk is the 32-byte seed
    sk = os.urandom(32) if seed is None else seed
    return sk, bytes(SigningKey(sk).verify_key)


def ed25519_sign(sk, msg):                             # 64-byte detached signature
    return SigningKey(sk).sign(msg).signature


def ed25519_verify(pk, msg, sig):                      # never raises on attacker bytes
    try:
        VerifyKey(pk).verify(msg, sig)
        return True
    except Exception:
        return False


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


# --- BLAKE3-XOF keystream: equal-length, index-seekable stream encryption ---------
# A keyed BLAKE3 extendable output is a pseudo-random stream; XORing it encrypts
# and decrypts (its own inverse) without changing length, so ciphertext keeps the
# exact byte geometry a Bao tree commits to. `info` names the position, so each
# unit (a file slice index) draws an independent keystream from a fresh key — no
# nonce and no seeking. Integrity is NOT here: it comes from the signed Bao root
# the ciphertext authenticates against, so a flipped ciphertext bit fails
# verification rather than silently flipping a plaintext bit.
def stream_key(key32, info, length):
    return _b3(info, key=key32).digest(length=length)


def stream_xor(key32, info, data):
    ks = stream_key(key32, info, len(data))
    return (int.from_bytes(data, "big") ^ int.from_bytes(ks, "big")).to_bytes(len(data), "big")


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
