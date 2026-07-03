"""Crypto facade tests: standards vectors pin each primitive to its RFC, and
the open/dh sides prove they never raise on attacker bytes — a bad point,
wrong tag, or truncated input is None, never an error."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import crypto as c

# RFC 7748 section 5.2 X25519 vectors: (scalar, u-coordinate, output).
X25519_VECTORS = [
    ("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
     "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
     "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"),
    ("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d",
     "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493",
     "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957"),
]

# RFC 7748 section 6.1 Diffie-Hellman: alice/bob privates, publics, shared K.
ALICE_SK = bytes.fromhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
ALICE_PK = bytes.fromhex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
BOB_SK = bytes.fromhex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
BOB_PK = bytes.fromhex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
SHARED = bytes.fromhex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")

def test_x25519_rfc7748():
    for k_h, u_h, out_h in X25519_VECTORS:
        assert c.dh(bytes.fromhex(k_h), bytes.fromhex(u_h)) == bytes.fromhex(out_h)
    assert c.x25519_keygen(ALICE_SK) == (ALICE_SK, ALICE_PK)
    assert c.x25519_pk(BOB_SK) == BOB_PK
    assert c.dh(ALICE_SK, BOB_PK) == c.dh(BOB_SK, ALICE_PK) == SHARED
    assert c.dh(ALICE_SK, bytes(32)) is None          # low-order point: None, no raise
    assert c.dh(ALICE_SK, b"short") is None           # malformed point: None, no raise

# RFC 5869 appendix A test cases 1 and 2 (SHA-256); we take the first block.
def test_hkdf_rfc5869():
    okm = c.hkdf_sha256(b"\x0b" * 22, bytes.fromhex("000102030405060708090a0b0c"),
                        bytes.fromhex("f0f1f2f3f4f5f6f7f8f9"))
    assert okm == bytes.fromhex(
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf")
    okm2 = c.hkdf_sha256(bytes(range(0x00, 0x50)), bytes(range(0x60, 0xb0)),
                         bytes(range(0xb0, 0x100)))
    assert okm2 == bytes.fromhex(
        "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c")

# draft-irtf-cfrg-xchacha section A.3: XChaCha20-Poly1305 AEAD vector.
def test_xchacha20poly1305_vector():
    key = bytes.fromhex("808182838485868788898a8b8c8d8e8f"
                        "909192939495969798999a9b9c9d9e9f")
    nonce = bytes.fromhex("404142434445464748494a4b4c4d4e4f5051525354555657")
    aad = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")
    pt = (b"Ladies and Gentlemen of the class of '99: If I could offer you "
          b"only one tip for the future, sunscreen would be it.")
    ct = c.aead_seal(key, nonce, aad, pt)
    assert ct == bytes.fromhex(
        "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb"
        "731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452"
        "2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9"
        "21f9664c97637da9768812f615c68b13b52e"
        "c0875924c1c7987947deafd8780acf49")               # ciphertext ‖ tag
    assert c.aead_open(key, nonce, aad, ct) == pt

def test_aead_rejects_tamper_aad_nonce_key():
    key, nonce = os.urandom(32), os.urandom(24)
    ct = c.aead_seal(key, nonce, b"aad", b"payload")
    assert c.aead_open(key, nonce, b"aad", ct) == b"payload"
    bad = bytearray(ct); bad[0] ^= 1
    assert c.aead_open(key, nonce, b"aad", bytes(bad)) is None      # tampered ct
    assert c.aead_open(key, nonce, b"dad", ct) is None              # wrong aad
    assert c.aead_open(key, os.urandom(24), b"aad", ct) is None     # wrong nonce
    assert c.aead_open(os.urandom(32), nonce, b"aad", ct) is None   # wrong key
    assert c.aead_open(key, nonce, b"aad", ct[:15]) is None         # truncated: no raise

def test_sealed_box_roundtrip_and_symmetry():
    ask, apk = c.x25519_keygen()
    bsk, bpk = c.x25519_keygen()
    nonce = os.urandom(24)
    ct = c.seal_x25519(ask, bpk, b"purpose", b"hdr", nonce, b"secret plan")
    # X25519 symmetry: the recipient opens with its secret and the SENDER's pk.
    assert c.open_x25519(bsk, apk, b"purpose", b"hdr", nonce, ct) == b"secret plan"
    assert c.open_x25519(bsk, apk, b"other", b"hdr", nonce, ct) is None    # wrong purpose
    assert c.open_x25519(bsk, apk, b"purpose", b"hdX", nonce, ct) is None  # wrong aad
    csk, _ = c.x25519_keygen()
    assert c.open_x25519(csk, apk, b"purpose", b"hdr", nonce, ct) is None  # wrong key
    assert c.seal_x25519(ask, bytes(32), b"p", b"", nonce, b"x") is None   # bad peer point

def test_keyed_hash_binds_domain_and_info():
    k = os.urandom(32)
    a = c.keyed_hash(k, b"domain", b"info")
    assert a == c.keyed_hash(k, b"domain", b"info") and len(a) == 32
    assert a != c.keyed_hash(k, b"domain2", b"info")   # domain separates
    assert a != c.keyed_hash(k, b"domain", b"info2")   # info separates
    assert a != c.keyed_hash(k, b"do", b"maininfo")    # framing is injective
    assert a != c.keyed_hash(os.urandom(32), b"domain", b"info")

if __name__ == "__main__":
    for t in (test_x25519_rfc7748, test_hkdf_rfc5869, test_xchacha20poly1305_vector,
              test_aead_rejects_tamper_aad_nonce_key,
              test_sealed_box_roundtrip_and_symmetry,
              test_keyed_hash_binds_domain_and_info):
        t(); print(f"ok  {t.__name__}")
    print("\nall crypto tests passed")
