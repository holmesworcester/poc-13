"""facts/connection/frame.py — the sealed throughput wrapper (poc-10's
frame_bundle). Established-connection traffic rides here: many length-framed
canonical fact bytes packed into one blob, then sealed under the session's
connection_secret with XChaCha20-Poly1305. The public wire form is
frame(version, connection_id, nonce, ciphertext); the connection id selects the
opening secret and is bound into the AEAD associated data, so a frame sealed for
one session can never open under another. A tampered frame opens to None and is
dropped whole; the daemon then unpacks the plaintext and admits each inner fact
through the NORMAL gate, so a corrupt inner is still a per-fact miss that never
poisons its siblings. Volatile, marker-free, never in leaves: pure transport.
Handshake facts (the sealed request and connection) travel as bare facts before
a secret exists — they carry their own X25519 envelopes; frames seal everything
after."""
from kernel import Out, _rd, fact, frame
from crypto import aead_open, aead_seal

TAG = b"connection.frame"
SC = b"conn"
TARGET = 48 << 10                        # bundle small facts to ~48 KiB; one oversized content
                                         # fact remains legal and gets a frame of its own
VERSION = 1
PURPOSE = b"tinyp2p connection frame v1"

# SHAPE — none: a frame is sealed onto the wire, never admitted as a fact.

# EXTRACT — volatile transport, never stored.
def extract(f): return False

# PROJECT — inert: a frame is unpacked by the daemon, never projected.
def project(f, ctx): return Out()

# COMMANDS — none: a frame is sealed onto the wire, not into the db.

# QUERIES — pure transforms over frame bytes; authority for nothing.
def pack_counts(items):                  # group into ~TARGET blobs, each with the inner count it holds
    out, cur, sz = [], [], 0
    for b in items:
        if cur and sz + len(b) > TARGET: out.append((frame(*cur), len(cur))); cur, sz = [], 0
        cur.append(b); sz += len(b)
    if cur: out.append((frame(*cur), len(cur)))
    return out

def seal(blob, cid, secret, nonce):      # one plaintext blob -> one sealed wire message
    aad = frame(PURPOSE, cid, nonce)
    return frame(bytes([VERSION]), cid, nonce, aead_seal(secret, nonce, aad, blob))

def open_frame(wire, secret):            # a sealed wire message -> its plaintext blob | None
    try:
        ver, i = _rd(wire, 0); cid, i = _rd(wire, i); nonce, i = _rd(wire, i); ct, i = _rd(wire, i)
    except Exception:
        return None
    if ver != bytes([VERSION]): return None
    return aead_open(secret, nonce, frame(PURPOSE, cid, nonce), ct)

def frame_cid(wire):                     # peek the connection id a sealed frame names
    try:
        _v, i = _rd(wire, 0); cid, _ = _rd(wire, i); return cid
    except Exception:
        return None

# CLI — no human surface.
CLI = {}
