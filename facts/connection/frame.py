"""facts/connection/frame.py — the sealed throughput wrapper (poc-10's
frame_bundle). Established-connection traffic rides here: many length-framed
canonical fact bytes packed into one blob, then sealed under the session's
connection_secret with XChaCha20-Poly1305. The public wire form is
frame(version, connection_id, nonce, ciphertext); the connection id selects the
opening secret and is bound into the AEAD associated data, so a frame sealed for
one session can never open under another. A tampered frame opens to None and is
dropped whole; the daemon then unpacks the plaintext and admits each inner fact
through the NORMAL gate, so a corrupt inner is still a per-fact miss that never
poisons its siblings. Volatile, unshareable, never in leaves: pure transport.
Handshake facts (the sealed request and connection) travel as bare facts before
a secret exists — they carry their own X25519 envelopes; frames seal everything
after."""
from kernel import Atom, OFFER, Out, SELF, _rd, encode, fact, frame
from crypto import aead_open, aead_seal

TAG = b"connection.frame"
SC = b"conn"
TARGET = 48 << 10                        # pack up to ~48 KiB of inner fact bytes per frame
VERSION = 1
PURPOSE = b"poc13 connection frame v1"

# SHAPE — the canonical atom set; a frame is opened by the daemon, never admitted.
def marker(cid):                         # a vestigial shape: frames live on the wire, not the db
    return fact(TAG, Atom(OFFER, b"frame", SC, SELF, cid))

# EXTRACT — content-pure: volatile + unshareable. Transport, never stored.
def extract(f): return False, False

# PROJECT — inert: a frame is unpacked by the daemon, never projected.
def project(f, ctx, sl): return Out()

# COMMANDS — none: a frame is sealed onto the wire, not into the db.

# QUERIES — pure transforms over frame bytes; authority for nothing.
def pack(items):                         # group fact frames into ~TARGET-sized plaintext blobs
    out, cur, sz = [], [], 0
    for b in items:
        if cur and sz + len(b) > TARGET: out.append(frame(*cur)); cur, sz = [], 0
        cur.append(b); sz += len(b)
    if cur: out.append(frame(*cur))
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

def unframe(blob):                       # a plaintext blob -> its inner fact byte-frames
    out, i = [], 0
    while i < len(blob): b, i = _rd(blob, i); out.append(b)
    return out

# CLI — no human surface.
CLI = {}
