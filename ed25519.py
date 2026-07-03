"""Pure-Python Ed25519 (RFC 8032), stdlib only: keygen, detached sign, verify.
Deterministic per RFC 8032 (SHA-512), affine Edwards math, recursive
scalarmult — slow (~ms/op) is fine because verification runs exactly once per
fact at first admission and never on replay. verify() never raises on attacker
bytes: malformed points or out-of-range scalars return False, never an error.
No external curve library, no ASN.1, no key format of our own — a 32-byte seed
is the secret, its 32-byte public key the identity, a 64-byte detached sig."""
import hashlib, os

P = 2**255 - 19                                        # field prime
L = 2**252 + 27742317777372353535851937790883648493   # group order
D = -121665 * pow(121666, P - 2, P) % P                # curve constant
I = pow(2, (P - 1) // 4, P)                            # sqrt(-1) mod P
_h = lambda m: hashlib.sha512(m).digest()
_inv = lambda x: pow(x, P - 2, P)

def _recover(y):                                       # the x for a given y
    xx = (y * y - 1) * _inv(D * y * y + 1) % P
    x = pow(xx, (P + 3) // 8, P)
    if (x * x - xx) % P: x = x * I % P
    return P - x if x & 1 else x

_By = 4 * _inv(5) % P
B = (_recover(_By), _By)                               # base point

def _add(Pt, Q):
    x1, y1 = Pt; x2, y2 = Q; t = D * x1 * x2 * y1 * y2 % P
    iv = _inv((1 - t * t) % P)                         # 1/((1+t)(1-t)): one inverse
    return ((x1 * y2 + x2 * y1) * (1 - t) * iv % P,
            (y1 * y2 + x1 * x2) * (1 + t) * iv % P)

def _mul(Pt, e):                                       # scalar multiply, e >= 0
    if not e: return (0, 1)
    Q = _mul(Pt, e >> 1); Q = _add(Q, Q)
    return _add(Q, Pt) if e & 1 else Q

def _oncurve(Pt):
    x, y = Pt
    return (-x * x + y * y - 1 - D * x * x * y * y) % P == 0

def _enc(Pt):
    x, y = Pt
    return (y | (x & 1) << 255).to_bytes(32, "little")

def _dec(s):                                           # raises on off-curve pt
    y = int.from_bytes(s, "little") & (1 << 255) - 1
    x = _recover(y)
    if x & 1 != s[31] >> 7: x = P - x
    if not _oncurve((x, y)): raise ValueError("off curve")
    return (x, y)

def _clamp(h):                                         # seed hash -> scalar a
    return int.from_bytes(h[:32], "little") & ((1 << 254) - 8) | 1 << 254

def keygen(seed=None):                                 # (sk, pk); sk is the seed
    sk = os.urandom(32) if seed is None else seed
    return sk, _enc(_mul(B, _clamp(_h(sk))))

def sign(sk, msg):
    h = _h(sk); a = _clamp(h); pk = _enc(_mul(B, a))
    r = int.from_bytes(_h(h[32:] + msg), "little") % L
    R = _enc(_mul(B, r))
    k = int.from_bytes(_h(R + pk + msg), "little")
    return R + ((r + k * a) % L).to_bytes(32, "little")

def verify(pk, msg, sig):
    if len(sig) != 64 or len(pk) != 32: return False
    S = int.from_bytes(sig[32:], "little")
    if S >= L: return False
    try: R, A = _dec(sig[:32]), _dec(pk)
    except Exception: return False
    k = int.from_bytes(_h(sig[:32] + pk + msg), "little")
    return _mul(B, S) == _add(R, _mul(A, k))
