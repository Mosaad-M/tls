# ============================================================================
# p256.mojo — NIST P-256 elliptic curve for TLS 1.3
# ============================================================================
# Provides:
#   p256_public_key(private_key)       → 65-byte uncompressed public key
#   p256_ecdh(private_key, peer_pub)   → 32-byte shared secret (x-coord)
#   p256_ecdsa_verify(pub, hash, r, s) → raises on invalid signature
#
# Uses BigInt arithmetic; field elements are BigInt in [0, p-1].
# Points use Jacobian coordinates (X:Y:Z) with Z=1 for affine input.
# ============================================================================

from crypto.bigint import (
    BigInt, bigint_zero, bigint_one, bigint_from_u64, bigint_from_bytes,
    bigint_to_bytes, bigint_is_zero, bigint_cmp, bigint_add, bigint_sub,
    bigint_mul, bigint_mod, bigint_modmul, bigint_modinv,
    bigint_bit_len, bigint_get_bit, bigint_cswap_inplace,
)
from crypto.hmac import hmac_sha256


# ============================================================================
# P-256 constants (returned as BigInt on demand)
# ============================================================================

def _p256_p() -> BigInt:
    """Field prime p = 2^256 - 2^224 + 2^192 + 2^96 - 1."""
    var b = List[UInt8](capacity=32)
    b.append(0xFF); b.append(0xFF); b.append(0xFF); b.append(0xFF)
    b.append(0x00); b.append(0x00); b.append(0x00); b.append(0x01)
    b.append(0x00); b.append(0x00); b.append(0x00); b.append(0x00)
    b.append(0x00); b.append(0x00); b.append(0x00); b.append(0x00)
    b.append(0x00); b.append(0x00); b.append(0x00); b.append(0x00)
    b.append(0xFF); b.append(0xFF); b.append(0xFF); b.append(0xFF)
    b.append(0xFF); b.append(0xFF); b.append(0xFF); b.append(0xFF)
    b.append(0xFF); b.append(0xFF); b.append(0xFF); b.append(0xFF)
    return bigint_from_bytes(b)


def _p256_n() -> BigInt:
    """Curve order n."""
    var b = List[UInt8](capacity=32)
    b.append(0xFF); b.append(0xFF); b.append(0xFF); b.append(0xFF)
    b.append(0x00); b.append(0x00); b.append(0x00); b.append(0x00)
    b.append(0xFF); b.append(0xFF); b.append(0xFF); b.append(0xFF)
    b.append(0xFF); b.append(0xFF); b.append(0xFF); b.append(0xFF)
    b.append(0xBC); b.append(0xE6); b.append(0xFA); b.append(0xAD)
    b.append(0xA7); b.append(0x17); b.append(0x9E); b.append(0x84)
    b.append(0xF3); b.append(0xB9); b.append(0xCA); b.append(0xC2)
    b.append(0xFC); b.append(0x63); b.append(0x25); b.append(0x51)
    return bigint_from_bytes(b)


def _p256_gx() -> BigInt:
    """Generator x-coordinate."""
    var b = List[UInt8](capacity=32)
    b.append(0x6B); b.append(0x17); b.append(0xD1); b.append(0xF2)
    b.append(0xE1); b.append(0x2C); b.append(0x42); b.append(0x47)
    b.append(0xF8); b.append(0xBC); b.append(0xE6); b.append(0xE5)
    b.append(0x63); b.append(0xA4); b.append(0x40); b.append(0xF2)
    b.append(0x77); b.append(0x03); b.append(0x7D); b.append(0x81)
    b.append(0x2D); b.append(0xEB); b.append(0x33); b.append(0xA0)
    b.append(0xF4); b.append(0xA1); b.append(0x39); b.append(0x45)
    b.append(0xD8); b.append(0x98); b.append(0xC2); b.append(0x96)
    return bigint_from_bytes(b)


def _p256_gy() -> BigInt:
    """Generator y-coordinate."""
    var b = List[UInt8](capacity=32)
    b.append(0x4F); b.append(0xE3); b.append(0x42); b.append(0xE2)
    b.append(0xFE); b.append(0x1A); b.append(0x7F); b.append(0x9B)
    b.append(0x8E); b.append(0xE7); b.append(0xEB); b.append(0x4A)
    b.append(0x7C); b.append(0x0F); b.append(0x9E); b.append(0x16)
    b.append(0x2B); b.append(0xCE); b.append(0x33); b.append(0x57)
    b.append(0x6B); b.append(0x31); b.append(0x5E); b.append(0xCE)
    b.append(0xCB); b.append(0xB6); b.append(0x40); b.append(0x68)
    b.append(0x37); b.append(0xBF); b.append(0x51); b.append(0xF5)
    return bigint_from_bytes(b)


# ============================================================================
# Field arithmetic — all operands in [0, p-1]
# ============================================================================

def _fadd(a: BigInt, b: BigInt, p: BigInt) -> BigInt:
    """(a + b) mod p. Single conditional subtraction (a,b < p)."""
    var r = bigint_add(a, b)
    if bigint_cmp(r, p) >= 0:
        r = bigint_sub(r, p)
    return r^


def _fsub(a: BigInt, b: BigInt, p: BigInt) -> BigInt:
    """(a - b) mod p. Single conditional addition."""
    if bigint_cmp(a, b) >= 0:
        return bigint_sub(a, b)
    return bigint_sub(bigint_add(a, p), b)


def _p256_nist_reduce(t: BigInt) -> BigInt:
    """Reduce a 512-bit product mod P-256 prime using NIST FIPS 186-4 D.1.2.3.

    t must be < p^2 (true for products of field elements).
    Words c[0..15] are the 32-bit LE limbs of t (c[0]=LSW).
    Result is in [0, p).
    """
    # Extract 16 words (zero-pad if t has fewer limbs)
    var nt = len(t.limbs)
    var c0:  Int64 = Int64(t.limbs[0])  if nt >  0 else 0
    var c1:  Int64 = Int64(t.limbs[1])  if nt >  1 else 0
    var c2:  Int64 = Int64(t.limbs[2])  if nt >  2 else 0
    var c3:  Int64 = Int64(t.limbs[3])  if nt >  3 else 0
    var c4:  Int64 = Int64(t.limbs[4])  if nt >  4 else 0
    var c5:  Int64 = Int64(t.limbs[5])  if nt >  5 else 0
    var c6:  Int64 = Int64(t.limbs[6])  if nt >  6 else 0
    var c7:  Int64 = Int64(t.limbs[7])  if nt >  7 else 0
    var c8:  Int64 = Int64(t.limbs[8])  if nt >  8 else 0
    var c9:  Int64 = Int64(t.limbs[9])  if nt >  9 else 0
    var c10: Int64 = Int64(t.limbs[10]) if nt > 10 else 0
    var c11: Int64 = Int64(t.limbs[11]) if nt > 11 else 0
    var c12: Int64 = Int64(t.limbs[12]) if nt > 12 else 0
    var c13: Int64 = Int64(t.limbs[13]) if nt > 13 else 0
    var c14: Int64 = Int64(t.limbs[14]) if nt > 14 else 0
    var c15: Int64 = Int64(t.limbs[15]) if nt > 15 else 0

    # NIST FIPS 186-4 App D.1.2.3 linear combination.
    # Derived from 2^{32k} mod p for k=8..15 (see implementation notes).
    # All Int64 accumulators — signed carries propagate correctly.
    var a0 = c0  + c8  + c9  - c11 - c12 - c13 - c14
    var a1 = c1  + c9  + c10 - c12 - c13 - c14 - c15
    var a2 = c2  + c10 + c11 - c13 - c14 - c15
    var a3 = c3  - c8  - c9  + 2*c11 + 2*c12 + c13 - c15
    var a4 = c4  - c9  - c10 + 2*c12 + 2*c13 + c14
    var a5 = c5  - c10 - c11 + 2*c13 + 2*c14 + c15
    var a6 = c6  - c8  - c9  + c13  + 3*c14 + 2*c15
    var a7 = c7  + c8  - c10 - c11  - c12   - c13 + 3*c15

    # First carry propagation — signed arithmetic, each word → [0, 2^32)
    var carry: Int64
    carry = a0 >> 32; a0 &= Int64(0xFFFFFFFF); a1 += carry
    carry = a1 >> 32; a1 &= Int64(0xFFFFFFFF); a2 += carry
    carry = a2 >> 32; a2 &= Int64(0xFFFFFFFF); a3 += carry
    carry = a3 >> 32; a3 &= Int64(0xFFFFFFFF); a4 += carry
    carry = a4 >> 32; a4 &= Int64(0xFFFFFFFF); a5 += carry
    carry = a5 >> 32; a5 &= Int64(0xFFFFFFFF); a6 += carry
    carry = a6 >> 32; a6 &= Int64(0xFFFFFFFF); a7 += carry
    var a8 = a7 >> 32; a7 &= Int64(0xFFFFFFFF)

    # Reduce a8 * 2^256: since 2^256 ≡ 2^224 − 2^192 − 2^96 + 1 mod p,
    # each unit of a8 contributes: +1 to word 0, −1 to word 3, −1 to word 6, +1 to word 7.
    a0 += a8
    a3 -= a8
    a6 -= a8
    a7 += a8

    # Second carry propagation
    carry = a0 >> 32; a0 &= Int64(0xFFFFFFFF); a1 += carry
    carry = a1 >> 32; a1 &= Int64(0xFFFFFFFF); a2 += carry
    carry = a2 >> 32; a2 &= Int64(0xFFFFFFFF); a3 += carry
    carry = a3 >> 32; a3 &= Int64(0xFFFFFFFF); a4 += carry
    carry = a4 >> 32; a4 &= Int64(0xFFFFFFFF); a5 += carry
    carry = a5 >> 32; a5 &= Int64(0xFFFFFFFF); a6 += carry
    carry = a6 >> 32; a6 &= Int64(0xFFFFFFFF); a7 += carry
    a8 = a7 >> 32; a7 &= Int64(0xFFFFFFFF)

    # a8 should now be 0 or at most 1 — apply one more time for safety
    a0 += a8
    a3 -= a8
    a6 -= a8
    a7 += a8

    # Third carry propagation — settle any last borrows
    carry = a0 >> 32; a0 &= Int64(0xFFFFFFFF); a1 += carry
    carry = a1 >> 32; a1 &= Int64(0xFFFFFFFF); a2 += carry
    carry = a2 >> 32; a2 &= Int64(0xFFFFFFFF); a3 += carry
    carry = a3 >> 32; a3 &= Int64(0xFFFFFFFF); a4 += carry
    carry = a4 >> 32; a4 &= Int64(0xFFFFFFFF); a5 += carry
    carry = a5 >> 32; a5 &= Int64(0xFFFFFFFF); a6 += carry
    carry = a6 >> 32; a6 &= Int64(0xFFFFFFFF); a7 += carry
    a7 &= Int64(0xFFFFFFFF)

    # Build BigInt from 8 words (trim leading zeros manually)
    var r = BigInt()
    r.limbs = List[UInt32](capacity=8)
    r.limbs.append(UInt32(a0))
    r.limbs.append(UInt32(a1))
    r.limbs.append(UInt32(a2))
    r.limbs.append(UInt32(a3))
    r.limbs.append(UInt32(a4))
    r.limbs.append(UInt32(a5))
    r.limbs.append(UInt32(a6))
    r.limbs.append(UInt32(a7))
    # Trim leading zeros (bigint_cmp compares by limb count first)
    while len(r.limbs) > 1 and r.limbs[len(r.limbs) - 1] == 0:
        _ = r.limbs.pop()

    # Conditional subtraction of p: result is in [0, 3p) after carry prop.
    var p = _p256_p()
    for _ in range(3):
        if bigint_cmp(r, p) >= 0:
            r = bigint_sub(r, p)
    return r^


def _p256_fmul_fast(a: BigInt, b: BigInt) -> BigInt:
    """(a * b) mod p256 using NIST fast reduction."""
    return _p256_nist_reduce(bigint_mul(a, b))


def _p256_fsq_fast(a: BigInt) -> BigInt:
    """a^2 mod p256 using NIST fast reduction."""
    return _p256_nist_reduce(bigint_mul(a, a.copy()))


def _fmul(a: BigInt, b: BigInt, p: BigInt) -> BigInt:
    """(a * b) mod p."""
    return _p256_fmul_fast(a, b)


def _fsq(a: BigInt, p: BigInt) -> BigInt:
    """a^2 mod p."""
    return _p256_fsq_fast(a)


def _fneg(a: BigInt, p: BigInt) -> BigInt:
    """-a mod p."""
    if bigint_is_zero(a):
        return bigint_zero()
    return bigint_sub(p, a)


def _finv(a: BigInt, p: BigInt) raises -> BigInt:
    """a^(-1) mod p using binary extended GCD (fast, safe for public Z coord)."""
    return bigint_modinv(a, p)


def _fk(a: BigInt, k: UInt64, p: BigInt) -> BigInt:
    """k*a mod p for small constant k using repeated doubling."""
    if k == 2:
        return _fadd(a, a.copy(), p)
    elif k == 3:
        var a2 = _fadd(a.copy(), a.copy(), p)
        return _fadd(a2, a, p)
    elif k == 4:
        var a2 = _fadd(a.copy(), a.copy(), p)
        return _fadd(a2, a2.copy(), p)
    elif k == 8:
        var a2 = _fadd(a.copy(), a.copy(), p)
        var a4 = _fadd(a2, a2.copy(), p)
        return _fadd(a4, a4.copy(), p)
    else:
        return bigint_modmul(a, bigint_from_u64(k), p)


# ============================================================================
# Jacobian point representation
# ============================================================================

struct P256Point(Copyable, Movable):
    var x: BigInt
    var y: BigInt
    var z: BigInt
    var inf: Bool  # True = point at infinity

    def __init__(out self):
        """Construct the point at infinity."""
        self.x = bigint_zero()
        self.y = bigint_zero()
        self.z = bigint_zero()
        self.inf = True

    def __copyinit__(out self, copy: Self):
        self.x = copy.x.copy()
        self.y = copy.y.copy()
        self.z = copy.z.copy()
        self.inf = copy.inf

    def __moveinit__(out self, deinit take: Self):
        self.x = take.x^
        self.y = take.y^
        self.z = take.z^
        self.inf = take.inf


def _from_affine(x: BigInt, y: BigInt) -> P256Point:
    """Jacobian point from affine (x, y) with Z=1."""
    var P = P256Point()
    P.x = x.copy()
    P.y = y.copy()
    P.z = bigint_one()
    P.inf = False
    return P^


def _to_affine(P: P256Point, p: BigInt) raises -> Tuple[BigInt, BigInt]:
    """Convert Jacobian to affine: (X/Z^2, Y/Z^3) mod p."""
    var zinv = _finv(P.z, p)
    var zinv2 = _fsq(zinv.copy(), p)
    var zinv3 = _fmul(zinv, zinv2.copy(), p)
    var ax = _fmul(P.x, zinv2, p)
    var ay = _fmul(P.y, zinv3, p)
    return (ax^, ay^)


# ============================================================================
# Point doubling — dbl-2001-b (optimized for a = -3)
# https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#doubling-dbl-2001-b
# Cost: 3M + 5S + 8add
# ============================================================================

def _pdbl(P: P256Point, p: BigInt) -> P256Point:
    if P.inf or bigint_is_zero(P.y):
        return P256Point()

    var delta = _fsq(P.z, p)                        # delta = Z1²
    var gamma = _fsq(P.y, p)                        # gamma = Y1²
    var beta  = _fmul(P.x, gamma.copy(), p)         # beta  = X1·gamma
    # alpha = 3·(X1−delta)·(X1+delta)
    var xmd   = _fsub(P.x, delta.copy(), p)
    var xpd   = _fadd(P.x, delta, p)
    var alpha = _fk(_fmul(xmd, xpd, p), 3, p)
    # X3 = alpha² − 8·beta
    var x3    = _fsub(_fsq(alpha.copy(), p), _fk(beta.copy(), 8, p), p)
    # Z3 = (Y1+Z1)² − gamma − delta  [delta reused below]
    var delta2 = _fsq(P.z, p)                       # recompute to avoid borrow conflict
    var gamma2 = gamma.copy()
    var ypz2  = _fsq(_fadd(P.y, P.z, p), p)
    var z3    = _fsub(_fsub(ypz2, gamma2, p), delta2, p)
    # Y3 = alpha·(4·beta − X3) − 8·gamma²
    var four_beta = _fk(beta, 4, p)
    var y3    = _fsub(
        _fmul(alpha, _fsub(four_beta, x3.copy(), p), p),
        _fk(_fsq(gamma, p), 8, p),
        p
    )

    var R = P256Point()
    R.x = x3^
    R.y = y3^
    R.z = z3^
    R.inf = False
    return R^


# ============================================================================
# Mixed addition (Jacobian P + affine Q) — madd-2007-bl
# https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#addition-madd-2007-bl
# Cost: 7M + 4S + 9add  (Z2 = 1 assumed)
# ============================================================================

def _pmadd(P: P256Point, qx: BigInt, qy: BigInt, p: BigInt) -> P256Point:
    """P + Q where Q is in affine coordinates."""
    if P.inf:
        return _from_affine(qx, qy)

    var z1z1 = _fsq(P.z, p)                            # Z1Z1 = Z1²
    var u2   = _fmul(qx, z1z1.copy(), p)               # U2   = X2·Z1Z1
    var s2   = _fmul(qy, _fmul(P.z, z1z1, p), p)      # S2   = Y2·Z1·Z1Z1
    var h    = _fsub(u2, P.x, p)                        # H    = U2 − X1
    var hh   = _fsq(h.copy(), p)                        # HH   = H²
    var i    = _fk(hh, 4, p)                            # I    = 4·HH
    var j    = _fmul(h.copy(), i.copy(), p)             # J    = H·I
    var r2   = _fk(_fsub(s2, P.y, p), 2, p)            # r    = 2·(S2 − Y1)
    var v    = _fmul(P.x, i, p)                         # V    = X1·I
    # X3 = r² − J − 2V
    var x3   = _fsub(_fsub(_fsq(r2.copy(), p), j.copy(), p), _fk(v.copy(), 2, p), p)
    # Y3 = r·(V − X3) − 2·Y1·J
    var y3   = _fsub(
        _fmul(r2, _fsub(v, x3.copy(), p), p),
        _fk(_fmul(P.y, j, p), 2, p),
        p
    )
    # Z3 = (Z1+H)² − Z1Z1 − HH
    var z1z1b = _fsq(P.z, p)                            # recompute Z1Z1
    var hhb   = _fsq(h, p)                              # recompute HH (h already moved? no, h is borrowed)
    # Wait — h was borrowed into hh, j, z3.  Let's recompute z3:
    # Actually h was passed as a borrow to _fsq and _fmul, so it's still valid.
    # But we already moved h^ to j above... no, it was passed as h.copy() to j.
    # Let me reorganize:
    var zplusH = _fadd(P.z, h, p)  # h still valid (borrowed)
    var z3     = _fsub(_fsub(_fsq(zplusH, p), z1z1b, p), hhb, p)

    # Special case: H = 0 means same X-coordinate
    if bigint_is_zero(h):
        # Same X: either P = Q (double) or P = -Q (infinity)
        if bigint_is_zero(r2):
            return _pdbl(_from_affine(qx, qy), p)
        else:
            return P256Point()

    var R = P256Point()
    R.x = x3^
    R.y = y3^
    R.z = z3^
    R.inf = False
    return R^


# ============================================================================
# Full Jacobian addition — add-2007-bl
# https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#addition-add-2007-bl
# Cost: 11M + 5S
# ============================================================================

def _padd(P: P256Point, Q: P256Point, p: BigInt) -> P256Point:
    """Full Jacobian + Jacobian point addition."""
    if P.inf:
        return Q.copy()
    if Q.inf:
        return P.copy()

    var z1z1 = _fsq(P.z, p)
    var z2z2 = _fsq(Q.z, p)
    var u1   = _fmul(P.x, z2z2.copy(), p)
    var u2   = _fmul(Q.x, z1z1.copy(), p)
    var s1   = _fmul(P.y, _fmul(Q.z, z2z2, p), p)
    var s2   = _fmul(Q.y, _fmul(P.z, z1z1, p), p)
    var h    = _fsub(u2, u1.copy(), p)
    var i    = _fsq(_fk(h.copy(), 2, p), p)
    var j    = _fmul(h.copy(), i.copy(), p)
    var r    = _fk(_fsub(s2, s1.copy(), p), 2, p)
    var v    = _fmul(u1, i, p)
    var x3   = _fsub(_fsub(_fsq(r.copy(), p), j.copy(), p), _fk(v.copy(), 2, p), p)
    var y3   = _fsub(
        _fmul(r, _fsub(v, x3.copy(), p), p),
        _fk(_fmul(s1, j, p), 2, p),
        p
    )
    var z3   = _fmul(
        _fsub(_fsub(_fsq(_fadd(P.z, Q.z, p), p), _fsq(P.z, p), p), _fsq(Q.z, p), p),
        h, p
    )

    if bigint_is_zero(h):
        if bigint_is_zero(r):
            return _pdbl(P, p)
        else:
            return P256Point()

    var R = P256Point()
    R.x = x3^
    R.y = y3^
    R.z = z3^
    R.inf = False
    return R^


# ============================================================================
# Scalar multiplication: Montgomery ladder (constant-time structure)
# ============================================================================

def _p256_point_cswap(mut a: P256Point, mut b: P256Point, swap: Int):
    """Conditionally swap two P-256 points in constant time (swap if swap==1)."""
    var mask: UInt32 = ~UInt32(0) if swap == 1 else UInt32(0)
    bigint_cswap_inplace(a.x, b.x, mask)
    bigint_cswap_inplace(a.y, b.y, mask)
    bigint_cswap_inplace(a.z, b.z, mask)
    var ai = UInt32(1) if a.inf else UInt32(0)
    var bi = UInt32(1) if b.inf else UInt32(0)
    var t = (ai ^ bi) & mask
    ai ^= t
    bi ^= t
    a.inf = (ai == 1)
    b.inf = (bi == 1)


def _scalar_mul_affine(scalar: BigInt, px: BigInt, py: BigInt, p: BigInt) -> P256Point:
    """Compute scalar * P where P = (px, py) in affine coords, using Montgomery ladder."""
    var r0 = P256Point()  # point at infinity
    var r1 = P256Point()
    r1.x = px.copy()
    r1.y = py.copy()
    r1.z = bigint_one()
    r1.inf = False
    var bits = bigint_bit_len(scalar)
    if bits == 0:
        return r0^
    for i in range(bits - 1, -1, -1):
        var b = Int(bigint_get_bit(scalar, i))
        _p256_point_cswap(r0, r1, b)
        var add_result = _padd(r0, r1, p)
        r0 = _pdbl(r0, p)
        r1 = add_result^
        _p256_point_cswap(r0, r1, b)
    return r0^


def _scalar_mul(scalar: BigInt, P: P256Point, p: BigInt) -> P256Point:
    """Compute scalar * P where P is in Jacobian coords, using Montgomery ladder."""
    var r0 = P256Point()  # point at infinity
    var r1 = P.copy()
    var bits = bigint_bit_len(scalar)
    if bits == 0:
        return r0^
    for i in range(bits - 1, -1, -1):
        var b = Int(bigint_get_bit(scalar, i))
        _p256_point_cswap(r0, r1, b)
        var add_result = _padd(r0, r1, p)
        r0 = _pdbl(r0, p)
        r1 = add_result^
        _p256_point_cswap(r0, r1, b)
    return r0^


# ============================================================================
# Point validation
# ============================================================================

def _point_on_curve(x: BigInt, y: BigInt, p: BigInt) -> Bool:
    """Check y² ≡ x³ − 3x + b (mod p)."""
    # b = 5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
    var bv = List[UInt8](capacity=32)
    bv.append(0x5A); bv.append(0xC6); bv.append(0x35); bv.append(0xD8)
    bv.append(0xAA); bv.append(0x3A); bv.append(0x93); bv.append(0xE7)
    bv.append(0xB3); bv.append(0xEB); bv.append(0xBD); bv.append(0x55)
    bv.append(0x76); bv.append(0x98); bv.append(0x86); bv.append(0xBC)
    bv.append(0x65); bv.append(0x1D); bv.append(0x06); bv.append(0xB0)
    bv.append(0xCC); bv.append(0x53); bv.append(0xB0); bv.append(0xF6)
    bv.append(0x3B); bv.append(0xCE); bv.append(0x3C); bv.append(0x3E)
    bv.append(0x27); bv.append(0xD2); bv.append(0x60); bv.append(0x4B)
    var b  = bigint_from_bytes(bv)
    var lhs = _fsq(y, p)                              # y²
    var x3  = _fmul(_fsq(x.copy(), p), x.copy(), p)  # x³
    var ax  = _fk(x, 3, p)                            # 3x  (a = -3)
    var rhs = _fadd(_fsub(x3, ax, p), b, p)           # x³ − 3x + b
    return bigint_cmp(lhs, rhs) == 0


# ============================================================================
# Parse uncompressed public key (65 bytes: 0x04 || X || Y)
# ============================================================================

def _parse_pub(pub: List[UInt8]) raises -> Tuple[BigInt, BigInt]:
    """Parse 65-byte uncompressed P-256 public key → (Qx, Qy)."""
    if len(pub) != 65 or pub[0] != 0x04:
        raise Error("p256: invalid public key format (need 65-byte uncompressed)")
    var qx_bytes = List[UInt8](capacity=32)
    var qy_bytes = List[UInt8](capacity=32)
    for i in range(32):
        qx_bytes.append(pub[1 + i])
        qy_bytes.append(pub[33 + i])
    return (bigint_from_bytes(qx_bytes), bigint_from_bytes(qy_bytes))


# ============================================================================
# Public API
# ============================================================================

def p256_public_key(private_key: List[UInt8]) raises -> List[UInt8]:
    """Derive 65-byte uncompressed P-256 public key from 32-byte private scalar."""
    if len(private_key) != 32:
        raise Error("p256: private key must be 32 bytes")
    var p = _p256_p()
    var n = _p256_n()
    var d = bigint_from_bytes(private_key)
    if bigint_is_zero(d) or bigint_cmp(d, n) >= 0:
        raise Error("p256: private key out of range")
    var gx = _p256_gx()
    var gy = _p256_gy()
    var Q  = _scalar_mul_affine(d, gx, gy, p)
    if Q.inf:
        raise Error("p256: degenerate public key")
    var affine = _to_affine(Q, p)
    var qx = affine[0].copy()
    var qy = affine[1].copy()
    var out = List[UInt8](capacity=65)
    out.append(0x04)
    var qx_bytes = bigint_to_bytes(qx, 32)
    var qy_bytes = bigint_to_bytes(qy, 32)
    for i in range(32):
        out.append(qx_bytes[i])
    for i in range(32):
        out.append(qy_bytes[i])
    return out^


def p256_ecdh(private_key: List[UInt8], peer_public_key: List[UInt8]) raises -> List[UInt8]:
    """Compute 32-byte P-256 ECDH shared secret (x-coordinate only)."""
    if len(private_key) != 32:
        raise Error("p256: private key must be 32 bytes")
    var p = _p256_p()
    var n = _p256_n()
    var d = bigint_from_bytes(private_key)
    if bigint_is_zero(d) or bigint_cmp(d, n) >= 0:
        raise Error("p256: private key out of range")
    var parsed = _parse_pub(peer_public_key)
    var qx = parsed[0].copy()
    var qy = parsed[1].copy()
    if not _point_on_curve(qx.copy(), qy.copy(), p):
        raise Error("p256: peer public key not on curve")
    var S = _scalar_mul_affine(d, qx, qy, p)
    if S.inf:
        raise Error("p256: degenerate ECDH result")
    var affine = _to_affine(S, p)
    return bigint_to_bytes(affine[0], 32)


def p256_ecdsa_verify(
    pub_key:  List[UInt8],   # 65-byte uncompressed P-256 public key
    msg_hash: List[UInt8],   # 32-byte message hash
    sig_r:    List[UInt8],   # 32-byte r component
    sig_s:    List[UInt8],   # 32-byte s component
) raises:
    """Verify P-256 ECDSA signature. Raises on invalid."""
    var p = _p256_p()
    var n = _p256_n()

    # Parse public key
    var parsed = _parse_pub(pub_key)
    var qx = parsed[0].copy()
    var qy = parsed[1].copy()
    if not _point_on_curve(qx.copy(), qy.copy(), p):
        raise Error("p256: public key not on curve")

    # Parse r, s
    var r = bigint_from_bytes(sig_r)
    var s = bigint_from_bytes(sig_s)
    var one = bigint_one()
    if bigint_cmp(r, one) < 0 or bigint_cmp(r, n) >= 0:
        raise Error("p256: r out of range")
    if bigint_cmp(s, one) < 0 or bigint_cmp(s, n) >= 0:
        raise Error("p256: s out of range")

    # e = hash interpreted as integer, reduced mod n
    var e = bigint_mod(bigint_from_bytes(msg_hash), n)

    # w = s^(-1) mod n
    var w = bigint_modinv(s, n)

    # u1 = e*w mod n, u2 = r*w mod n
    var u1 = bigint_modmul(e, w.copy(), n)
    var u2 = bigint_modmul(r.copy(), w, n)

    # R = u1*G + u2*Q
    var gx = _p256_gx()
    var gy = _p256_gy()
    var R1 = _scalar_mul_affine(u1, gx, gy, p)
    var R2 = _scalar_mul_affine(u2, qx, qy, p)
    var R  = _padd(R1, R2, p)
    if R.inf:
        raise Error("p256: ECDSA verify failed — R is infinity")

    # Convert R to affine and check x mod n == r
    var affine = _to_affine(R, p)
    var rx = bigint_mod(affine[0], n)
    if bigint_cmp(rx, r) != 0:
        raise Error("p256: ECDSA signature invalid")


def p256_ecdsa_sign(
    private_key:  List[UInt8],   # 32-byte big-endian scalar in [1, n-1]
    msg_hash:     List[UInt8],   # 32-byte message hash (e.g. SHA-256 digest)
    nonce_bytes:  List[UInt8],   # 32-byte caller-provided entropy
) raises -> Tuple[List[UInt8], List[UInt8]]:
    """Sign msg_hash with P-256 ECDSA. Returns (r[32], s[32]).

    Nonce k is derived deterministically:
      k_raw = HMAC-SHA-256(private_key, msg_hash || nonce_bytes)
      k     = bigint_from_bytes(k_raw) mod n   (clamped into [1, n-1])

    Low-s normalization is applied: if s > n/2 then s = n - s.
    This prevents signature malleability.

    Safety:
    - private_key is validated in [1, n-1] before any computation.
    - k is validated non-zero before use.
    - r and s are validated non-zero before returning.
    """
    if len(private_key) != 32:
        raise Error("p256_ecdsa_sign: private key must be 32 bytes")
    if len(msg_hash) != 32:
        raise Error("p256_ecdsa_sign: msg_hash must be 32 bytes")
    if len(nonce_bytes) != 32:
        raise Error("p256_ecdsa_sign: nonce_bytes must be 32 bytes")

    var p = _p256_p()
    var n = _p256_n()

    # Validate private key
    var d = bigint_from_bytes(private_key)
    if bigint_is_zero(d) or bigint_cmp(d, n) >= 0:
        raise Error("p256_ecdsa_sign: private key out of range [1, n-1]")

    # Derive nonce k: HMAC-SHA-256(private_key, msg_hash || nonce_bytes)
    var k_input = List[UInt8](capacity=64)
    for i in range(32):
        k_input.append(msg_hash[i])
    for i in range(32):
        k_input.append(nonce_bytes[i])
    var k_raw = hmac_sha256(private_key, k_input)
    var k_big = bigint_from_bytes(k_raw)
    var k = bigint_mod(k_big, n)
    if bigint_is_zero(k):
        raise Error("p256_ecdsa_sign: degenerate nonce k=0; retry with different nonce_bytes")

    # R = k * G; r = R.x mod n
    var gx = _p256_gx()
    var gy = _p256_gy()
    var R_pt = _scalar_mul_affine(k, gx, gy, p)
    if R_pt.inf:
        raise Error("p256_ecdsa_sign: degenerate R point; retry with different nonce_bytes")
    var R_affine = _to_affine(R_pt, p)
    var r = bigint_mod(R_affine[0], n)
    if bigint_is_zero(r):
        raise Error("p256_ecdsa_sign: degenerate r=0; retry with different nonce_bytes")

    # s = k^(-1) * (e + r*d) mod n
    var e = bigint_mod(bigint_from_bytes(msg_hash), n)
    var rd = bigint_modmul(r.copy(), d, n)
    var e_plus_rd = bigint_add(e, rd)
    if bigint_cmp(e_plus_rd, n) >= 0:
        e_plus_rd = bigint_sub(e_plus_rd, n)
    var k_inv = bigint_modinv(k, n)
    var s = bigint_modmul(k_inv, e_plus_rd, n)
    if bigint_is_zero(s):
        raise Error("p256_ecdsa_sign: degenerate s=0; retry with different nonce_bytes")

    # Low-s normalization: if s > n/2, replace s = n - s
    # n/2 computed as right-shift; compare s against it
    # Equivalent: if 2*s > n then s = n - s
    var s2 = bigint_add(s.copy(), s.copy())
    if bigint_cmp(s2, n) > 0:
        s = bigint_sub(n, s)

    return (bigint_to_bytes(r, 32), bigint_to_bytes(s, 32))
