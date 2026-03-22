# ============================================================================
# p384.mojo — NIST P-384 elliptic curve for TLS 1.3 certificate verification
# ============================================================================
# Provides:
#   p384_ecdsa_verify(pub, hash, r, s) → raises on invalid signature
#
# Uses BigInt arithmetic; field elements are BigInt in [0, p-1].
# Points use Jacobian coordinates (X:Y:Z) with Z=1 for affine input.
#
# Note: P-384 key generation and ECDH are not implemented (not needed for
# certificate verification in TLS 1.3 — X25519 is used for key exchange).
# ============================================================================

from crypto.bigint import (
    BigInt, bigint_zero, bigint_one, bigint_from_u64, bigint_from_bytes,
    bigint_to_bytes, bigint_is_zero, bigint_cmp, bigint_add, bigint_sub,
    bigint_mul, bigint_mod, bigint_modmul, bigint_modinv,
    bigint_bit_len, bigint_get_bit, bigint_cswap_inplace,
)


# ============================================================================
# P-384 constants (returned as BigInt on demand)
# ============================================================================

def _p384_p() -> BigInt:
    """Field prime p = 2^384 − 2^128 − 2^96 + 2^32 − 1."""
    var b = List[UInt8](capacity=48)
    b.append(0xFF); b.append(0xFF); b.append(0xFF); b.append(0xFF)
    b.append(0xFF); b.append(0xFF); b.append(0xFF); b.append(0xFF)
    b.append(0xFF); b.append(0xFF); b.append(0xFF); b.append(0xFF)
    b.append(0xFF); b.append(0xFF); b.append(0xFF); b.append(0xFF)
    b.append(0xFF); b.append(0xFF); b.append(0xFF); b.append(0xFF)
    b.append(0xFF); b.append(0xFF); b.append(0xFF); b.append(0xFF)
    b.append(0xFF); b.append(0xFF); b.append(0xFF); b.append(0xFF)
    b.append(0xFF); b.append(0xFF); b.append(0xFF); b.append(0xFE)
    b.append(0xFF); b.append(0xFF); b.append(0xFF); b.append(0xFF)
    b.append(0x00); b.append(0x00); b.append(0x00); b.append(0x00)
    b.append(0x00); b.append(0x00); b.append(0x00); b.append(0x00)
    b.append(0xFF); b.append(0xFF); b.append(0xFF); b.append(0xFF)
    return bigint_from_bytes(b)


def _p384_n() -> BigInt:
    """Curve order n."""
    var b = List[UInt8](capacity=48)
    b.append(0xFF); b.append(0xFF); b.append(0xFF); b.append(0xFF)
    b.append(0xFF); b.append(0xFF); b.append(0xFF); b.append(0xFF)
    b.append(0xFF); b.append(0xFF); b.append(0xFF); b.append(0xFF)
    b.append(0xFF); b.append(0xFF); b.append(0xFF); b.append(0xFF)
    b.append(0xFF); b.append(0xFF); b.append(0xFF); b.append(0xFF)
    b.append(0xFF); b.append(0xFF); b.append(0xFF); b.append(0xFF)
    b.append(0xC7); b.append(0x63); b.append(0x4D); b.append(0x81)
    b.append(0xF4); b.append(0x37); b.append(0x2D); b.append(0xDF)
    b.append(0x58); b.append(0x1A); b.append(0x0D); b.append(0xB2)
    b.append(0x48); b.append(0xB0); b.append(0xA7); b.append(0x7A)
    b.append(0xEC); b.append(0xEC); b.append(0x19); b.append(0x6A)
    b.append(0xCC); b.append(0xC5); b.append(0x29); b.append(0x73)
    return bigint_from_bytes(b)


def _p384_gx() -> BigInt:
    """Generator x-coordinate."""
    var b = List[UInt8](capacity=48)
    b.append(0xAA); b.append(0x87); b.append(0xCA); b.append(0x22)
    b.append(0xBE); b.append(0x8B); b.append(0x05); b.append(0x37)
    b.append(0x8E); b.append(0xB1); b.append(0xC7); b.append(0x1E)
    b.append(0xF3); b.append(0x20); b.append(0xAD); b.append(0x74)
    b.append(0x6E); b.append(0x1D); b.append(0x3B); b.append(0x62)
    b.append(0x8B); b.append(0xA7); b.append(0x9B); b.append(0x98)
    b.append(0x59); b.append(0xF7); b.append(0x41); b.append(0xE0)
    b.append(0x82); b.append(0x54); b.append(0x2A); b.append(0x38)
    b.append(0x55); b.append(0x02); b.append(0xF2); b.append(0x5D)
    b.append(0xBF); b.append(0x55); b.append(0x29); b.append(0x6C)
    b.append(0x3A); b.append(0x54); b.append(0x5E); b.append(0x38)
    b.append(0x72); b.append(0x76); b.append(0x0A); b.append(0xB7)
    return bigint_from_bytes(b)


def _p384_gy() -> BigInt:
    """Generator y-coordinate."""
    var b = List[UInt8](capacity=48)
    b.append(0x36); b.append(0x17); b.append(0xDE); b.append(0x4A)
    b.append(0x96); b.append(0x26); b.append(0x2C); b.append(0x6F)
    b.append(0x5D); b.append(0x9E); b.append(0x98); b.append(0xBF)
    b.append(0x92); b.append(0x92); b.append(0xDC); b.append(0x29)
    b.append(0xF8); b.append(0xF4); b.append(0x1D); b.append(0xBD)
    b.append(0x28); b.append(0x9A); b.append(0x14); b.append(0x7C)
    b.append(0xE9); b.append(0xDA); b.append(0x31); b.append(0x13)
    b.append(0xB5); b.append(0xF0); b.append(0xB8); b.append(0xC0)
    b.append(0x0A); b.append(0x60); b.append(0xB1); b.append(0xCE)
    b.append(0x1D); b.append(0x7E); b.append(0x81); b.append(0x9D)
    b.append(0x7A); b.append(0x43); b.append(0x1D); b.append(0x7C)
    b.append(0x90); b.append(0xEA); b.append(0x0E); b.append(0x5F)
    return bigint_from_bytes(b)


# ============================================================================
# Field arithmetic — all operands in [0, p-1]
# ============================================================================

def _p384_fadd(a: BigInt, b: BigInt, p: BigInt) -> BigInt:
    """(a + b) mod p."""
    var r = bigint_add(a, b)
    if bigint_cmp(r, p) >= 0:
        r = bigint_sub(r, p)
    return r^


def _p384_fsub(a: BigInt, b: BigInt, p: BigInt) -> BigInt:
    """(a - b) mod p."""
    if bigint_cmp(a, b) >= 0:
        return bigint_sub(a, b)
    return bigint_sub(bigint_add(a, p), b)


def _p384_nist_reduce(t: BigInt) -> BigInt:
    """Reduce a 768-bit product mod P-384 prime using NIST FIPS 186-4 D.1.2.4.

    t must be < p^2 (true for products of field elements).
    Words c[0..23] are the 32-bit LE limbs of t (c[0]=LSW).
    Result is in [0, p).

    Per-word linear combination derived from 2^{32k} mod p for k=12..23:
      2^384 ≡ 2^128 + 2^96 - 2^32 + 1  (mod p)
    """
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
    var c16: Int64 = Int64(t.limbs[16]) if nt > 16 else 0
    var c17: Int64 = Int64(t.limbs[17]) if nt > 17 else 0
    var c18: Int64 = Int64(t.limbs[18]) if nt > 18 else 0
    var c19: Int64 = Int64(t.limbs[19]) if nt > 19 else 0
    var c20: Int64 = Int64(t.limbs[20]) if nt > 20 else 0
    var c21: Int64 = Int64(t.limbs[21]) if nt > 21 else 0
    var c22: Int64 = Int64(t.limbs[22]) if nt > 22 else 0
    var c23: Int64 = Int64(t.limbs[23]) if nt > 23 else 0

    # Signed 12-word accumulators.  Coefficients from r[k] = 2^{32k} mod p:
    var a0  = c0  + c12 + c20 + c21 - c23
    var a1  = c1  - c12 + c13 - c20 + c22 + c23
    var a2  = c2  - c13 + c14 - c21 + c23
    var a3  = c3  + c12 - c14 + c15 + c20 + c21 - c22 - c23
    var a4  = c4  + c12 + c13 - c15 + c16 + c20 + 2*c21 + c22 - 2*c23
    var a5  = c5  + c13 + c14 - c16 + c17 + c21 + 2*c22 + c23
    var a6  = c6  + c14 + c15 - c17 + c18 + c22 + 2*c23
    var a7  = c7  + c15 + c16 - c18 + c19 + c23
    var a8  = c8  + c16 + c17 - c19 + c20
    var a9  = c9  + c17 + c18 - c20 + c21
    var a10 = c10 + c18 + c19 - c21 + c22
    var a11 = c11 + c19 + c20 - c22 + c23

    # First carry propagation
    var carry: Int64
    carry = a0  >> 32; a0  &= Int64(0xFFFFFFFF); a1  += carry
    carry = a1  >> 32; a1  &= Int64(0xFFFFFFFF); a2  += carry
    carry = a2  >> 32; a2  &= Int64(0xFFFFFFFF); a3  += carry
    carry = a3  >> 32; a3  &= Int64(0xFFFFFFFF); a4  += carry
    carry = a4  >> 32; a4  &= Int64(0xFFFFFFFF); a5  += carry
    carry = a5  >> 32; a5  &= Int64(0xFFFFFFFF); a6  += carry
    carry = a6  >> 32; a6  &= Int64(0xFFFFFFFF); a7  += carry
    carry = a7  >> 32; a7  &= Int64(0xFFFFFFFF); a8  += carry
    carry = a8  >> 32; a8  &= Int64(0xFFFFFFFF); a9  += carry
    carry = a9  >> 32; a9  &= Int64(0xFFFFFFFF); a10 += carry
    carry = a10 >> 32; a10 &= Int64(0xFFFFFFFF); a11 += carry
    var a12 = a11 >> 32; a11 &= Int64(0xFFFFFFFF)

    # Reduce a12 * 2^384: 2^384 ≡ 2^128 + 2^96 - 2^32 + 1 mod p
    # In 12-word LE: word0=+1, word1=-1, word3=+1, word4=+1
    a0  += a12
    a1  -= a12
    a3  += a12
    a4  += a12

    # Second carry propagation
    carry = a0  >> 32; a0  &= Int64(0xFFFFFFFF); a1  += carry
    carry = a1  >> 32; a1  &= Int64(0xFFFFFFFF); a2  += carry
    carry = a2  >> 32; a2  &= Int64(0xFFFFFFFF); a3  += carry
    carry = a3  >> 32; a3  &= Int64(0xFFFFFFFF); a4  += carry
    carry = a4  >> 32; a4  &= Int64(0xFFFFFFFF); a5  += carry
    carry = a5  >> 32; a5  &= Int64(0xFFFFFFFF); a6  += carry
    carry = a6  >> 32; a6  &= Int64(0xFFFFFFFF); a7  += carry
    carry = a7  >> 32; a7  &= Int64(0xFFFFFFFF); a8  += carry
    carry = a8  >> 32; a8  &= Int64(0xFFFFFFFF); a9  += carry
    carry = a9  >> 32; a9  &= Int64(0xFFFFFFFF); a10 += carry
    carry = a10 >> 32; a10 &= Int64(0xFFFFFFFF); a11 += carry
    a12 = a11 >> 32; a11 &= Int64(0xFFFFFFFF)

    # a12 should be 0 or 1 — one more reduction for safety
    a0  += a12
    a1  -= a12
    a3  += a12
    a4  += a12

    # Third carry propagation
    carry = a0  >> 32; a0  &= Int64(0xFFFFFFFF); a1  += carry
    carry = a1  >> 32; a1  &= Int64(0xFFFFFFFF); a2  += carry
    carry = a2  >> 32; a2  &= Int64(0xFFFFFFFF); a3  += carry
    carry = a3  >> 32; a3  &= Int64(0xFFFFFFFF); a4  += carry
    carry = a4  >> 32; a4  &= Int64(0xFFFFFFFF); a5  += carry
    carry = a5  >> 32; a5  &= Int64(0xFFFFFFFF); a6  += carry
    carry = a6  >> 32; a6  &= Int64(0xFFFFFFFF); a7  += carry
    carry = a7  >> 32; a7  &= Int64(0xFFFFFFFF); a8  += carry
    carry = a8  >> 32; a8  &= Int64(0xFFFFFFFF); a9  += carry
    carry = a9  >> 32; a9  &= Int64(0xFFFFFFFF); a10 += carry
    carry = a10 >> 32; a10 &= Int64(0xFFFFFFFF); a11 += carry
    a11 &= Int64(0xFFFFFFFF)

    # Build 12-limb BigInt, trim leading zeros
    var r = BigInt()
    r.limbs = List[UInt32](capacity=12)
    r.limbs.append(UInt32(a0));  r.limbs.append(UInt32(a1))
    r.limbs.append(UInt32(a2));  r.limbs.append(UInt32(a3))
    r.limbs.append(UInt32(a4));  r.limbs.append(UInt32(a5))
    r.limbs.append(UInt32(a6));  r.limbs.append(UInt32(a7))
    r.limbs.append(UInt32(a8));  r.limbs.append(UInt32(a9))
    r.limbs.append(UInt32(a10)); r.limbs.append(UInt32(a11))
    while len(r.limbs) > 1 and r.limbs[len(r.limbs) - 1] == 0:
        _ = r.limbs.pop()

    var p = _p384_p()
    for _ in range(3):
        if bigint_cmp(r, p) >= 0:
            r = bigint_sub(r, p)
    return r^


def _p384_fmul_fast(a: BigInt, b: BigInt) -> BigInt:
    """(a * b) mod p384 using NIST fast reduction."""
    return _p384_nist_reduce(bigint_mul(a, b))


def _p384_fsq_fast(a: BigInt) -> BigInt:
    """a^2 mod p384 using NIST fast reduction."""
    return _p384_nist_reduce(bigint_mul(a, a.copy()))


def _p384_fmul(a: BigInt, b: BigInt, p: BigInt) -> BigInt:
    """(a * b) mod p."""
    return _p384_fmul_fast(a, b)


def _p384_fsq(a: BigInt, p: BigInt) -> BigInt:
    """a^2 mod p."""
    return _p384_fsq_fast(a)


def _p384_fk(a: BigInt, k: UInt64, p: BigInt) -> BigInt:
    """k*a mod p for small constant k using repeated doubling."""
    if k == 2:
        return _p384_fadd(a, a.copy(), p)
    elif k == 3:
        var a2 = _p384_fadd(a.copy(), a.copy(), p)
        return _p384_fadd(a2, a, p)
    elif k == 4:
        var a2 = _p384_fadd(a.copy(), a.copy(), p)
        return _p384_fadd(a2, a2.copy(), p)
    elif k == 8:
        var a2 = _p384_fadd(a.copy(), a.copy(), p)
        var a4 = _p384_fadd(a2, a2.copy(), p)
        return _p384_fadd(a4, a4.copy(), p)
    else:
        return bigint_modmul(a, bigint_from_u64(k), p)


def _p384_finv(a: BigInt, p: BigInt) raises -> BigInt:
    """a^(-1) mod p using binary extended GCD (fast, safe for public Z coord)."""
    return bigint_modinv(a, p)


# ============================================================================
# Jacobian point representation
# ============================================================================

struct P384Point(Copyable, Movable):
    var x: BigInt
    var y: BigInt
    var z: BigInt
    var inf: Bool

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


def _p384_from_affine(x: BigInt, y: BigInt) -> P384Point:
    """Jacobian point from affine (x, y) with Z=1."""
    var P = P384Point()
    P.x = x.copy()
    P.y = y.copy()
    P.z = bigint_one()
    P.inf = False
    return P^


def _p384_to_affine(P: P384Point, p: BigInt) raises -> Tuple[BigInt, BigInt]:
    """Convert Jacobian to affine: (X/Z^2, Y/Z^3) mod p."""
    var zinv  = _p384_finv(P.z, p)
    var zinv2 = _p384_fsq(zinv.copy(), p)
    var zinv3 = _p384_fmul(zinv, zinv2.copy(), p)
    var ax    = _p384_fmul(P.x, zinv2, p)
    var ay    = _p384_fmul(P.y, zinv3, p)
    return (ax^, ay^)


# ============================================================================
# Point doubling — dbl-2001-b (optimized for a = -3)
# P-384 also has a = -3, so the same formula applies.
# ============================================================================

def _p384_pdbl(P: P384Point, p: BigInt) -> P384Point:
    if P.inf or bigint_is_zero(P.y):
        return P384Point()

    var delta = _p384_fsq(P.z, p)
    var gamma = _p384_fsq(P.y, p)
    var beta  = _p384_fmul(P.x, gamma.copy(), p)
    var xmd   = _p384_fsub(P.x, delta.copy(), p)
    var xpd   = _p384_fadd(P.x, delta, p)
    var alpha = _p384_fk(_p384_fmul(xmd, xpd, p), 3, p)
    var x3    = _p384_fsub(_p384_fsq(alpha.copy(), p), _p384_fk(beta.copy(), 8, p), p)
    var delta2 = _p384_fsq(P.z, p)
    var gamma2 = gamma.copy()
    var ypz2  = _p384_fsq(_p384_fadd(P.y, P.z, p), p)
    var z3    = _p384_fsub(_p384_fsub(ypz2, gamma2, p), delta2, p)
    var four_beta = _p384_fk(beta, 4, p)
    var y3    = _p384_fsub(
        _p384_fmul(alpha, _p384_fsub(four_beta, x3.copy(), p), p),
        _p384_fk(_p384_fsq(gamma, p), 8, p),
        p
    )

    var R = P384Point()
    R.x = x3^
    R.y = y3^
    R.z = z3^
    R.inf = False
    return R^


# ============================================================================
# Mixed addition (Jacobian P + affine Q) — madd-2007-bl
# ============================================================================

def _p384_pmadd(P: P384Point, qx: BigInt, qy: BigInt, p: BigInt) -> P384Point:
    """P + Q where Q is in affine coordinates."""
    if P.inf:
        return _p384_from_affine(qx, qy)

    var z1z1 = _p384_fsq(P.z, p)
    var u2   = _p384_fmul(qx, z1z1.copy(), p)
    var s2   = _p384_fmul(qy, _p384_fmul(P.z, z1z1, p), p)
    var h    = _p384_fsub(u2, P.x, p)
    var hh   = _p384_fsq(h.copy(), p)
    var i    = _p384_fk(hh, 4, p)
    var j    = _p384_fmul(h.copy(), i.copy(), p)
    var r2   = _p384_fk(_p384_fsub(s2, P.y, p), 2, p)
    var v    = _p384_fmul(P.x, i, p)
    var x3   = _p384_fsub(_p384_fsub(_p384_fsq(r2.copy(), p), j.copy(), p), _p384_fk(v.copy(), 2, p), p)
    var y3   = _p384_fsub(
        _p384_fmul(r2, _p384_fsub(v, x3.copy(), p), p),
        _p384_fk(_p384_fmul(P.y, j, p), 2, p),
        p
    )
    var z1z1b = _p384_fsq(P.z, p)
    var hhb   = _p384_fsq(h, p)
    var zplusH = _p384_fadd(P.z, h, p)
    var z3     = _p384_fsub(_p384_fsub(_p384_fsq(zplusH, p), z1z1b, p), hhb, p)

    if bigint_is_zero(h):
        if bigint_is_zero(r2):
            return _p384_pdbl(_p384_from_affine(qx, qy), p)
        else:
            return P384Point()

    var R = P384Point()
    R.x = x3^
    R.y = y3^
    R.z = z3^
    R.inf = False
    return R^


# ============================================================================
# Full Jacobian addition
# ============================================================================

def _p384_padd(P: P384Point, Q: P384Point, p: BigInt) -> P384Point:
    """Full Jacobian + Jacobian point addition."""
    if P.inf:
        return Q.copy()
    if Q.inf:
        return P.copy()

    var z1z1 = _p384_fsq(P.z, p)
    var z2z2 = _p384_fsq(Q.z, p)
    var u1   = _p384_fmul(P.x, z2z2.copy(), p)
    var u2   = _p384_fmul(Q.x, z1z1.copy(), p)
    var s1   = _p384_fmul(P.y, _p384_fmul(Q.z, z2z2, p), p)
    var s2   = _p384_fmul(Q.y, _p384_fmul(P.z, z1z1, p), p)
    var h    = _p384_fsub(u2, u1.copy(), p)
    var i    = _p384_fsq(_p384_fk(h.copy(), 2, p), p)
    var j    = _p384_fmul(h.copy(), i.copy(), p)
    var r    = _p384_fk(_p384_fsub(s2, s1.copy(), p), 2, p)
    var v    = _p384_fmul(u1, i, p)
    var x3   = _p384_fsub(_p384_fsub(_p384_fsq(r.copy(), p), j.copy(), p), _p384_fk(v.copy(), 2, p), p)
    var y3   = _p384_fsub(
        _p384_fmul(r, _p384_fsub(v, x3.copy(), p), p),
        _p384_fk(_p384_fmul(s1, j, p), 2, p),
        p
    )
    var z3   = _p384_fmul(
        _p384_fsub(_p384_fsub(_p384_fsq(_p384_fadd(P.z, Q.z, p), p), _p384_fsq(P.z, p), p), _p384_fsq(Q.z, p), p),
        h, p
    )

    if bigint_is_zero(h):
        if bigint_is_zero(r):
            return _p384_pdbl(P, p)
        else:
            return P384Point()

    var R = P384Point()
    R.x = x3^
    R.y = y3^
    R.z = z3^
    R.inf = False
    return R^


# ============================================================================
# Scalar multiplication: Montgomery ladder (constant-time structure)
# ============================================================================

def _p384_point_cswap(mut a: P384Point, mut b: P384Point, swap: Int):
    """Conditionally swap two P-384 points in constant time (swap if swap==1)."""
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


def _p384_scalar_mul_affine(scalar: BigInt, px: BigInt, py: BigInt, p: BigInt) -> P384Point:
    """Compute scalar * P where P = (px, py) in affine coords, using Montgomery ladder."""
    var r0 = P384Point()  # point at infinity
    var r1 = P384Point()
    r1.x = px.copy()
    r1.y = py.copy()
    r1.z = bigint_one()
    r1.inf = False
    var bits = bigint_bit_len(scalar)
    if bits == 0:
        return r0^
    for i in range(bits - 1, -1, -1):
        var b = Int(bigint_get_bit(scalar, i))
        _p384_point_cswap(r0, r1, b)
        var add_result = _p384_padd(r0, r1, p)
        r0 = _p384_pdbl(r0, p)
        r1 = add_result^
        _p384_point_cswap(r0, r1, b)
    return r0^


def _p384_scalar_mul(scalar: BigInt, P: P384Point, p: BigInt) -> P384Point:
    """Compute scalar * P where P is in Jacobian coords, using Montgomery ladder."""
    var r0 = P384Point()  # point at infinity
    var r1 = P.copy()
    var bits = bigint_bit_len(scalar)
    if bits == 0:
        return r0^
    for i in range(bits - 1, -1, -1):
        var b = Int(bigint_get_bit(scalar, i))
        _p384_point_cswap(r0, r1, b)
        var add_result = _p384_padd(r0, r1, p)
        r0 = _p384_pdbl(r0, p)
        r1 = add_result^
        _p384_point_cswap(r0, r1, b)
    return r0^


# ============================================================================
# Point validation
# ============================================================================

def _p384_point_on_curve(x: BigInt, y: BigInt, p: BigInt) -> Bool:
    """Check y² ≡ x³ − 3x + b (mod p) for P-384."""
    # b = b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875a
    #       c656398d8a2ed19d2a85c8edd3ec2aef
    var bv = List[UInt8](capacity=48)
    bv.append(0xB3); bv.append(0x31); bv.append(0x2F); bv.append(0xA7)
    bv.append(0xE2); bv.append(0x3E); bv.append(0xE7); bv.append(0xE4)
    bv.append(0x98); bv.append(0x8E); bv.append(0x05); bv.append(0x6B)
    bv.append(0xE3); bv.append(0xF8); bv.append(0x2D); bv.append(0x19)
    bv.append(0x18); bv.append(0x1D); bv.append(0x9C); bv.append(0x6E)
    bv.append(0xFE); bv.append(0x81); bv.append(0x41); bv.append(0x12)
    bv.append(0x03); bv.append(0x14); bv.append(0x08); bv.append(0x8F)
    bv.append(0x50); bv.append(0x13); bv.append(0x87); bv.append(0x5A)
    bv.append(0xC6); bv.append(0x56); bv.append(0x39); bv.append(0x8D)
    bv.append(0x8A); bv.append(0x2E); bv.append(0xD1); bv.append(0x9D)
    bv.append(0x2A); bv.append(0x85); bv.append(0xC8); bv.append(0xED)
    bv.append(0xD3); bv.append(0xEC); bv.append(0x2A); bv.append(0xEF)
    var b   = bigint_from_bytes(bv)
    var lhs = _p384_fsq(y, p)
    var x3  = _p384_fmul(_p384_fsq(x.copy(), p), x.copy(), p)
    var ax  = _p384_fk(x, 3, p)
    var rhs = _p384_fadd(_p384_fsub(x3, ax, p), b, p)
    return bigint_cmp(lhs, rhs) == 0


# ============================================================================
# Parse uncompressed public key (97 bytes: 0x04 || X || Y)
# ============================================================================

def _p384_parse_pub(pub: List[UInt8]) raises -> Tuple[BigInt, BigInt]:
    """Parse 97-byte uncompressed P-384 public key → (Qx, Qy)."""
    if len(pub) != 97 or pub[0] != 0x04:
        raise Error("p384: invalid public key format (need 97-byte uncompressed)")
    var qx_bytes = List[UInt8](capacity=48)
    var qy_bytes = List[UInt8](capacity=48)
    for i in range(48):
        qx_bytes.append(pub[1 + i])
        qy_bytes.append(pub[49 + i])
    return (bigint_from_bytes(qx_bytes), bigint_from_bytes(qy_bytes))


# ============================================================================
# Public API
# ============================================================================

def p384_ecdsa_verify(
    pub_key:  List[UInt8],   # 97-byte uncompressed P-384 public key
    msg_hash: List[UInt8],   # 48-byte message hash (SHA-384)
    sig_r:    List[UInt8],   # up to 48-byte r component
    sig_s:    List[UInt8],   # up to 48-byte s component
) raises:
    """Verify P-384 ECDSA signature. Raises on invalid."""
    var p = _p384_p()
    var n = _p384_n()

    # Parse public key
    var parsed = _p384_parse_pub(pub_key)
    var qx = parsed[0].copy()
    var qy = parsed[1].copy()
    if not _p384_point_on_curve(qx.copy(), qy.copy(), p):
        raise Error("p384: public key not on curve")

    # Parse r, s
    var r = bigint_from_bytes(sig_r)
    var s = bigint_from_bytes(sig_s)
    var one = bigint_one()
    if bigint_cmp(r, one) < 0 or bigint_cmp(r, n) >= 0:
        raise Error("p384: r out of range")
    if bigint_cmp(s, one) < 0 or bigint_cmp(s, n) >= 0:
        raise Error("p384: s out of range")

    # e = hash interpreted as integer, reduced mod n
    var e = bigint_mod(bigint_from_bytes(msg_hash), n)

    # w = s^(-1) mod n
    var w = bigint_modinv(s, n)

    # u1 = e*w mod n, u2 = r*w mod n
    var u1 = bigint_modmul(e, w.copy(), n)
    var u2 = bigint_modmul(r.copy(), w, n)

    # R = u1*G + u2*Q
    var gx = _p384_gx()
    var gy = _p384_gy()
    var R1 = _p384_scalar_mul_affine(u1, gx, gy, p)
    var R2 = _p384_scalar_mul_affine(u2, qx, qy, p)
    var R  = _p384_padd(R1, R2, p)
    if R.inf:
        raise Error("p384: ECDSA verify failed — R is infinity")

    # Convert R to affine and check x mod n == r
    var affine = _p384_to_affine(R, p)
    var rx = bigint_mod(affine[0], n)
    if bigint_cmp(rx, r) != 0:
        raise Error("p384: ECDSA signature invalid")
