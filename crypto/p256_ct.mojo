# ============================================================================
# crypto/p256_ct.mojo — constant-time P-256 arithmetic for secret scalars
# ============================================================================
# Used by p256_public_key, p256_ecdh and p256_ecdsa_sign (crypto/p256.mojo).
# Signature verification handles only public data and keeps the BigInt code.
#
# Constant time with respect to secret values:
#   - field elements are 8 x 32-bit limbs (held in UInt64), fixed width;
#   - Montgomery multiplication (CIOS) with a mask-based final subtraction;
#   - add / sub / select / swap use masks, never branches on data;
#   - points use the complete projective formulas for a = -3 of Renes,
#     Costello and Batina (2016, Algorithms 4 and 6): no special cases for
#     the identity or for P == Q, so no data-dependent branches;
#   - scalar multiplication is a Montgomery ladder over all 256 bits;
#   - inversion is Fermat's little theorem with the public exponent m - 2.
# The same field code serves the scalar field (mod n) for ECDSA signing.
# ============================================================================

from std.collections import InlineArray


comptime Limbs = InlineArray[UInt64, 8]  # little-endian, each limb < 2^32
comptime _M32 = UInt64(0xFFFFFFFF)


struct Modulus(Copyable, Movable):
    """A 256-bit odd modulus with its Montgomery constants (R = 2^256)."""
    var m: Limbs
    var r2: Limbs        # R^2 mod m
    var m0inv: UInt64    # -m^-1 mod 2^32

    def __init__(out self, m: List[UInt64], r2: List[UInt64], m0inv: UInt64):
        self.m = Limbs(fill=0)
        self.r2 = Limbs(fill=0)
        for i in range(8):
            self.m[i] = m[i]
            self.r2[i] = r2[i]
        self.m0inv = m0inv


def mod_p() -> Modulus:
    """The P-256 field prime p = 2^256 - 2^224 + 2^192 + 2^96 - 1."""
    return Modulus(
        [0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000000, 0x00000000, 0x00000000, 0x00000001, 0xFFFFFFFF],
        [0x00000003, 0x00000000, 0xFFFFFFFF, 0xFFFFFFFB, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFD, 0x00000004],
        0x00000001,
    )


def mod_n() -> Modulus:
    """The P-256 group order n."""
    return Modulus(
        [0xFC632551, 0xF3B9CAC2, 0xA7179E84, 0xBCE6FAAD, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000000, 0xFFFFFFFF],
        [0xBE79EEA2, 0x83244C95, 0x49BD6FA6, 0x4699799C, 0x2B6BEC59, 0x2845B239, 0xF3D95620, 0x66E12D94],
        0xEE00BC4F,
    )


# ============================================================================
# Conversions
# ============================================================================

def limbs_from_be(b: List[UInt8], off: Int) -> Limbs:
    """32 big-endian bytes at b[off:] → limbs."""
    var a = Limbs(fill=0)
    for i in range(8):
        var o = off + 28 - 4 * i
        a[i] = (UInt64(b[o]) << 24) | (UInt64(b[o + 1]) << 16) | (UInt64(b[o + 2]) << 8) | UInt64(b[o + 3])
    return a^


def limbs_to_be(a: Limbs) -> List[UInt8]:
    var out = List[UInt8](capacity=32)
    for i in range(7, -1, -1):
        out.append(UInt8((a[i] >> 24) & 0xFF))
        out.append(UInt8((a[i] >> 16) & 0xFF))
        out.append(UInt8((a[i] >> 8) & 0xFF))
        out.append(UInt8(a[i] & 0xFF))
    return out^


def limbs_small(v: UInt64) -> Limbs:
    var a = Limbs(fill=0)
    a[0] = v
    return a^


# ============================================================================
# Constant-time helpers
# ============================================================================

@always_inline
def is_zero(a: Limbs) -> UInt64:
    """1 if a == 0 else 0, without branching."""
    var acc: UInt64 = 0
    for i in range(8):
        acc |= a[i]
    return ((acc | (UInt64(0) - acc)) >> 63) ^ 1


@always_inline
def lt(a: Limbs, b: Limbs) -> UInt64:
    """1 if a < b else 0 (borrow of a - b), without branching."""
    var borrow: UInt64 = 0
    for i in range(8):
        var d = a[i] - b[i] - borrow
        borrow = (d >> 63) & 1
    return borrow


@always_inline
def select(mask: UInt64, a: Limbs, b: Limbs) -> Limbs:
    """a where mask is all ones, b where mask is zero."""
    var r = Limbs(fill=0)
    for i in range(8):
        r[i] = (a[i] & mask) | (b[i] & ~mask)
    return r^


@always_inline
def cswap(mut a: Limbs, mut b: Limbs, bit: UInt64):
    var mask = UInt64(0) - bit
    for i in range(8):
        var t = (a[i] ^ b[i]) & mask
        a[i] ^= t
        b[i] ^= t


def _sub_m_if(r: Limbs, hi: UInt64, md: Modulus) -> Limbs:
    """r + hi*2^256, reduced by one conditional subtraction of m."""
    var d = Limbs(fill=0)
    var borrow: UInt64 = 0
    for i in range(8):
        var diff = r[i] - md.m[i] - borrow
        d[i] = diff & _M32
        borrow = (diff >> 63) & 1
    var use_d = hi | (borrow ^ 1)
    return select(UInt64(0) - use_d, d, r)


def reduce_once(a: Limbs, md: Modulus) -> Limbs:
    """a mod m for a < 2m."""
    return _sub_m_if(a, 0, md)


# ============================================================================
# Field arithmetic (inputs and outputs in [0, m))
# ============================================================================

def add(a: Limbs, b: Limbs, md: Modulus) -> Limbs:
    var r = Limbs(fill=0)
    var c: UInt64 = 0
    for i in range(8):
        var s = a[i] + b[i] + c
        r[i] = s & _M32
        c = s >> 32
    return _sub_m_if(r, c, md)


def sub(a: Limbs, b: Limbs, md: Modulus) -> Limbs:
    var r = Limbs(fill=0)
    var borrow: UInt64 = 0
    for i in range(8):
        var d = a[i] - b[i] - borrow
        r[i] = d & _M32
        borrow = (d >> 63) & 1
    # add m back when a < b
    var mask = UInt64(0) - borrow
    var c: UInt64 = 0
    for i in range(8):
        var s = r[i] + (md.m[i] & mask) + c
        r[i] = s & _M32
        c = s >> 32
    return r^


def mont_mul(a: Limbs, b: Limbs, md: Modulus) -> Limbs:
    """a * b * 2^-256 mod m (CIOS Montgomery multiplication)."""
    var t = InlineArray[UInt64, 10](fill=0)
    for i in range(8):
        var bi = b[i]
        var c: UInt64 = 0
        for j in range(8):
            var uv = t[j] + a[j] * bi + c
            t[j] = uv & _M32
            c = uv >> 32
        var top = t[8] + c
        t[8] = top & _M32
        t[9] = top >> 32
        var mq = (t[0] * md.m0inv) & _M32
        var uv = t[0] + mq * md.m[0]
        c = uv >> 32
        for j in range(1, 8):
            uv = t[j] + mq * md.m[j] + c
            t[j - 1] = uv & _M32
            c = uv >> 32
        uv = t[8] + c
        t[7] = uv & _M32
        t[8] = t[9] + (uv >> 32)
        t[9] = 0
    var r = Limbs(fill=0)
    for i in range(8):
        r[i] = t[i]
    return _sub_m_if(r, t[8], md)


def to_mont(a: Limbs, md: Modulus) -> Limbs:
    return mont_mul(a, md.r2, md)


def from_mont(a: Limbs, md: Modulus) -> Limbs:
    return mont_mul(a, limbs_small(1), md)


def mont_one(md: Modulus) -> Limbs:
    return to_mont(limbs_small(1), md)


def mont_inv(a: Limbs, md: Modulus) -> Limbs:
    """a^-1 in the Montgomery domain via a^(m-2); 0 maps to 0.

    The exponent is public, so branching on its bits leaks nothing.
    """
    var e = md.m.copy()
    e[0] -= 2  # m is odd and its low limb is > 2 for both P-256 moduli
    var r = mont_one(md)
    for i in range(255, -1, -1):
        r = mont_mul(r, r, md)
        if (e[i >> 5] >> UInt64(i & 31)) & 1 == 1:
            r = mont_mul(r, a, md)
    return r^


# ============================================================================
# Points: projective (X:Y:Z), Montgomery-form coordinates; identity (0:1:0)
# ============================================================================

struct Point(Copyable, Movable):
    var x: Limbs
    var y: Limbs
    var z: Limbs

    def __init__(out self, x: Limbs, y: Limbs, z: Limbs):
        self.x = x.copy()
        self.y = y.copy()
        self.z = z.copy()


def identity(md: Modulus) -> Point:
    return Point(Limbs(fill=0), mont_one(md), Limbs(fill=0))


def curve_b(md: Modulus) -> Limbs:
    var b = List[UInt8]()
    var hex = "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B".as_bytes()
    for i in range(32):
        var hi = hex[2 * i]
        var lo = hex[2 * i + 1]
        var h: UInt8 = (hi - 48) if hi <= 57 else (hi - 55)
        var l: UInt8 = (lo - 48) if lo <= 57 else (lo - 55)
        b.append((h << 4) | l)
    return to_mont(limbs_from_be(b, 0), md)


def point_add(p1: Point, p2: Point, b: Limbs, md: Modulus) -> Point:
    """Complete addition (RCB 2016 Algorithm 4, a = -3); valid for p1 == p2."""
    var t0 = mont_mul(p1.x, p2.x, md)
    var t1 = mont_mul(p1.y, p2.y, md)
    var t2 = mont_mul(p1.z, p2.z, md)
    var t3 = add(p1.x, p1.y, md)
    var t4 = add(p2.x, p2.y, md)
    t3 = mont_mul(t3, t4, md)
    t4 = add(t0, t1, md)
    t3 = sub(t3, t4, md)
    t4 = add(p1.y, p1.z, md)
    var x3 = add(p2.y, p2.z, md)
    t4 = mont_mul(t4, x3, md)
    x3 = add(t1, t2, md)
    t4 = sub(t4, x3, md)
    x3 = add(p1.x, p1.z, md)
    var y3 = add(p2.x, p2.z, md)
    x3 = mont_mul(x3, y3, md)
    y3 = add(t0, t2, md)
    y3 = sub(x3, y3, md)
    var z3 = mont_mul(b, t2, md)
    x3 = sub(y3, z3, md)
    z3 = add(x3, x3, md)
    x3 = add(x3, z3, md)
    z3 = sub(t1, x3, md)
    x3 = add(t1, x3, md)
    y3 = mont_mul(b, y3, md)
    t1 = add(t2, t2, md)
    t2 = add(t1, t2, md)
    y3 = sub(y3, t2, md)
    y3 = sub(y3, t0, md)
    t1 = add(y3, y3, md)
    y3 = add(t1, y3, md)
    t1 = add(t0, t0, md)
    t0 = add(t1, t0, md)
    t0 = sub(t0, t2, md)
    t1 = mont_mul(t4, y3, md)
    t2 = mont_mul(t0, y3, md)
    y3 = mont_mul(x3, z3, md)
    y3 = add(y3, t2, md)
    x3 = mont_mul(t3, x3, md)
    x3 = sub(x3, t1, md)
    z3 = mont_mul(t4, z3, md)
    t1 = mont_mul(t3, t0, md)
    z3 = add(z3, t1, md)
    return Point(x3, y3, z3)


def point_double(p: Point, b: Limbs, md: Modulus) -> Point:
    """Complete doubling (RCB 2016 Algorithm 6, a = -3)."""
    var t0 = mont_mul(p.x, p.x, md)
    var t1 = mont_mul(p.y, p.y, md)
    var t2 = mont_mul(p.z, p.z, md)
    var t3 = mont_mul(p.x, p.y, md)
    t3 = add(t3, t3, md)
    var z3 = mont_mul(p.x, p.z, md)
    z3 = add(z3, z3, md)
    var y3 = mont_mul(b, t2, md)
    y3 = sub(y3, z3, md)
    var x3 = add(y3, y3, md)
    y3 = add(x3, y3, md)
    x3 = sub(t1, y3, md)
    y3 = add(t1, y3, md)
    y3 = mont_mul(x3, y3, md)
    x3 = mont_mul(x3, t3, md)
    t3 = add(t2, t2, md)
    t2 = add(t2, t3, md)
    z3 = mont_mul(b, z3, md)
    z3 = sub(z3, t2, md)
    z3 = sub(z3, t0, md)
    t3 = add(z3, z3, md)
    z3 = add(z3, t3, md)
    t3 = add(t0, t0, md)
    t0 = add(t3, t0, md)
    t0 = sub(t0, t2, md)
    t0 = mont_mul(t0, z3, md)
    y3 = add(y3, t0, md)
    t0 = mont_mul(p.y, p.z, md)
    t0 = add(t0, t0, md)
    z3 = mont_mul(t0, z3, md)
    x3 = sub(x3, z3, md)
    z3 = mont_mul(t0, t1, md)
    z3 = add(z3, z3, md)
    z3 = add(z3, z3, md)
    return Point(x3, y3, z3)


def point_cswap(mut a: Point, mut b: Point, bit: UInt64):
    cswap(a.x, b.x, bit)
    cswap(a.y, b.y, bit)
    cswap(a.z, b.z, bit)


def scalar_mult(k: List[UInt8], p: Point, md: Modulus) -> Point:
    """k * p for a 32-byte big-endian scalar: Montgomery ladder, 256 steps."""
    var b = curve_b(md)
    var r0 = identity(md)
    var r1 = p.copy()
    for i in range(255, -1, -1):
        var bit = UInt64((k[31 - (i >> 3)] >> UInt8(i & 7)) & 1)
        point_cswap(r0, r1, bit)
        r1 = point_add(r0, r1, b, md)
        r0 = point_double(r0, b, md)
        point_cswap(r0, r1, bit)
    return r0^


def base_point(md: Modulus) -> Point:
    var gx: List[UInt8] = [
        0x6B, 0x17, 0xD1, 0xF2, 0xE1, 0x2C, 0x42, 0x47, 0xF8, 0xBC, 0xE6, 0xE5, 0x63, 0xA4, 0x40, 0xF2,
        0x77, 0x03, 0x7D, 0x81, 0x2D, 0xEB, 0x33, 0xA0, 0xF4, 0xA1, 0x39, 0x45, 0xD8, 0x98, 0xC2, 0x96,
    ]
    var gy: List[UInt8] = [
        0x4F, 0xE3, 0x42, 0xE2, 0xFE, 0x1A, 0x7F, 0x9B, 0x8E, 0xE7, 0xEB, 0x4A, 0x7C, 0x0F, 0x9E, 0x16,
        0x2B, 0xCE, 0x33, 0x57, 0x6B, 0x31, 0x5E, 0xCE, 0xCB, 0xB6, 0x40, 0x68, 0x37, 0xBF, 0x51, 0xF5,
    ]
    return Point(to_mont(limbs_from_be(gx, 0), md), to_mont(limbs_from_be(gy, 0), md), mont_one(md))


def to_affine(p: Point, md: Modulus) raises -> Tuple[Limbs, Limbs]:
    """(x, y) in normal form. Raises for the identity (Z == 0).

    The check runs on the final result, which is public (a public key, an
    ECDH output, or R in a signature); the arithmetic before it is uniform.
    """
    var zinv = mont_inv(p.z, md)
    var x = from_mont(mont_mul(p.x, zinv, md), md)
    var y = from_mont(mont_mul(p.y, zinv, md), md)
    if is_zero(p.z) == 1:
        raise Error("p256: point at infinity")
    return (x^, y^)


def scalar_in_range(k: List[UInt8], md: Modulus) -> Bool:
    """1 <= k < m, decided without branching on k's value."""
    var a = limbs_from_be(k, 0)
    return (lt(a, md.m) & (is_zero(a) ^ 1)) == 1
