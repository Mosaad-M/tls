# ============================================================================
# crypto/ec_ct.mojo — constant-time arithmetic for P-256 and P-384 secrets
# ============================================================================
# Used for every operation on a private scalar: p256_public_key, p256_ecdh,
# p256_ecdsa_sign (crypto/p256.mojo) and p384_public_key, p384_ecdh
# (crypto/p384.mojo). Signature verification handles only public data and
# keeps the BigInt code.
#
# Generic over the limb count N (8 for P-256, 12 for P-384). Constant time
# with respect to secret values:
#   - field elements are N x 32-bit limbs (held in UInt64), fixed width;
#   - Montgomery multiplication (CIOS) with a mask-based final subtraction;
#   - add / sub / select / swap use masks, never branches on data;
#   - points use the complete projective formulas for a = -3 of Renes,
#     Costello and Batina (2016, Algorithms 4 and 6): no special cases for
#     the identity or for P == Q, so no data-dependent branches;
#   - scalar multiplication is a Montgomery ladder over all 32*N bits;
#   - inversion is Fermat's little theorem with the public exponent m - 2.
# The same field code serves the scalar field (mod n) for ECDSA signing.
# ============================================================================

from std.collections import InlineArray


comptime _M32 = UInt64(0xFFFFFFFF)


struct Modulus[N: Int](Copyable, Movable):
    """An odd modulus of 32*N bits with its Montgomery constants (R = 2^(32N))."""
    var m: InlineArray[UInt64, Self.N]
    var r2: InlineArray[UInt64, Self.N]   # R^2 mod m
    var m0inv: UInt64                # -m^-1 mod 2^32

    def __init__(out self, m: List[UInt64], r2: List[UInt64], m0inv: UInt64):
        self.m = InlineArray[UInt64, Self.N](fill=0)
        self.r2 = InlineArray[UInt64, Self.N](fill=0)
        for i in range(Self.N):
            self.m[i] = m[i]
            self.r2[i] = r2[i]
        self.m0inv = m0inv


# ============================================================================
# Conversions
# ============================================================================

def limbs_from_be[N: Int](b: List[UInt8], off: Int) -> InlineArray[UInt64, N]:
    """4*N big-endian bytes at b[off:] → limbs."""
    var a = InlineArray[UInt64, N](fill=0)
    for i in range(N):
        var o = off + 4 * (N - 1 - i)
        a[i] = (UInt64(b[o]) << 24) | (UInt64(b[o + 1]) << 16) | (UInt64(b[o + 2]) << 8) | UInt64(b[o + 3])
    return a^


def limbs_to_be[N: Int](a: InlineArray[UInt64, N]) -> List[UInt8]:
    var out = List[UInt8](capacity=4 * N)
    for i in range(N - 1, -1, -1):
        out.append(UInt8((a[i] >> 24) & 0xFF))
        out.append(UInt8((a[i] >> 16) & 0xFF))
        out.append(UInt8((a[i] >> 8) & 0xFF))
        out.append(UInt8(a[i] & 0xFF))
    return out^


def limbs_small[N: Int](v: UInt64) -> InlineArray[UInt64, N]:
    var a = InlineArray[UInt64, N](fill=0)
    a[0] = v
    return a^


def _unhex(h: String) -> List[UInt8]:
    var raw = h.as_bytes()
    var out = List[UInt8](capacity=len(raw) // 2)
    for i in range(0, len(raw) - 1, 2):
        var hi = raw[i]
        var lo = raw[i + 1]
        var a: UInt8 = (hi - 48) if hi <= 57 else (hi - 55)
        var b: UInt8 = (lo - 48) if lo <= 57 else (lo - 55)
        out.append((a << 4) | b)
    return out^


# ============================================================================
# Constant-time helpers
# ============================================================================

@always_inline
def is_zero[N: Int](a: InlineArray[UInt64, N]) -> UInt64:
    """1 if a == 0 else 0, without branching."""
    var acc: UInt64 = 0
    for i in range(N):
        acc |= a[i]
    return ((acc | (UInt64(0) - acc)) >> 63) ^ 1


@always_inline
def lt[N: Int](a: InlineArray[UInt64, N], b: InlineArray[UInt64, N]) -> UInt64:
    """1 if a < b else 0 (borrow of a - b), without branching."""
    var borrow: UInt64 = 0
    for i in range(N):
        var d = a[i] - b[i] - borrow
        borrow = (d >> 63) & 1
    return borrow


@always_inline
def select[N: Int](mask: UInt64, a: InlineArray[UInt64, N], b: InlineArray[UInt64, N]) -> InlineArray[UInt64, N]:
    """a where mask is all ones, b where mask is zero."""
    var r = InlineArray[UInt64, N](fill=0)
    for i in range(N):
        r[i] = (a[i] & mask) | (b[i] & ~mask)
    return r^


@always_inline
def cswap[N: Int](mut a: InlineArray[UInt64, N], mut b: InlineArray[UInt64, N], bit: UInt64):
    var mask = UInt64(0) - bit
    for i in range(N):
        var t = (a[i] ^ b[i]) & mask
        a[i] ^= t
        b[i] ^= t


def _sub_m_if[N: Int](r: InlineArray[UInt64, N], hi: UInt64, md: Modulus[N]) -> InlineArray[UInt64, N]:
    """r + hi*R, reduced by one conditional subtraction of m."""
    var d = InlineArray[UInt64, N](fill=0)
    var borrow: UInt64 = 0
    for i in range(N):
        var diff = r[i] - md.m[i] - borrow
        d[i] = diff & _M32
        borrow = (diff >> 63) & 1
    var use_d = hi | (borrow ^ 1)
    return select(UInt64(0) - use_d, d, r)


def reduce_once[N: Int](a: InlineArray[UInt64, N], md: Modulus[N]) -> InlineArray[UInt64, N]:
    """a mod m for a < 2m."""
    return _sub_m_if(a, 0, md)


# ============================================================================
# Field arithmetic (inputs and outputs in [0, m))
# ============================================================================

def add[N: Int](a: InlineArray[UInt64, N], b: InlineArray[UInt64, N], md: Modulus[N]) -> InlineArray[UInt64, N]:
    var r = InlineArray[UInt64, N](fill=0)
    var c: UInt64 = 0
    for i in range(N):
        var s = a[i] + b[i] + c
        r[i] = s & _M32
        c = s >> 32
    return _sub_m_if(r, c, md)


def sub[N: Int](a: InlineArray[UInt64, N], b: InlineArray[UInt64, N], md: Modulus[N]) -> InlineArray[UInt64, N]:
    var r = InlineArray[UInt64, N](fill=0)
    var borrow: UInt64 = 0
    for i in range(N):
        var d = a[i] - b[i] - borrow
        r[i] = d & _M32
        borrow = (d >> 63) & 1
    # add m back when a < b
    var mask = UInt64(0) - borrow
    var c: UInt64 = 0
    for i in range(N):
        var s = r[i] + (md.m[i] & mask) + c
        r[i] = s & _M32
        c = s >> 32
    return r^


def mont_mul[N: Int](a: InlineArray[UInt64, N], b: InlineArray[UInt64, N], md: Modulus[N]) -> InlineArray[UInt64, N]:
    """a * b * R^-1 mod m (CIOS Montgomery multiplication)."""
    var t = InlineArray[UInt64, N + 2](fill=0)
    for i in range(N):
        var bi = b[i]
        var c: UInt64 = 0
        for j in range(N):
            var uv = t[j] + a[j] * bi + c
            t[j] = uv & _M32
            c = uv >> 32
        var top = t[N] + c
        t[N] = top & _M32
        t[N + 1] = top >> 32
        var mq = (t[0] * md.m0inv) & _M32
        var uv = t[0] + mq * md.m[0]
        c = uv >> 32
        for j in range(1, N):
            uv = t[j] + mq * md.m[j] + c
            t[j - 1] = uv & _M32
            c = uv >> 32
        uv = t[N] + c
        t[N - 1] = uv & _M32
        t[N] = t[N + 1] + (uv >> 32)
        t[N + 1] = 0
    var r = InlineArray[UInt64, N](fill=0)
    for i in range(N):
        r[i] = t[i]
    return _sub_m_if(r, t[N], md)


def to_mont[N: Int](a: InlineArray[UInt64, N], md: Modulus[N]) -> InlineArray[UInt64, N]:
    return mont_mul(a, md.r2, md)


def from_mont[N: Int](a: InlineArray[UInt64, N], md: Modulus[N]) -> InlineArray[UInt64, N]:
    return mont_mul(a, limbs_small[N](1), md)


def mont_one[N: Int](md: Modulus[N]) -> InlineArray[UInt64, N]:
    return to_mont(limbs_small[N](1), md)


def mont_inv[N: Int](a: InlineArray[UInt64, N], md: Modulus[N]) -> InlineArray[UInt64, N]:
    """a^-1 in the Montgomery domain via a^(m-2); 0 maps to 0.

    The exponent is public, so branching on its bits leaks nothing.
    """
    var e = md.m.copy()
    e[0] -= 2  # m is odd and its low limb is > 2 for all four moduli
    var r = mont_one(md)
    for i in range(32 * N - 1, -1, -1):
        r = mont_mul(r, r, md)
        if (e[i >> 5] >> UInt64(i & 31)) & 1 == 1:
            r = mont_mul(r, a, md)
    return r^


# ============================================================================
# Points: projective (X:Y:Z), Montgomery-form coordinates; identity (0:1:0)
# ============================================================================

struct Point[N: Int](Copyable, Movable):
    var x: InlineArray[UInt64, Self.N]
    var y: InlineArray[UInt64, Self.N]
    var z: InlineArray[UInt64, Self.N]

    def __init__(out self, x: InlineArray[UInt64, Self.N], y: InlineArray[UInt64, Self.N], z: InlineArray[UInt64, Self.N]):
        self.x = x.copy()
        self.y = y.copy()
        self.z = z.copy()


struct Curve[N: Int](Copyable, Movable):
    """A short-Weierstrass curve with a = -3 (P-256, P-384)."""
    var field: Modulus[Self.N]              # field prime p
    var order: Modulus[Self.N]              # group order n
    var b: InlineArray[UInt64, Self.N]      # curve coefficient b, Montgomery form
    var g: Point[Self.N]                    # base point, Montgomery form

    def __init__(out self, field: Modulus[Self.N], order: Modulus[Self.N], b_hex: String, gx_hex: String, gy_hex: String):
        self.field = field.copy()
        self.order = order.copy()
        self.b = to_mont(limbs_from_be[Self.N](_unhex(b_hex), 0), field)
        self.g = Point[Self.N](
            to_mont(limbs_from_be[Self.N](_unhex(gx_hex), 0), field),
            to_mont(limbs_from_be[Self.N](_unhex(gy_hex), 0), field),
            mont_one(field),
        )


def p256_curve() -> Curve[8]:
    return Curve[8](
        Modulus[8](
            [0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000000, 0x00000000, 0x00000000, 0x00000001, 0xFFFFFFFF],
            [0x00000003, 0x00000000, 0xFFFFFFFF, 0xFFFFFFFB, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFD, 0x00000004],
            0x00000001,
        ),
        Modulus[8](
            [0xFC632551, 0xF3B9CAC2, 0xA7179E84, 0xBCE6FAAD, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000000, 0xFFFFFFFF],
            [0xBE79EEA2, 0x83244C95, 0x49BD6FA6, 0x4699799C, 0x2B6BEC59, 0x2845B239, 0xF3D95620, 0x66E12D94],
            0xEE00BC4F,
        ),
        "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B",
        "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296",
        "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5",
    )


def p384_curve() -> Curve[12]:
    return Curve[12](
        Modulus[12](
            [0xFFFFFFFF, 0x00000000, 0x00000000, 0xFFFFFFFF, 0xFFFFFFFE, 0xFFFFFFFF,
             0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF],
            [0x00000001, 0xFFFFFFFE, 0x00000000, 0x00000002, 0x00000000, 0xFFFFFFFE,
             0x00000000, 0x00000002, 0x00000001, 0x00000000, 0x00000000, 0x00000000],
            0x00000001,
        ),
        Modulus[12](
            [0xCCC52973, 0xECEC196A, 0x48B0A77A, 0x581A0DB2, 0xF4372DDF, 0xC7634D81,
             0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF],
            [0x19B409A9, 0x2D319B24, 0xDF1AA419, 0xFF3D81E5, 0xFCB82947, 0xBC3E483A,
             0x4AAB1CC5, 0xD40D4917, 0x28266895, 0x3FB05B7A, 0x2B39BF21, 0x0C84EE01],
            0xE88FDC45,
        ),
        "B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF",
        "AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7",
        "3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F",
    )


def point_add[N: Int](p1: Point[N], p2: Point[N], b: InlineArray[UInt64, N], md: Modulus[N]) -> Point[N]:
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
    return Point[N](x3, y3, z3)


def point_double[N: Int](p: Point[N], b: InlineArray[UInt64, N], md: Modulus[N]) -> Point[N]:
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
    return Point[N](x3, y3, z3)


def point_cswap[N: Int](mut a: Point[N], mut b: Point[N], bit: UInt64):
    cswap(a.x, b.x, bit)
    cswap(a.y, b.y, bit)
    cswap(a.z, b.z, bit)


def scalar_mult[N: Int](k: List[UInt8], p: Point[N], c: Curve[N]) -> Point[N]:
    """k * p for a 4N-byte big-endian scalar: Montgomery ladder, 32N steps."""
    var r0 = Point[N](InlineArray[UInt64, N](fill=0), mont_one(c.field), InlineArray[UInt64, N](fill=0))
    var r1 = p.copy()
    for i in range(32 * N - 1, -1, -1):
        var bit = UInt64((k[4 * N - 1 - (i >> 3)] >> UInt8(i & 7)) & 1)
        point_cswap(r0, r1, bit)
        r1 = point_add(r0, r1, c.b, c.field)
        r0 = point_double(r0, c.b, c.field)
        point_cswap(r0, r1, bit)
    return r0^


def to_affine[N: Int](p: Point[N], md: Modulus[N]) raises -> Tuple[InlineArray[UInt64, N], InlineArray[UInt64, N]]:
    """(x, y) in normal form. Raises for the identity (Z == 0).

    The check runs on the final result, which is public (a public key, an
    ECDH output, or R in a signature); the arithmetic before it is uniform.
    """
    var zinv = mont_inv(p.z, md)
    var x = from_mont(mont_mul(p.x, zinv, md), md)
    var y = from_mont(mont_mul(p.y, zinv, md), md)
    if is_zero(p.z) == 1:
        raise Error("ec: point at infinity")
    return (x^, y^)


def scalar_in_range[N: Int](k: List[UInt8], md: Modulus[N]) -> Bool:
    """1 <= k < m for a 4N-byte big-endian k, decided without branching on k."""
    var a = limbs_from_be[N](k, 0)
    return (lt(a, md.m) & (is_zero(a) ^ 1)) == 1


def public_key[N: Int](private_key: List[UInt8], c: Curve[N]) raises -> List[UInt8]:
    """Uncompressed public key 04 || X || Y for a private scalar in [1, n-1]."""
    if len(private_key) != 4 * N or not scalar_in_range(private_key, c.order):
        raise Error("ec: private key out of range")
    var aff = to_affine(scalar_mult(private_key, c.g, c), c.field)
    var out = List[UInt8](capacity=1 + 8 * N)
    out.append(0x04)
    var xb = limbs_to_be(aff[0])
    var yb = limbs_to_be(aff[1])
    for i in range(4 * N):
        out.append(xb[i])
    for i in range(4 * N):
        out.append(yb[i])
    return out^


def ecdh_x[N: Int](private_key: List[UInt8], peer_public_key: List[UInt8], c: Curve[N]) raises -> List[UInt8]:
    """x-coordinate of private_key * peer. The caller must already have
    checked that peer_public_key is a valid uncompressed point on the curve."""
    if len(private_key) != 4 * N or not scalar_in_range(private_key, c.order):
        raise Error("ec: private key out of range")
    var peer = Point[N](
        to_mont(limbs_from_be[N](peer_public_key, 1), c.field),
        to_mont(limbs_from_be[N](peer_public_key, 1 + 4 * N), c.field),
        mont_one(c.field),
    )
    var aff = to_affine(scalar_mult(private_key, peer, c), c.field)
    return limbs_to_be(aff[0])
