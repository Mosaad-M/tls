# ============================================================================
# crypto/ec_ct.mojo — constant-time arithmetic for P-256 and P-384 secrets
# ============================================================================
# Used for every operation on a private scalar: p256_public_key, p256_ecdh,
# p256_ecdsa_sign (crypto/p256.mojo) and p384_public_key, p384_ecdh
# (crypto/p384.mojo), and ECDSA verification (ecdsa_verify, public data
# only, so it may branch on the scalars' bits).
#
# Generic over the limb count N (4 for P-256, 6 for P-384; RSA verification
# uses wider moduli). Constant time with respect to secret values:
#   - field elements are N x 64-bit limbs, fixed width; carries go through
#     UInt128 (MUL/UMULH and adds: constant time on ARM64 and x86-64);
#   - Montgomery multiplication (CIOS) with a mask-based final subtraction;
#   - add / sub / select / swap use masks, never branches on data;
#   - points use the complete projective formulas for a = -3 of Renes,
#     Costello and Batina (2016, Algorithms 4 and 6): no special cases for
#     the identity or for P == Q, so no data-dependent branches;
#   - scalar multiplication is a Montgomery ladder over all 64*N bits;
#   - inversion is Fermat's little theorem with the public exponent m - 2.
# The same field code serves the scalar field (mod n) for ECDSA signing.
# ============================================================================

from std.collections import InlineArray


@always_inline
def _adc(a: UInt64, b: UInt64, carry: UInt64) -> Tuple[UInt64, UInt64]:
    """(a + b + carry) as (low 64 bits, carry out)."""
    var s = UInt128(a) + UInt128(b) + UInt128(carry)
    return (UInt64(s), UInt64(s >> 64))


@always_inline
def _sbb(a: UInt64, b: UInt64, borrow: UInt64) -> Tuple[UInt64, UInt64]:
    """(a - b - borrow) as (low 64 bits, borrow out in {0, 1})."""
    var d = UInt128(a) - UInt128(b) - UInt128(borrow)
    return (UInt64(d), UInt64(d >> 127))


@always_inline
def _mac(t: UInt64, a: UInt64, b: UInt64, carry: UInt64) -> Tuple[UInt64, UInt64]:
    """t + a * b + carry (cannot overflow 128 bits) as (low, high)."""
    var s = UInt128(t) + UInt128(a) * UInt128(b) + UInt128(carry)
    return (UInt64(s), UInt64(s >> 64))


struct Modulus[N: Int](Copyable, Movable):
    """An odd modulus of 64*N bits with its Montgomery constants (R = 2^(64N))."""
    var m: InlineArray[UInt64, Self.N]
    var r2: InlineArray[UInt64, Self.N]   # R^2 mod m
    var m0inv: UInt64                # -m^-1 mod 2^64

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
    """8*N big-endian bytes at b[off:] → limbs (least significant first)."""
    var a = InlineArray[UInt64, N](fill=0)
    for i in range(N):
        var o = off + 8 * (N - 1 - i)
        var v: UInt64 = 0
        for j in range(8):
            v = (v << 8) | UInt64(b[o + j])
        a[i] = v
    return a^


def limbs_to_be[N: Int](a: InlineArray[UInt64, N]) -> List[UInt8]:
    var out = List[UInt8](capacity=8 * N)
    for i in range(N - 1, -1, -1):
        for j in range(7, -1, -1):
            out.append(UInt8((a[i] >> UInt64(8 * j)) & 0xFF))
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
    comptime for i in range(N):
        acc |= a[i]
    return ((acc | (UInt64(0) - acc)) >> 63) ^ 1


@always_inline
def lt[N: Int](a: InlineArray[UInt64, N], b: InlineArray[UInt64, N]) -> UInt64:
    """1 if a < b else 0 (borrow of a - b), without branching."""
    var borrow: UInt64 = 0
    comptime for i in range(N):
        borrow = _sbb(a[i], b[i], borrow)[1]
    return borrow


@always_inline
def select[N: Int](mask: UInt64, a: InlineArray[UInt64, N], b: InlineArray[UInt64, N]) -> InlineArray[UInt64, N]:
    """a where mask is all ones, b where mask is zero."""
    var r = InlineArray[UInt64, N](fill=0)
    comptime for i in range(N):
        r[i] = (a[i] & mask) | (b[i] & ~mask)
    return r^


@always_inline
def cswap[N: Int](mut a: InlineArray[UInt64, N], mut b: InlineArray[UInt64, N], bit: UInt64):
    var mask = UInt64(0) - bit
    comptime for i in range(N):
        var t = (a[i] ^ b[i]) & mask
        a[i] ^= t
        b[i] ^= t


@always_inline
def _sub_m_if[N: Int](r: InlineArray[UInt64, N], hi: UInt64, md: Modulus[N]) -> InlineArray[UInt64, N]:
    """r + hi*R, reduced by one conditional subtraction of m."""
    var d = InlineArray[UInt64, N](fill=0)
    var borrow: UInt64 = 0
    comptime for i in range(N):
        var sb = _sbb(r[i], md.m[i], borrow)
        d[i] = sb[0]
        borrow = sb[1]
    var use_d = hi | (borrow ^ 1)
    return select(UInt64(0) - use_d, d, r)


@always_inline
def reduce_once[N: Int](a: InlineArray[UInt64, N], md: Modulus[N]) -> InlineArray[UInt64, N]:
    """a mod m for a < 2m."""
    return _sub_m_if(a, 0, md)


# ============================================================================
# Field arithmetic (inputs and outputs in [0, m))
# ============================================================================

@always_inline
def add[N: Int](a: InlineArray[UInt64, N], b: InlineArray[UInt64, N], md: Modulus[N]) -> InlineArray[UInt64, N]:
    var r = InlineArray[UInt64, N](fill=0)
    var c: UInt64 = 0
    comptime for i in range(N):
        var s = _adc(a[i], b[i], c)
        r[i] = s[0]
        c = s[1]
    return _sub_m_if(r, c, md)


@always_inline
def sub[N: Int](a: InlineArray[UInt64, N], b: InlineArray[UInt64, N], md: Modulus[N]) -> InlineArray[UInt64, N]:
    var r = InlineArray[UInt64, N](fill=0)
    var borrow: UInt64 = 0
    comptime for i in range(N):
        var d = _sbb(a[i], b[i], borrow)
        r[i] = d[0]
        borrow = d[1]
    # add m back when a < b
    var mask = UInt64(0) - borrow
    var c: UInt64 = 0
    comptime for i in range(N):
        var s = _adc(r[i], md.m[i] & mask, c)
        r[i] = s[0]
        c = s[1]
    return r^


@always_inline
def mont_mul[N: Int](a: InlineArray[UInt64, N], b: InlineArray[UInt64, N], md: Modulus[N]) -> InlineArray[UInt64, N]:
    """a * b * R^-1 mod m (CIOS Montgomery multiplication)."""
    var t = InlineArray[UInt64, N + 2](fill=0)
    comptime for i in range(N):
        var bi = b[i]
        var c: UInt64 = 0
        comptime for j in range(N):
            var uv = _mac(t[j], a[j], bi, c)
            t[j] = uv[0]
            c = uv[1]
        var top = _adc(t[N], c, 0)
        t[N] = top[0]
        t[N + 1] = top[1]
        var mq = t[0] * md.m0inv  # mod 2^64
        var uv = _mac(t[0], mq, md.m[0], 0)
        c = uv[1]
        comptime for j in range(1, N):
            uv = _mac(t[j], mq, md.m[j], c)
            t[j - 1] = uv[0]
            c = uv[1]
        var hi = _adc(t[N], c, 0)
        t[N - 1] = hi[0]
        t[N] = t[N + 1] + hi[1]
        t[N + 1] = 0
    var r = InlineArray[UInt64, N](fill=0)
    comptime for i in range(N):
        r[i] = t[i]
    return _sub_m_if(r, t[N], md)


@always_inline
def to_mont[N: Int](a: InlineArray[UInt64, N], md: Modulus[N]) -> InlineArray[UInt64, N]:
    return mont_mul(a, md.r2, md)


@always_inline
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
    for i in range(64 * N - 1, -1, -1):
        r = mont_mul(r, r, md)
        if (e[i >> 6] >> UInt64(i & 63)) & 1 == 1:
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


def p256_curve() -> Curve[4]:
    return Curve[4](
        Modulus[4](
            [0xFFFFFFFFFFFFFFFF, 0x00000000FFFFFFFF, 0x0000000000000000, 0xFFFFFFFF00000001],
            [0x0000000000000003, 0xFFFFFFFBFFFFFFFF, 0xFFFFFFFFFFFFFFFE, 0x00000004FFFFFFFD],
            0x0000000000000001,
        ),
        Modulus[4](
            [0xF3B9CAC2FC632551, 0xBCE6FAADA7179E84, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFF00000000],
            [0x83244C95BE79EEA2, 0x4699799C49BD6FA6, 0x2845B2392B6BEC59, 0x66E12D94F3D95620],
            0xCCD1C8AAEE00BC4F,
        ),
        "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B",
        "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296",
        "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5",
    )


def p384_curve() -> Curve[6]:
    return Curve[6](
        Modulus[6](
            [0x00000000FFFFFFFF, 0xFFFFFFFF00000000, 0xFFFFFFFFFFFFFFFE,
             0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF],
            [0xFFFFFFFE00000001, 0x0000000200000000, 0xFFFFFFFE00000000,
             0x0000000200000000, 0x0000000000000001, 0x0000000000000000],
            0x0000000100000001,
        ),
        Modulus[6](
            [0xECEC196ACCC52973, 0x581A0DB248B0A77A, 0xC7634D81F4372DDF,
             0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF],
            [0x2D319B2419B409A9, 0xFF3D81E5DF1AA419, 0xBC3E483AFCB82947,
             0xD40D49174AAB1CC5, 0x3FB05B7A28266895, 0x0C84EE012B39BF21],
            0x6ED46089E88FDC45,
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
    """k * p for an 8N-byte big-endian scalar: Montgomery ladder, 64N steps."""
    var r0 = Point[N](InlineArray[UInt64, N](fill=0), mont_one(c.field), InlineArray[UInt64, N](fill=0))
    var r1 = p.copy()
    for i in range(64 * N - 1, -1, -1):
        var bit = UInt64((k[8 * N - 1 - (i >> 3)] >> UInt8(i & 7)) & 1)
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
    """1 <= k < m for an 8N-byte big-endian k, decided without branching on k."""
    var a = limbs_from_be[N](k, 0)
    return (lt(a, md.m) & (is_zero(a) ^ 1)) == 1


def public_key[N: Int](private_key: List[UInt8], c: Curve[N]) raises -> List[UInt8]:
    """Uncompressed public key 04 || X || Y for a private scalar in [1, n-1]."""
    if len(private_key) != 8 * N or not scalar_in_range(private_key, c.order):
        raise Error("ec: private key out of range")
    var aff = to_affine(scalar_mult(private_key, c.g, c), c.field)
    var out = List[UInt8](capacity=1 + 16 * N)
    out.append(0x04)
    var xb = limbs_to_be(aff[0])
    var yb = limbs_to_be(aff[1])
    for i in range(8 * N):
        out.append(xb[i])
    for i in range(8 * N):
        out.append(yb[i])
    return out^


def ecdh_x[N: Int](private_key: List[UInt8], peer_public_key: List[UInt8], c: Curve[N]) raises -> List[UInt8]:
    """x-coordinate of private_key * peer. The caller must already have
    checked that peer_public_key is a valid uncompressed point on the curve."""
    if len(private_key) != 8 * N or not scalar_in_range(private_key, c.order):
        raise Error("ec: private key out of range")
    var peer = Point[N](
        to_mont(limbs_from_be[N](peer_public_key, 1), c.field),
        to_mont(limbs_from_be[N](peer_public_key, 1 + 8 * N), c.field),
        mont_one(c.field),
    )
    var aff = to_affine(scalar_mult(private_key, peer, c), c.field)
    return limbs_to_be(aff[0])


# ============================================================================
# ECDSA verification (public data only: variable time is fine here)
# ============================================================================

def _scalar_bytes[N: Int](v: List[UInt8], name: String, prefix: String) raises -> InlineArray[UInt64, N]:
    """A big-endian integer of any length (leading zeros allowed) as N limbs;
    raises "<prefix>: <name> out of range" if it does not fit."""
    var start = 0
    while start < len(v) and v[start] == 0:
        start += 1
    var n = len(v) - start
    if n > 8 * N:
        raise Error(prefix + ": " + name + " out of range")
    var padded = List[UInt8](length=8 * N, fill=0)
    for i in range(n):
        padded[8 * N - n + i] = v[start + i]
    return limbs_from_be[N](padded, 0)


@always_inline
def _bit[N: Int](a: InlineArray[UInt64, N], i: Int) -> Int:
    return Int((a[i >> 6] >> UInt64(i & 63)) & 1)


def ecdsa_verify[N: Int](
    c: Curve[N], pub_key: List[UInt8], msg_hash: List[UInt8],
    sig_r: List[UInt8], sig_s: List[UInt8], prefix: String,
) raises:
    """Verify an ECDSA signature (r, s) on msg_hash with the uncompressed
    public key 04 || X || Y. Raises on any invalid input or signature.

    msg_hash longer than the order is truncated to its leftmost 8N bytes,
    shorter is the same integer (FIPS 186-5 §6.4.2). R = u1*G + u2*Q is
    computed with one shared doubling chain (Shamir's trick) and the complete
    formulas, so the identity and P == Q need no special cases."""
    var fm = c.field.copy()
    var om = c.order.copy()
    if len(pub_key) != 1 + 16 * N or pub_key[0] != 0x04:
        raise Error(
            prefix + ": invalid public key format (need " + String(1 + 16 * N)
            + "-byte uncompressed)"
        )
    var qx = limbs_from_be[N](pub_key, 1)
    var qy = limbs_from_be[N](pub_key, 1 + 8 * N)
    if lt(qx, fm.m) == 0 or lt(qy, fm.m) == 0:
        raise Error(prefix + ": public key coordinate out of range")
    var xm = to_mont(qx, fm)
    var ym = to_mont(qy, fm)
    # y^2 == x^3 - 3x + b
    var lhs = mont_mul(ym, ym, fm)
    var x3 = mont_mul(mont_mul(xm, xm, fm), xm, fm)
    var three_x = add(add(xm, xm, fm), xm, fm)
    var rhs = add(sub(x3, three_x, fm), c.b, fm)
    if is_zero(sub(lhs, rhs, fm)) == 0:
        raise Error(prefix + ": public key not on curve")

    var r = _scalar_bytes[N](sig_r, "r", prefix)
    var s = _scalar_bytes[N](sig_s, "s", prefix)
    if is_zero(r) == 1 or lt(r, om.m) == 0:
        raise Error(prefix + ": r out of range")
    if is_zero(s) == 1 or lt(s, om.m) == 0:
        raise Error(prefix + ": s out of range")

    # e: leftmost 8N bytes of the hash (left-padded if shorter), mod n
    var eb = List[UInt8](length=8 * N, fill=0)
    var take = min(len(msg_hash), 8 * N)
    for i in range(take):
        eb[8 * N - take + i] = msg_hash[i]
    var e = reduce_once(limbs_from_be[N](eb, 0), om)  # e < 2^(64N) < 2n

    # w = s^-1, u1 = e w, u2 = r w (mod n)
    var w = mont_inv(to_mont(s, om), om)
    var u1 = from_mont(mont_mul(to_mont(e, om), w, om), om)
    var u2 = from_mont(mont_mul(to_mont(r, om), w, om), om)

    var q = Point[N](xm, ym, mont_one(fm))
    var gq = point_add(c.g, q, c.b, fm)
    var acc = Point[N](InlineArray[UInt64, N](fill=0), mont_one(fm), InlineArray[UInt64, N](fill=0))
    var top = 64 * N - 1
    while top >= 0 and _bit(u1, top) == 0 and _bit(u2, top) == 0:
        top -= 1
    for i in range(top, -1, -1):
        acc = point_double(acc, c.b, fm)
        var b1 = _bit(u1, i)
        var b2 = _bit(u2, i)
        if b1 == 1 and b2 == 1:
            acc = point_add(acc, gq, c.b, fm)
        elif b1 == 1:
            acc = point_add(acc, c.g, c.b, fm)
        elif b2 == 1:
            acc = point_add(acc, q, c.b, fm)
    if is_zero(acc.z) == 1:
        raise Error(prefix + ": ECDSA verify failed — R is infinity")
    var x_aff = from_mont(mont_mul(acc.x, mont_inv(acc.z, fm), fm), fm)
    var rx = reduce_once(x_aff, om)  # x < p < 2n
    if is_zero(sub(rx, r, om)) == 0:
        raise Error(prefix + ": ECDSA signature invalid")
