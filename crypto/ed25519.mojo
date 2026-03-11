# ============================================================================
# crypto/ed25519.mojo — Ed25519 signatures (RFC 8032)
# ============================================================================
#
# Curve: Twisted Edwards  -x² + y² = 1 + d·x²·y²  over GF(2²⁵⁵ - 19)
#   d = -121665/121666 mod p
#   p = 2²⁵⁵ - 19
#   L = 2²⁵² + 27742317777372141416604633099232577417  (group order)
#   G = base point with y = 4/5 mod p (encoded as specific 32-byte value)
#
# Reuses Fe field arithmetic from curve25519.mojo (same field GF(2²⁵⁵-19)).
# Requires sha512 from hash.mojo.
#
# Public API:
#   ed25519_sign(privkey, msg)   -> 64-byte signature
#   ed25519_verify(pubkey, msg, sig) raises -> Bool
# ============================================================================

from crypto.curve25519 import Fe, fe_zero, fe_one, fe_add, fe_sub, fe_mul, fe_sq, fe_inv, fe_cswap, fe_from_bytes, fe_to_bytes, fe_carry, fe_reduce, fe_mul_scalar
from crypto.hash import sha512


# ============================================================================
# Extended Edwards point: (X:Y:Z:T) — x = X/Z, y = Y/Z, T = X*Y/Z
# ============================================================================

struct EdPoint(Copyable, Movable):
    var x: Fe
    var y: Fe
    var z: Fe
    var t: Fe

    fn __init__(out self):
        self.x = fe_zero()
        self.y = fe_one()
        self.z = fe_one()
        self.t = fe_zero()

    fn __copyinit__(out self, copy: Self):
        self.x = copy.x.copy()
        self.y = copy.y.copy()
        self.z = copy.z.copy()
        self.t = copy.t.copy()

    fn __moveinit__(out self, deinit take: Self):
        self.x = take.x^
        self.y = take.y^
        self.z = take.z^
        self.t = take.t^


# ============================================================================
# Curve constants
# ============================================================================

fn _fe_d() -> Fe:
    """d = -121665/121666 mod p (RFC 8032 §5.1, little-endian)."""
    # d = 37095705934669439343138083508754565189542113879843219016388785533085940283555
    # big-endian hex: 52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3
    # Bytes: a3 78 59 13 ca 4d eb 75 ab d8 41 41 4d 0a 70 00
    #        98 e8 79 77 79 40 c7 8c 73 fe 6f 2b ee 6c 03 52
    var b = List[UInt8](capacity=32)
    b.append(0xa3); b.append(0x78); b.append(0x59); b.append(0x13)
    b.append(0xca); b.append(0x4d); b.append(0xeb); b.append(0x75)
    b.append(0xab); b.append(0xd8); b.append(0x41); b.append(0x41)
    b.append(0x4d); b.append(0x0a); b.append(0x70); b.append(0x00)
    b.append(0x98); b.append(0xe8); b.append(0x79); b.append(0x77)
    b.append(0x79); b.append(0x40); b.append(0xc7); b.append(0x8c)
    b.append(0x73); b.append(0xfe); b.append(0x6f); b.append(0x2b)
    b.append(0xee); b.append(0x6c); b.append(0x03); b.append(0x52)
    return fe_from_bytes(b)


fn _fe_d2() -> Fe:
    """2*d mod p."""
    return fe_add(_fe_d(), _fe_d())


fn _ed_base_point() -> EdPoint:
    """Generator point G (RFC 8032 §5.1)."""
    # G_y in little-endian
    var gy_b = List[UInt8](capacity=32)
    gy_b.append(0x58); gy_b.append(0x66); gy_b.append(0x66); gy_b.append(0x66)
    gy_b.append(0x66); gy_b.append(0x66); gy_b.append(0x66); gy_b.append(0x66)
    gy_b.append(0x66); gy_b.append(0x66); gy_b.append(0x66); gy_b.append(0x66)
    gy_b.append(0x66); gy_b.append(0x66); gy_b.append(0x66); gy_b.append(0x66)
    gy_b.append(0x66); gy_b.append(0x66); gy_b.append(0x66); gy_b.append(0x66)
    gy_b.append(0x66); gy_b.append(0x66); gy_b.append(0x66); gy_b.append(0x66)
    gy_b.append(0x66); gy_b.append(0x66); gy_b.append(0x66); gy_b.append(0x66)
    gy_b.append(0x66); gy_b.append(0x66); gy_b.append(0x66); gy_b.append(0x66)
    var gy = fe_from_bytes(gy_b)
    # Recover x from y using the curve equation: x² = (y²-1)/(d*y²+1)
    return _ed_decompress_x(gy, 0)  # sign bit = 0


# ============================================================================
# Compressed point encoding/decoding
# ============================================================================

fn _ed_compress(p: EdPoint) -> List[UInt8]:
    """Compress an extended point to 32 bytes: y || sign(x)."""
    var zi = fe_inv(p.z.copy())
    var x = fe_mul(p.x.copy(), zi.copy())
    var y = fe_mul(p.y.copy(), zi)
    var out = fe_to_bytes(y)
    # Set high bit of last byte to sign of x (bit 0 of canonical x)
    var xb = fe_to_bytes(x)
    out[31] = out[31] | (xb[0] & 1) << 7
    return out^


fn _fe_sqrt_m1() -> Fe:
    """sqrt(-1) = 2^((p-1)/4) mod p — Tonelli-Shanks correction constant."""
    # Value: 19681161376707505956807079304988542015446066515923890162744021073123829784752
    # Little-endian bytes: b0 a0 0e 4a 27 1b ee c4 78 e4 2f ad 06 18 43 2f
    #                      a7 d7 fb 3d 99 00 4d 2b 0b df c1 4f 80 24 83 2b
    var b = List[UInt8](capacity=32)
    b.append(0xb0); b.append(0xa0); b.append(0x0e); b.append(0x4a)
    b.append(0x27); b.append(0x1b); b.append(0xee); b.append(0xc4)
    b.append(0x78); b.append(0xe4); b.append(0x2f); b.append(0xad)
    b.append(0x06); b.append(0x18); b.append(0x43); b.append(0x2f)
    b.append(0xa7); b.append(0xd7); b.append(0xfb); b.append(0x3d)
    b.append(0x99); b.append(0x00); b.append(0x4d); b.append(0x2b)
    b.append(0x0b); b.append(0xdf); b.append(0xc1); b.append(0x4f)
    b.append(0x80); b.append(0x24); b.append(0x83); b.append(0x2b)
    return fe_from_bytes(b)


fn _fe_is_nonzero(a: Fe) -> Bool:
    """Return True if a != 0 mod p."""
    var b = fe_to_bytes(fe_reduce(a))
    for i in range(32):
        if b[i] != 0:
            return True
    return False


fn _ed_decompress_x(y: Fe, sign: UInt8) -> EdPoint:
    """Recover x from y and sign bit. Returns identity on failure."""
    # x² = (y²-1) / (d·y²+1)
    var y2 = fe_sq(y.copy())
    var u = fe_sub(y2.copy(), fe_one())          # y² - 1
    var v = fe_add(fe_mul(_fe_d(), y2), fe_one())  # d·y² + 1
    # Candidate: x = u*v³*(u*v^7)^((p-5)/8)  (Tonelli-Shanks for p ≡ 5 mod 8)
    var v3 = fe_mul(fe_sq(v.copy()), v.copy())
    var uv3 = fe_mul(u.copy(), v3.copy())
    var v7 = fe_mul(fe_sq(v3.copy()), v.copy())
    var uv7 = fe_mul(u.copy(), v7)
    var x = fe_mul(uv3, _fe_pow_p58(uv7))
    # Tonelli-Shanks correction: check if v*x² = u; if v*x² = -u, scale by sqrt(-1)
    var vx2 = fe_mul(v.copy(), fe_sq(x.copy()))
    var check = fe_sub(vx2, u.copy())
    if _fe_is_nonzero(check):
        x = fe_mul(x, _fe_sqrt_m1())
    # Fix sign of x
    var xb = fe_to_bytes(x.copy())
    if Int(xb[0] & 1) != Int(sign & 1):
        x = fe_sub(fe_zero(), x)
    var p = EdPoint()
    p.x = x^
    p.y = y.copy()
    p.z = fe_one()
    p.t = fe_mul(p.x.copy(), p.y.copy())
    return p^


fn _fe_pow_p58(z: Fe) -> Fe:
    """Compute z^((p-5)/8) mod p — used for square root in Ed25519 decode.
    Addition chain from RFC 8032 §5.1.3 / standard Curve25519 chain."""
    var z2_1 = fe_sq(z.copy())
    var z2_2 = fe_sq(z2_1.copy())
    var z2_3 = fe_sq(z2_2.copy())
    var b9 = fe_mul(z2_3, z.copy())   # z^9 = z^(2^3+1) ... actually z^(1+8)
    var b11 = fe_mul(b9.copy(), z2_1.copy())  # z^11
    var b22 = fe_sq(b11.copy())
    var b31 = fe_mul(b22, b9)          # z^(2^5-1)
    var z2_5_0 = b31.copy()

    var t2 = fe_sq(z2_5_0.copy()); t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy())
    t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy())
    t2 = fe_mul(t2, z2_5_0.copy())
    var z2_10_0 = t2.copy()

    t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy())
    t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy())
    t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy())
    t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy())
    t2 = fe_mul(t2, z2_10_0.copy())
    var z2_20_0 = t2.copy()

    t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy())
    t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy())
    t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy())
    t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy())
    t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy())
    t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy())
    t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy())
    t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy())
    t2 = fe_mul(t2, z2_20_0)
    var z2_40_0 = t2.copy()

    t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy())
    t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy())
    t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy())
    t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy())
    t2 = fe_mul(t2, z2_10_0)
    var z2_50_0 = t2.copy()

    t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy())
    t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy())
    t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy())
    t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy())
    t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy())
    t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy())
    t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy())
    t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy())
    t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy())
    t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy())
    t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy())
    t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy())
    t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy())
    t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy())
    t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy())
    t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy())
    t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy())
    t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy())
    t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy())
    t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy())
    t2 = fe_mul(t2, z2_50_0.copy())
    var z2_100_0 = t2.copy()

    # 100 squarings: z^(2^100-1) -> z^(2^200-1)
    t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy())
    t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy())
    t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy())
    t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy())
    t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy())
    t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy())
    t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy())
    t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy())
    t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy())
    t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy())
    t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy())
    t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy())
    t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy())
    t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy())
    t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy())
    t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy())
    t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy())
    t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy())
    t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy())
    t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy())
    t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy())
    t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy())
    t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy())
    t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy())
    t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy())
    t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy())
    t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy())
    t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy())
    t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy())
    t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy())
    t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy())
    t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy())
    t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy())
    t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy())
    t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy())
    t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy())
    t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy())
    t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy())
    t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy())
    t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy())
    t2 = fe_mul(t2, z2_100_0)

    t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy())
    t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy())
    t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy())
    t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy())
    t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy())
    t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy())
    t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy())
    t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy())
    t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy())
    t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy())
    t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy())
    t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy())
    t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy())
    t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy())
    t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy())
    t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy())
    t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy())
    t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy())
    t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy())
    t2 = fe_sq(t2.copy()); t2 = fe_sq(t2.copy())
    t2 = fe_mul(t2, z2_50_0)

    # Final 2 squarings: z^(2^252-3) = (p-5)/8
    t2 = fe_sq(t2.copy())
    t2 = fe_sq(t2.copy())
    return fe_mul(t2, z)


# ============================================================================
# Ed25519 point decompression (public)
# ============================================================================

fn _ed_decode_point(b: List[UInt8]) raises -> EdPoint:
    """Decompress a 32-byte encoded point. Raises if not on curve."""
    var sign = (b[31] >> 7) & 1
    var yb = b.copy()
    yb[31] &= 0x7F  # clear sign bit
    var y = fe_from_bytes(yb)
    var p = _ed_decompress_x(y, sign)

    # Validate: check the point is on the curve: -x²+y² == 1 + d·x²·y²
    var x2 = fe_sq(p.x.copy())
    var y2 = fe_sq(p.y.copy())
    var lhs = fe_sub(y2.copy(), x2.copy())             # y² - x²
    var rhs = fe_add(fe_one(), fe_mul(fe_mul(_fe_d(), x2), y2))  # 1 + d·x²·y²
    var lhs_b = fe_to_bytes(fe_reduce(lhs))
    var rhs_b = fe_to_bytes(fe_reduce(rhs))
    for i in range(32):
        if lhs_b[i] != rhs_b[i]:
            raise Error("Ed25519: point not on curve")
    return p^


# ============================================================================
# Edwards point addition (unified, extended coordinates)
# Hisil et al. "Twisted Edwards Curves Revisited", §3.1 (2008)
# ============================================================================

fn _ed_add(p: EdPoint, q: EdPoint) -> EdPoint:
    """Unified addition of two extended Edwards points."""
    var d2 = _fe_d2()
    var A = fe_mul(fe_sub(p.y.copy(), p.x.copy()), fe_sub(q.y.copy(), q.x.copy()))
    var B = fe_mul(fe_add(p.y.copy(), p.x.copy()), fe_add(q.y.copy(), q.x.copy()))
    var C = fe_mul(p.t.copy(), fe_mul(d2, q.t.copy()))
    var D = fe_mul(fe_mul_scalar(p.z.copy(), 2), q.z.copy())
    var E = fe_sub(B.copy(), A.copy())
    var F = fe_sub(D.copy(), C.copy())
    var G2 = fe_add(D.copy(), C.copy())
    var H = fe_add(B.copy(), A.copy())
    var r = EdPoint()
    r.x = fe_mul(E.copy(), F.copy())
    r.y = fe_mul(G2.copy(), H.copy())
    r.z = fe_mul(F.copy(), G2.copy())
    r.t = fe_mul(E.copy(), H.copy())
    return r^


fn _ed_double(p: EdPoint) -> EdPoint:
    """Point doubling in extended coordinates (dedicated formula, faster)."""
    var A = fe_sq(p.x.copy())
    var B = fe_sq(p.y.copy())
    var C = fe_mul_scalar(fe_sq(p.z.copy()), 2)
    var H = fe_add(A.copy(), B.copy())
    var E = fe_sub(H.copy(), fe_sq(fe_add(p.x.copy(), p.y.copy())))
    var G2 = fe_sub(A.copy(), B.copy())
    var F = fe_add(C.copy(), G2.copy())
    var r = EdPoint()
    r.x = fe_mul(E.copy(), F.copy())
    r.y = fe_mul(G2.copy(), H.copy())
    r.z = fe_mul(F.copy(), G2.copy())
    r.t = fe_mul(E.copy(), H.copy())
    return r^


# ============================================================================
# Scalar multiply (constant-time double-and-add, MSB first)
# ============================================================================

fn _ed_scalar_mul(scalar: List[UInt8], p: EdPoint) -> EdPoint:
    """Constant-time scalar multiply: returns scalar * p."""
    var r = EdPoint()   # identity: (0:1:1:0)
    var q = p.copy()
    # Process 255 bits, MSB first (bit 254 down to bit 0)
    for i in range(254, -1, -1):
        var byte_idx = i >> 3
        var bit_idx = UInt64(i & 7)
        var bit = UInt64((UInt64(scalar[byte_idx]) >> bit_idx) & 1)
        # Constant-time select: conditionally swap r and q, add, swap back
        _ed_cswap(r, q, bit)
        q = _ed_add(r.copy(), q)
        r = _ed_double(r)
        _ed_cswap(r, q, bit)
    return r^


fn _ed_cswap(mut a: EdPoint, mut b: EdPoint, swap: UInt64):
    """Constant-time conditional swap of two EdPoints."""
    fe_cswap(a.x, b.x, swap)
    fe_cswap(a.y, b.y, swap)
    fe_cswap(a.z, b.z, swap)
    fe_cswap(a.t, b.t, swap)


fn _ed_base_mul(scalar: List[UInt8]) -> EdPoint:
    """Compute scalar * G (base point multiply)."""
    return _ed_scalar_mul(scalar, _ed_base_point())


# ============================================================================
# Scalar arithmetic mod L (group order)
# L = 2^252 + 27742317777372141416604633099232577417
#   = 2^252 + 0x14def9dea2f79cd65812631a5cf5d3ed  (little-endian)
# ============================================================================

fn _scalar_reduce(s: List[UInt8]) -> List[UInt8]:
    """Reduce an up-to-64-byte scalar mod L, returning 32 bytes (little-endian).
    Uses the RFC 8032 §5.1.5 / SUPERCOP 21-bit limb schoolbook method."""
    var sb = s.copy()
    while len(sb) < 64:
        sb.append(0)

    var s0:  Int64 = Int64( UInt64(sb[0])  | (UInt64(sb[1]) << 8) | (UInt64(sb[2]) << 16)) & Int64(0x1FFFFF)
    var s1:  Int64 = (Int64(UInt64(sb[2]) >> 5) | Int64(UInt64(sb[3]) << 3) | Int64(UInt64(sb[4]) << 11) | Int64(UInt64(sb[5]) << 19)) & Int64(0x1FFFFF)
    var s2:  Int64 = (Int64(UInt64(sb[5]) >> 2) | Int64(UInt64(sb[6]) << 6) | Int64(UInt64(sb[7]) << 14)) & Int64(0x1FFFFF)
    var s3:  Int64 = (Int64(UInt64(sb[7]) >> 7) | Int64(UInt64(sb[8]) << 1) | Int64(UInt64(sb[9]) << 9) | Int64(UInt64(sb[10]) << 17)) & Int64(0x1FFFFF)
    var s4:  Int64 = (Int64(UInt64(sb[10]) >> 4) | Int64(UInt64(sb[11]) << 4) | Int64(UInt64(sb[12]) << 12) | Int64(UInt64(sb[13]) << 20)) & Int64(0x1FFFFF)
    var s5:  Int64 = (Int64(UInt64(sb[13]) >> 1) | Int64(UInt64(sb[14]) << 7) | Int64(UInt64(sb[15]) << 15)) & Int64(0x1FFFFF)
    var s6:  Int64 = (Int64(UInt64(sb[15]) >> 6) | Int64(UInt64(sb[16]) << 2) | Int64(UInt64(sb[17]) << 10) | Int64(UInt64(sb[18]) << 18)) & Int64(0x1FFFFF)
    var s7:  Int64 = (Int64(UInt64(sb[18]) >> 3) | Int64(UInt64(sb[19]) << 5) | Int64(UInt64(sb[20]) << 13)) & Int64(0x1FFFFF)
    var s8:  Int64 = Int64(UInt64(sb[21]) | (UInt64(sb[22]) << 8) | (UInt64(sb[23]) << 16)) & Int64(0x1FFFFF)
    var s9:  Int64 = (Int64(UInt64(sb[23]) >> 5) | Int64(UInt64(sb[24]) << 3) | Int64(UInt64(sb[25]) << 11) | Int64(UInt64(sb[26]) << 19)) & Int64(0x1FFFFF)
    var s10: Int64 = (Int64(UInt64(sb[26]) >> 2) | Int64(UInt64(sb[27]) << 6) | Int64(UInt64(sb[28]) << 14)) & Int64(0x1FFFFF)
    var s11: Int64 = (Int64(UInt64(sb[28]) >> 7) | Int64(UInt64(sb[29]) << 1) | Int64(UInt64(sb[30]) << 9) | Int64(UInt64(sb[31]) << 17)) & Int64(0x1FFFFF)
    var s12: Int64 = (Int64(UInt64(sb[31]) >> 4) | Int64(UInt64(sb[32]) << 4) | Int64(UInt64(sb[33]) << 12) | Int64(UInt64(sb[34]) << 20)) & Int64(0x1FFFFF)
    var s13: Int64 = (Int64(UInt64(sb[34]) >> 1) | Int64(UInt64(sb[35]) << 7) | Int64(UInt64(sb[36]) << 15)) & Int64(0x1FFFFF)
    var s14: Int64 = (Int64(UInt64(sb[36]) >> 6) | Int64(UInt64(sb[37]) << 2) | Int64(UInt64(sb[38]) << 10) | Int64(UInt64(sb[39]) << 18)) & Int64(0x1FFFFF)
    var s15: Int64 = (Int64(UInt64(sb[39]) >> 3) | Int64(UInt64(sb[40]) << 5) | Int64(UInt64(sb[41]) << 13)) & Int64(0x1FFFFF)
    var s16: Int64 = Int64(UInt64(sb[42]) | (UInt64(sb[43]) << 8) | (UInt64(sb[44]) << 16)) & Int64(0x1FFFFF)
    var s17: Int64 = (Int64(UInt64(sb[44]) >> 5) | Int64(UInt64(sb[45]) << 3) | Int64(UInt64(sb[46]) << 11) | Int64(UInt64(sb[47]) << 19)) & Int64(0x1FFFFF)
    var s18: Int64 = (Int64(UInt64(sb[47]) >> 2) | Int64(UInt64(sb[48]) << 6) | Int64(UInt64(sb[49]) << 14)) & Int64(0x1FFFFF)
    var s19: Int64 = (Int64(UInt64(sb[49]) >> 7) | Int64(UInt64(sb[50]) << 1) | Int64(UInt64(sb[51]) << 9) | Int64(UInt64(sb[52]) << 17)) & Int64(0x1FFFFF)
    var s20: Int64 = (Int64(UInt64(sb[52]) >> 4) | Int64(UInt64(sb[53]) << 4) | Int64(UInt64(sb[54]) << 12) | Int64(UInt64(sb[55]) << 20)) & Int64(0x1FFFFF)
    var s21: Int64 = (Int64(UInt64(sb[55]) >> 1) | Int64(UInt64(sb[56]) << 7) | Int64(UInt64(sb[57]) << 15)) & Int64(0x1FFFFF)
    var s22: Int64 = (Int64(UInt64(sb[57]) >> 6) | Int64(UInt64(sb[58]) << 2) | Int64(UInt64(sb[59]) << 10) | Int64(UInt64(sb[60]) << 18)) & Int64(0x1FFFFF)
    var s23: Int64 = Int64(UInt64(sb[60]) >> 3) | Int64(UInt64(sb[61]) << 5) | Int64(UInt64(sb[62]) << 13) | Int64(UInt64(sb[63]) << 21)

    # From SUPERCOP / NaCl: reduction constants (mu × L_inverse components)
    # The s_i coefficients for reducing 2^(21*k) mod L for k=12..23
    # These are the precomputed values from crypto_sign/ed25519/ref/sc_reduce.c
    # s23 reduction: 2^(21*23) = 2^483 ≡ mu23 * (-c) terms
    # Use the standard ed25519 reduce constants (from SUPERCOP):
    s11 += s23 * Int64(666643)
    s12 += s23 * Int64(470296)
    s13 += s23 * Int64(654183)
    s14 -= s23 * Int64(997805)
    s15 += s23 * Int64(136657)
    s16 -= s23 * Int64(683901)

    s10 += s22 * Int64(666643)
    s11 += s22 * Int64(470296)
    s12 += s22 * Int64(654183)
    s13 -= s22 * Int64(997805)
    s14 += s22 * Int64(136657)
    s15 -= s22 * Int64(683901)

    s9  += s21 * Int64(666643)
    s10 += s21 * Int64(470296)
    s11 += s21 * Int64(654183)
    s12 -= s21 * Int64(997805)
    s13 += s21 * Int64(136657)
    s14 -= s21 * Int64(683901)

    s8  += s20 * Int64(666643)
    s9  += s20 * Int64(470296)
    s10 += s20 * Int64(654183)
    s11 -= s20 * Int64(997805)
    s12 += s20 * Int64(136657)
    s13 -= s20 * Int64(683901)

    s7  += s19 * Int64(666643)
    s8  += s19 * Int64(470296)
    s9  += s19 * Int64(654183)
    s10 -= s19 * Int64(997805)
    s11 += s19 * Int64(136657)
    s12 -= s19 * Int64(683901)

    s6  += s18 * Int64(666643)
    s7  += s18 * Int64(470296)
    s8  += s18 * Int64(654183)
    s9  -= s18 * Int64(997805)
    s10 += s18 * Int64(136657)
    s11 -= s18 * Int64(683901)
    s18 = 0

    # Carry propagation round 1: extend to s6..s17→s18 to bound s12..s17 before Phase 2
    # fold. Without this, s12..s17 can reach ~5e13 and s_k * fold_const overflows Int64.
    var carry6  = (s6  + Int64(1 << 20)) >> 21; s7  += carry6;  s6  -= carry6  << 21
    var carry7  = (s7  + Int64(1 << 20)) >> 21; s8  += carry7;  s7  -= carry7  << 21
    var carry8  = (s8  + Int64(1 << 20)) >> 21; s9  += carry8;  s8  -= carry8  << 21
    var carry9  = (s9  + Int64(1 << 20)) >> 21; s10 += carry9;  s9  -= carry9  << 21
    var carry10 = (s10 + Int64(1 << 20)) >> 21; s11 += carry10; s10 -= carry10 << 21
    var carry11 = (s11 + Int64(1 << 20)) >> 21; s12 += carry11; s11 -= carry11 << 21
    var carry12 = (s12 + Int64(1 << 20)) >> 21; s13 += carry12; s12 -= carry12 << 21
    var carry13 = (s13 + Int64(1 << 20)) >> 21; s14 += carry13; s13 -= carry13 << 21
    var carry14 = (s14 + Int64(1 << 20)) >> 21; s15 += carry14; s14 -= carry14 << 21
    var carry15 = (s15 + Int64(1 << 20)) >> 21; s16 += carry15; s15 -= carry15 << 21
    var carry16 = (s16 + Int64(1 << 20)) >> 21; s17 += carry16; s16 -= carry16 << 21
    var carry17 = (s17 + Int64(1 << 20)) >> 21; s18 += carry17; s17 -= carry17 << 21

    # Phase 2: Fold s18..s12 into s6..s0 (s18 may be non-zero after extended carry)
    s6  += s18 * Int64(666643); s7  += s18 * Int64(470296); s8  += s18 * Int64(654183)
    s9  -= s18 * Int64(997805); s10 += s18 * Int64(136657); s11 -= s18 * Int64(683901)
    s18 = 0

    s5  += s17 * Int64(666643); s6  += s17 * Int64(470296); s7  += s17 * Int64(654183)
    s8  -= s17 * Int64(997805); s9  += s17 * Int64(136657); s10 -= s17 * Int64(683901)
    s17 = 0

    s4  += s16 * Int64(666643); s5  += s16 * Int64(470296); s6  += s16 * Int64(654183)
    s7  -= s16 * Int64(997805); s8  += s16 * Int64(136657); s9  -= s16 * Int64(683901)
    s16 = 0

    s3  += s15 * Int64(666643); s4  += s15 * Int64(470296); s5  += s15 * Int64(654183)
    s6  -= s15 * Int64(997805); s7  += s15 * Int64(136657); s8  -= s15 * Int64(683901)
    s15 = 0

    s2  += s14 * Int64(666643); s3  += s14 * Int64(470296); s4  += s14 * Int64(654183)
    s5  -= s14 * Int64(997805); s6  += s14 * Int64(136657); s7  -= s14 * Int64(683901)
    s14 = 0

    s1  += s13 * Int64(666643); s2  += s13 * Int64(470296); s3  += s13 * Int64(654183)
    s4  -= s13 * Int64(997805); s5  += s13 * Int64(136657); s6  -= s13 * Int64(683901)
    s13 = 0

    s0  += s12 * Int64(666643); s1  += s12 * Int64(470296); s2  += s12 * Int64(654183)
    s3  -= s12 * Int64(997805); s4  += s12 * Int64(136657); s5  -= s12 * Int64(683901)
    s12 = 0

    # Carry propagation round 2: full balanced carry s0..s11 → s12
    var carry0  = (s0  + Int64(1 << 20)) >> 21; s1  += carry0;  s0  -= carry0  << 21
    var carry1  = (s1  + Int64(1 << 20)) >> 21; s2  += carry1;  s1  -= carry1  << 21
    var carry2  = (s2  + Int64(1 << 20)) >> 21; s3  += carry2;  s2  -= carry2  << 21
    var carry3  = (s3  + Int64(1 << 20)) >> 21; s4  += carry3;  s3  -= carry3  << 21
    var carry4  = (s4  + Int64(1 << 20)) >> 21; s5  += carry4;  s4  -= carry4  << 21
    var carry5  = (s5  + Int64(1 << 20)) >> 21; s6  += carry5;  s5  -= carry5  << 21

    carry6  = (s6  + Int64(1 << 20)) >> 21; s7  += carry6;  s6  -= carry6  << 21
    carry7  = (s7  + Int64(1 << 20)) >> 21; s8  += carry7;  s7  -= carry7  << 21
    carry8  = (s8  + Int64(1 << 20)) >> 21; s9  += carry8;  s8  -= carry8  << 21
    carry9  = (s9  + Int64(1 << 20)) >> 21; s10 += carry9;  s9  -= carry9  << 21
    carry10 = (s10 + Int64(1 << 20)) >> 21; s11 += carry10; s10 -= carry10 << 21
    carry11 = (s11 + Int64(1 << 20)) >> 21; s12 += carry11; s11 -= carry11 << 21

    # Phase 3: Fold s12, floor carry s0..s11 → s12 (canonical)
    s0  += s12 * Int64(666643); s1  += s12 * Int64(470296); s2  += s12 * Int64(654183)
    s3  -= s12 * Int64(997805); s4  += s12 * Int64(136657); s5  -= s12 * Int64(683901)
    s12 = 0

    carry0  = s0  >> 21; s1  += carry0;  s0  -= carry0  << 21
    carry1  = s1  >> 21; s2  += carry1;  s1  -= carry1  << 21
    carry2  = s2  >> 21; s3  += carry2;  s2  -= carry2  << 21
    carry3  = s3  >> 21; s4  += carry3;  s3  -= carry3  << 21
    carry4  = s4  >> 21; s5  += carry4;  s4  -= carry4  << 21
    carry5  = s5  >> 21; s6  += carry5;  s5  -= carry5  << 21
    carry6  = s6  >> 21; s7  += carry6;  s6  -= carry6  << 21
    carry7  = s7  >> 21; s8  += carry7;  s7  -= carry7  << 21
    carry8  = s8  >> 21; s9  += carry8;  s8  -= carry8  << 21
    carry9  = s9  >> 21; s10 += carry9;  s9  -= carry9  << 21
    carry10 = s10 >> 21; s11 += carry10; s10 -= carry10 << 21
    carry11 = s11 >> 21; s12 += carry11; s11 -= carry11 << 21

    # Phase 4: Second fold s12, floor carry s0..s10 (final canonical)
    s0  += s12 * Int64(666643); s1  += s12 * Int64(470296); s2  += s12 * Int64(654183)
    s3  -= s12 * Int64(997805); s4  += s12 * Int64(136657); s5  -= s12 * Int64(683901)
    s12 = 0

    carry0  = s0  >> 21; s1  += carry0;  s0  -= carry0  << 21
    carry1  = s1  >> 21; s2  += carry1;  s1  -= carry1  << 21
    carry2  = s2  >> 21; s3  += carry2;  s2  -= carry2  << 21
    carry3  = s3  >> 21; s4  += carry3;  s3  -= carry3  << 21
    carry4  = s4  >> 21; s5  += carry4;  s4  -= carry4  << 21
    carry5  = s5  >> 21; s6  += carry5;  s5  -= carry5  << 21
    carry6  = s6  >> 21; s7  += carry6;  s6  -= carry6  << 21
    carry7  = s7  >> 21; s8  += carry7;  s7  -= carry7  << 21
    carry8  = s8  >> 21; s9  += carry8;  s8  -= carry8  << 21
    carry9  = s9  >> 21; s10 += carry9;  s9  -= carry9  << 21
    carry10 = s10 >> 21; s11 += carry10; s10 -= carry10 << 21

    # Pack result into 32 bytes
    var out = List[UInt8](capacity=32)
    out.append(UInt8(s0 & 0xFF))
    out.append(UInt8((s0 >> 8) & 0xFF))
    out.append(UInt8(((s0 >> 16) | (s1 << 5)) & 0xFF))
    out.append(UInt8((s1 >> 3) & 0xFF))
    out.append(UInt8((s1 >> 11) & 0xFF))
    out.append(UInt8(((s1 >> 19) | (s2 << 2)) & 0xFF))
    out.append(UInt8((s2 >> 6) & 0xFF))
    out.append(UInt8(((s2 >> 14) | (s3 << 7)) & 0xFF))
    out.append(UInt8((s3 >> 1) & 0xFF))
    out.append(UInt8((s3 >> 9) & 0xFF))
    out.append(UInt8(((s3 >> 17) | (s4 << 4)) & 0xFF))
    out.append(UInt8((s4 >> 4) & 0xFF))
    out.append(UInt8((s4 >> 12) & 0xFF))
    out.append(UInt8(((s4 >> 20) | (s5 << 1)) & 0xFF))
    out.append(UInt8((s5 >> 7) & 0xFF))
    out.append(UInt8(((s5 >> 15) | (s6 << 6)) & 0xFF))
    out.append(UInt8((s6 >> 2) & 0xFF))
    out.append(UInt8((s6 >> 10) & 0xFF))
    out.append(UInt8(((s6 >> 18) | (s7 << 3)) & 0xFF))
    out.append(UInt8((s7 >> 5) & 0xFF))
    out.append(UInt8((s7 >> 13) & 0xFF))
    out.append(UInt8(s8 & 0xFF))
    out.append(UInt8((s8 >> 8) & 0xFF))
    out.append(UInt8(((s8 >> 16) | (s9 << 5)) & 0xFF))
    out.append(UInt8((s9 >> 3) & 0xFF))
    out.append(UInt8((s9 >> 11) & 0xFF))
    out.append(UInt8(((s9 >> 19) | (s10 << 2)) & 0xFF))
    out.append(UInt8((s10 >> 6) & 0xFF))
    out.append(UInt8(((s10 >> 14) | (s11 << 7)) & 0xFF))
    out.append(UInt8((s11 >> 1) & 0xFF))
    out.append(UInt8((s11 >> 9) & 0xFF))
    out.append(UInt8((s11 >> 17) & 0xFF))
    return out^


fn _scalar_mul_add(a: List[UInt8], b: List[UInt8], c: List[UInt8]) -> List[UInt8]:
    """Compute (a * b + c) mod L — for signing: S = (r + H*a) mod L.
    All inputs are 32 bytes (little-endian scalars < L).
    Output is 32 bytes.
    The product a*b can be up to 64 bytes; we reduce."""
    # Multiply a * b into 64 bytes via schoolbook
    var ab = List[UInt8](capacity=64)
    for _ in range(64):
        ab.append(0)

    for i in range(32):
        var carry: UInt64 = 0
        for j in range(32):
            var cur = UInt64(ab[i + j]) + UInt64(a[i]) * UInt64(b[j]) + carry
            ab[i + j] = UInt8(cur & 0xFF)
            carry = cur >> 8
        # propagate remaining carry
        var k = i + 32
        while carry > 0 and k < 64:
            var cur = UInt64(ab[k]) + carry
            ab[k] = UInt8(cur & 0xFF)
            carry = cur >> 8
            k += 1

    # Add c to ab
    var carry2: UInt64 = 0
    for i in range(32):
        var cur = UInt64(ab[i]) + UInt64(c[i]) + carry2
        ab[i] = UInt8(cur & 0xFF)
        carry2 = cur >> 8
    var i2 = 32
    while carry2 > 0 and i2 < 64:
        var cur = UInt64(ab[i2]) + carry2
        ab[i2] = UInt8(cur & 0xFF)
        carry2 = cur >> 8
        i2 += 1

    return _scalar_reduce(ab)


# ============================================================================
# Public key derivation
# ============================================================================

fn ed25519_public_key(private_key: List[UInt8]) -> List[UInt8]:
    """Compute Ed25519 public key from 32-byte private key seed."""
    var h = sha512(private_key)
    var scalar = _clamp_ed25519(h)
    var p = _ed_base_mul(scalar)
    return _ed_compress(p)


fn _clamp_ed25519(h: List[UInt8]) -> List[UInt8]:
    """Extract and clamp the scalar from SHA-512(seed).
    RFC 8032 §5.1.5: clear bits 0,1,2 and 255; set bit 254."""
    var scalar = List[UInt8](capacity=32)
    for i in range(32):
        scalar.append(h[i])
    scalar[0]  &= 248   # clear bits 0, 1, 2
    scalar[31] &= 127   # clear bit 255
    scalar[31] |= 64    # set bit 254
    return scalar^


# ============================================================================
# Sign
# ============================================================================

fn ed25519_sign(private_key: List[UInt8], message: List[UInt8]) -> List[UInt8]:
    """Sign a message with a 32-byte Ed25519 private key seed.
    Returns 64-byte signature (R || S)."""
    # Step 1: expand private key
    var h = sha512(private_key)
    var scalar = _clamp_ed25519(h.copy())

    # Step 2: nonce r = SHA-512(h[32..63] || message)
    var nonce_input = List[UInt8](capacity=32 + len(message))
    for i in range(32, 64):
        nonce_input.append(h[i])
    for i in range(len(message)):
        nonce_input.append(message[i])
    var r_hash = sha512(nonce_input)

    # Step 3: R = r * G (nonce point)
    var r_scalar = _scalar_reduce(r_hash)
    var R_point = _ed_base_mul(r_scalar)
    var R_bytes = _ed_compress(R_point)

    # Step 4: public key A = scalar * G
    var A_bytes = ed25519_public_key(private_key)

    # Step 5: k = SHA-512(R || A || message)
    var k_input = List[UInt8](capacity=32 + 32 + len(message))
    for i in range(32):
        k_input.append(R_bytes[i])
    for i in range(32):
        k_input.append(A_bytes[i])
    for i in range(len(message)):
        k_input.append(message[i])
    var k_hash = sha512(k_input)
    var k_scalar = _scalar_reduce(k_hash)

    # Step 6: S = (r + k * scalar) mod L
    var S_bytes = _scalar_mul_add(k_scalar, scalar, r_scalar)

    # Signature = R (32 bytes) || S (32 bytes)
    var sig = List[UInt8](capacity=64)
    for i in range(32):
        sig.append(R_bytes[i])
    for i in range(32):
        sig.append(S_bytes[i])
    return sig^


# ============================================================================
# Verify
# ============================================================================

fn ed25519_verify(public_key: List[UInt8], message: List[UInt8], signature: List[UInt8]) raises -> Bool:
    """Verify an Ed25519 signature.
    Returns True if valid, False if invalid. Raises on malformed input."""
    if len(signature) != 64:
        raise Error("Ed25519: signature must be 64 bytes")
    if len(public_key) != 32:
        raise Error("Ed25519: public key must be 32 bytes")

    # Extract R and S from signature
    var R_bytes = List[UInt8](capacity=32)
    var S_bytes = List[UInt8](capacity=32)
    for i in range(32):
        R_bytes.append(signature[i])
    for i in range(32):
        S_bytes.append(signature[i + 32])

    # Reject S >= L (top 3 bits of S[31] must be 0)
    if (S_bytes[31] & 0xE0) != 0:
        return False

    # Decode A (public key point)
    var A = _ed_decode_point(public_key)

    # Decode R (signature nonce point)
    var R = _ed_decode_point(R_bytes)

    # k = SHA-512(R || A || message)
    var k_input = List[UInt8](capacity=32 + 32 + len(message))
    for i in range(32):
        k_input.append(R_bytes[i])
    for i in range(32):
        k_input.append(public_key[i])
    for i in range(len(message)):
        k_input.append(message[i])
    var k_hash = sha512(k_input)
    var k_scalar = _scalar_reduce(k_hash)

    # Check: S*G == R + k*A
    var SG = _ed_base_mul(S_bytes)
    var kA = _ed_scalar_mul(k_scalar, A)
    var RkA = _ed_add(R, kA)

    # Compare compressed points
    var lhs = _ed_compress(SG)
    var rhs = _ed_compress(RkA)

    var ok: UInt8 = 0
    for i in range(32):
        ok |= lhs[i] ^ rhs[i]
    return ok == 0
