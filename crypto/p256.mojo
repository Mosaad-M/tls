# ============================================================================
# p256.mojo — NIST P-256 elliptic curve for TLS 1.3
# ============================================================================
# Provides:
#   p256_public_key(private_key)       → 65-byte uncompressed public key
#   p256_ecdh(private_key, peer_pub)   → 32-byte shared secret (x-coord)
#   p256_ecdsa_verify(pub, hash, r, s) → raises on invalid signature
#   p256_ecdsa_sign(priv, hash, nonce) → (r, s)
#
# All curve arithmetic runs in crypto/ec_ct.mojo (64-bit Montgomery limbs):
# constant time for secret scalars (public key, ECDH, signing); signature
# verification (ct.ecdsa_verify) sees only public data. The BigInt field
# code left here validates peer public keys for ECDH.
# ============================================================================

from crypto.bigint import (
    BigInt, bigint_zero, bigint_one, bigint_from_u64, bigint_from_bytes,
    bigint_to_bytes, bigint_is_zero, bigint_cmp, bigint_add, bigint_sub,
    bigint_mul, bigint_mod, bigint_modmul, bigint_modinv,
    bigint_bit_len, bigint_get_bit, bigint_cswap_inplace,
)
from std.collections import InlineArray
from crypto.hmac import hmac_sha256
import crypto.ec_ct as ct


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

# ============================================================================
# Point doubling — dbl-2001-b (optimized for a = -3)
# https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#doubling-dbl-2001-b
# Cost: 3M + 5S + 8add
# ============================================================================

# ============================================================================
# Mixed addition (Jacobian P + affine Q) — madd-2007-bl
# https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#addition-madd-2007-bl
# Cost: 7M + 4S + 9add  (Z2 = 1 assumed)
# ============================================================================

# ============================================================================
# Full Jacobian addition — add-2007-bl
# https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#addition-add-2007-bl
# Cost: 11M + 5S
# ============================================================================

# ============================================================================
# Scalar multiplication: Montgomery ladder (constant-time structure)
# ============================================================================

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
    """Derive 65-byte uncompressed P-256 public key from 32-byte private scalar.

    Constant time in the private key (crypto/ec_ct.mojo).
    """
    if len(private_key) != 32:
        raise Error("p256: private key must be 32 bytes")
    var c = ct.p256_curve()
    if not ct.scalar_in_range(private_key, c.order):
        raise Error("p256: private key out of range")
    return ct.public_key(private_key, c)


def p256_ecdh(private_key: List[UInt8], peer_public_key: List[UInt8]) raises -> List[UInt8]:
    """Compute 32-byte P-256 ECDH shared secret (x-coordinate only).

    The peer key is validated (format, coordinates < p, on the curve) with
    the BigInt code, since it is public; the scalar multiplication by the
    private key is constant time (crypto/ec_ct.mojo).
    """
    if len(private_key) != 32:
        raise Error("p256: private key must be 32 bytes")
    var p = _p256_p()
    var parsed = _parse_pub(peer_public_key)
    var qx = parsed[0].copy()
    var qy = parsed[1].copy()
    if bigint_cmp(qx, p) >= 0 or bigint_cmp(qy, p) >= 0:
        raise Error("p256: peer public key coordinate out of range")
    if not _point_on_curve(qx.copy(), qy.copy(), p):
        raise Error("p256: peer public key not on curve")
    var c = ct.p256_curve()
    if not ct.scalar_in_range(private_key, c.order):
        raise Error("p256: private key out of range")
    return ct.ecdh_x(private_key, peer_public_key, c)


def p256_ecdsa_verify(
    pub_key:  List[UInt8],   # 65-byte uncompressed P-256 public key
    msg_hash: List[UInt8],   # 32-byte message hash
    sig_r:    List[UInt8],   # 32-byte r component
    sig_s:    List[UInt8],   # 32-byte s component
) raises:
    """Verify P-256 ECDSA signature. Raises on invalid."""
    ct.ecdsa_verify(ct.p256_curve(), pub_key, msg_hash, sig_r, sig_s, "p256")


def p256_ecdsa_sign(
    private_key:  List[UInt8],   # 32-byte big-endian scalar in [1, n-1]
    msg_hash:     List[UInt8],   # 32-byte message hash (e.g. SHA-256 digest)
    nonce_bytes:  List[UInt8],   # 32-byte caller-provided entropy
) raises -> Tuple[List[UInt8], List[UInt8]]:
    """Sign msg_hash with P-256 ECDSA. Returns (r[32], s[32]).

    Nonce k is derived deterministically:
      k_raw = HMAC-SHA-256(private_key, msg_hash || nonce_bytes)
      k     = k_raw mod n   (one conditional subtraction; k_raw < 2^256 < 2n)

    Low-s normalization is applied: if s > n/2 then s = n - s.
    This prevents signature malleability.

    Constant time in the private key and the nonce (crypto/ec_ct.mojo):
    k*G is a fixed 256-step ladder, k^-1 is Fermat inversion, and all mod-n
    arithmetic is Montgomery with masked reductions.
    """
    if len(private_key) != 32:
        raise Error("p256_ecdsa_sign: private key must be 32 bytes")
    if len(msg_hash) != 32:
        raise Error("p256_ecdsa_sign: msg_hash must be 32 bytes")
    if len(nonce_bytes) != 32:
        raise Error("p256_ecdsa_sign: nonce_bytes must be 32 bytes")

    var curve = ct.p256_curve()
    var order = curve.order.copy()
    if not ct.scalar_in_range(private_key, order):
        raise Error("p256_ecdsa_sign: private key out of range [1, n-1]")

    # Derive nonce k: HMAC-SHA-256(private_key, msg_hash || nonce_bytes)
    var k_input = List[UInt8](capacity=64)
    for i in range(32):
        k_input.append(msg_hash[i])
    for i in range(32):
        k_input.append(nonce_bytes[i])
    var k = ct.reduce_once(ct.limbs_from_be[4](hmac_sha256(private_key, k_input), 0), order)
    if ct.is_zero(k) == 1:
        raise Error("p256_ecdsa_sign: degenerate nonce k=0; retry with different nonce_bytes")
    var k_bytes = ct.limbs_to_be(k)

    # R = k * G; r = R.x mod n (R.x < p < 2n)
    var big_r = ct.to_affine(ct.scalar_mult(k_bytes, curve.g, curve), curve.field)
    var r = ct.reduce_once(big_r[0], order)
    if ct.is_zero(r) == 1:
        raise Error("p256_ecdsa_sign: degenerate r=0; retry with different nonce_bytes")

    # s = k^-1 * (e + r*d) mod n, in the Montgomery domain mod n
    var e = ct.reduce_once(ct.limbs_from_be[4](msg_hash, 0), order)
    var d = ct.limbs_from_be[4](private_key, 0)
    var rd = ct.mont_mul(ct.to_mont(r, order), ct.to_mont(d, order), order)
    var sum = ct.add(ct.to_mont(e, order), rd, order)
    var s_m = ct.mont_mul(ct.mont_inv(ct.to_mont(k, order), order), sum, order)
    var s = ct.from_mont(s_m, order)
    if ct.is_zero(s) == 1:
        raise Error("p256_ecdsa_sign: degenerate s=0; retry with different nonce_bytes")

    # Low-s normalization: s > (n-1)/2  =>  s = n - s, chosen by mask
    var half = order.m.copy()
    for i in range(4):
        var next_bit = (order.m[i + 1] & 1) << 63 if i < 3 else UInt64(0)
        half[i] = (order.m[i] >> 1) | next_bit
    var high = ct.lt(half, s)
    var neg = ct.sub(InlineArray[UInt64, 4](fill=0), s, order)  # n - s
    s = ct.select(UInt64(0) - high, neg, s)

    return (ct.limbs_to_be(r), ct.limbs_to_be(s))
