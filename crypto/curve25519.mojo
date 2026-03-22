# ============================================================================
# crypto/curve25519.mojo — X25519 Diffie-Hellman (RFC 7748)
# ============================================================================
#
# Field: GF(2^255 - 19)
# Representation: 5 limbs of 51 bits each in UInt64
#   value = L[0] + L[1]*2^51 + L[2]*2^102 + L[3]*2^153 + L[4]*2^204
#
# Curve: Montgomery v^2 = u^3 + 486662*u^2 + u  (mod p)
# Scalar multiply: constant-time Montgomery ladder
# ============================================================================

from std.collections import InlineArray

# ============================================================================
# Field element
# ============================================================================

struct Fe(Copyable, Movable):
    var v: InlineArray[UInt64, 5]

    def __init__(out self):
        self.v = InlineArray[UInt64, 5](fill=UInt64(0))

    def __copyinit__(out self, copy: Self):
        self.v = copy.v.copy()

    def __moveinit__(out self, deinit take: Self):
        self.v = take.v^


def fe_zero() -> Fe:
    return Fe()


def fe_one() -> Fe:
    var r = Fe()
    r.v[0] = 1
    return r^


def fe_from_bytes(b: List[UInt8]) -> Fe:
    """Load 32 little-endian bytes, mask bit 255, split into 51-bit limbs."""
    var w0 = (UInt64(b[0])       | (UInt64(b[1]) << 8)  | (UInt64(b[2]) << 16)
            | (UInt64(b[3]) << 24) | (UInt64(b[4]) << 32) | (UInt64(b[5]) << 40)
            | (UInt64(b[6]) << 48) | (UInt64(b[7]) << 56))
    var w1 = (UInt64(b[8])        | (UInt64(b[9]) << 8)  | (UInt64(b[10]) << 16)
            | (UInt64(b[11]) << 24) | (UInt64(b[12]) << 32) | (UInt64(b[13]) << 40)
            | (UInt64(b[14]) << 48) | (UInt64(b[15]) << 56))
    var w2 = (UInt64(b[16])       | (UInt64(b[17]) << 8)  | (UInt64(b[18]) << 16)
            | (UInt64(b[19]) << 24) | (UInt64(b[20]) << 32) | (UInt64(b[21]) << 40)
            | (UInt64(b[22]) << 48) | (UInt64(b[23]) << 56))
    var w3 = (UInt64(b[24])       | (UInt64(b[25]) << 8)  | (UInt64(b[26]) << 16)
            | (UInt64(b[27]) << 24) | (UInt64(b[28]) << 32) | (UInt64(b[29]) << 40)
            | (UInt64(b[30]) << 48) | (UInt64(b[31]) << 56))
    w3 &= 0x7FFFFFFFFFFFFFFF  # mask bit 255 per RFC 7748 §5
    var r = Fe()
    r.v[0] =  w0                        & 0x0007FFFFFFFFFFFF
    r.v[1] = ((w0 >> 51) | (w1 << 13)) & 0x0007FFFFFFFFFFFF
    r.v[2] = ((w1 >> 38) | (w2 << 26)) & 0x0007FFFFFFFFFFFF
    r.v[3] = ((w2 >> 25) | (w3 << 39)) & 0x0007FFFFFFFFFFFF
    r.v[4] =  (w3 >> 12)               & 0x0007FFFFFFFFFFFF
    return r^


def fe_to_bytes(a: Fe) -> List[UInt8]:
    """Reduce fully and serialize as 32 little-endian bytes."""
    var r = fe_reduce(a)
    var w0 =  r.v[0]        | (r.v[1] << 51)
    var w1 = (r.v[1] >> 13) | (r.v[2] << 38)
    var w2 = (r.v[2] >> 26) | (r.v[3] << 25)
    var w3 = (r.v[3] >> 39) | (r.v[4] << 12)
    var out = List[UInt8](capacity=32)
    for i in range(8): out.append(UInt8((w0 >> UInt64(i * 8)) & 0xFF))
    for i in range(8): out.append(UInt8((w1 >> UInt64(i * 8)) & 0xFF))
    for i in range(8): out.append(UInt8((w2 >> UInt64(i * 8)) & 0xFF))
    for i in range(8): out.append(UInt8((w3 >> UInt64(i * 8)) & 0xFF))
    return out^


def fe_carry(a: Fe) -> Fe:
    """Propagate carries; top limb has 47 usable bits."""
    var l0 = a.v[0]; var l1 = a.v[1]; var l2 = a.v[2]
    var l3 = a.v[3]; var l4 = a.v[4]
    var c: UInt64
    c = l0 >> 51; l0 &= 0x0007FFFFFFFFFFFF; l1 += c
    c = l1 >> 51; l1 &= 0x0007FFFFFFFFFFFF; l2 += c
    c = l2 >> 51; l2 &= 0x0007FFFFFFFFFFFF; l3 += c
    c = l3 >> 51; l3 &= 0x0007FFFFFFFFFFFF; l4 += c
    c = l4 >> 51; l4 &= 0x0007FFFFFFFFFFFF; l0 += c * 19
    c = l0 >> 51; l0 &= 0x0007FFFFFFFFFFFF; l1 += c
    var r = Fe()
    r.v[0] = l0; r.v[1] = l1; r.v[2] = l2; r.v[3] = l3; r.v[4] = l4
    return r^


def fe_reduce(a: Fe) -> Fe:
    """Canonical reduction modulo p = 2^255 - 19."""
    var r = fe_carry(a)
    var t0 = r.v[0] + 19
    var c0 = t0 >> 51; t0 &= 0x0007FFFFFFFFFFFF
    var t1 = r.v[1] + c0
    var c1 = t1 >> 51; t1 &= 0x0007FFFFFFFFFFFF
    var t2 = r.v[2] + c1
    var c2 = t2 >> 51; t2 &= 0x0007FFFFFFFFFFFF
    var t3 = r.v[3] + c2
    var c3 = t3 >> 51; t3 &= 0x0007FFFFFFFFFFFF
    var t4 = r.v[4] + c3
    var overflow = t4 >> 51
    var mask: UInt64 = 0 - overflow
    var out = Fe()
    out.v[0] = (r.v[0] & ~mask) | (t0 & mask)
    out.v[1] = (r.v[1] & ~mask) | (t1 & mask)
    out.v[2] = (r.v[2] & ~mask) | (t2 & mask)
    out.v[3] = (r.v[3] & ~mask) | (t3 & mask)
    out.v[4] = (r.v[4] & ~mask) | ((t4 & 0x0007FFFFFFFFFFFF) & mask)
    return out^


def fe_add(a: Fe, b: Fe) -> Fe:
    var r = Fe()
    r.v[0] = a.v[0] + b.v[0]; r.v[1] = a.v[1] + b.v[1]
    r.v[2] = a.v[2] + b.v[2]; r.v[3] = a.v[3] + b.v[3]
    r.v[4] = a.v[4] + b.v[4]
    return r^


def fe_sub(a: Fe, b: Fe) -> Fe:
    """Compute a - b mod p (adds 2p to avoid underflow)."""
    var r = Fe()
    r.v[0] = (a.v[0] + 0x000FFFFFFFFFFFDA) - b.v[0]
    r.v[1] = (a.v[1] + 0x000FFFFFFFFFFFFE) - b.v[1]
    r.v[2] = (a.v[2] + 0x000FFFFFFFFFFFFE) - b.v[2]
    r.v[3] = (a.v[3] + 0x000FFFFFFFFFFFFE) - b.v[3]
    r.v[4] = (a.v[4] + 0x000FFFFFFFFFFFFE) - b.v[4]
    return r^


# ============================================================================
# 128-bit multiply helpers
# ============================================================================

def _mul64(a: UInt64, b: UInt64) -> Tuple[UInt64, UInt64]:
    """Return (hi, lo) of a * b using 32-bit halves."""
    var a_lo = a & 0xFFFFFFFF; var a_hi = a >> 32
    var b_lo = b & 0xFFFFFFFF; var b_hi = b >> 32
    var p0 = a_lo * b_lo
    var p1 = a_lo * b_hi
    var p2 = a_hi * b_lo
    var p3 = a_hi * b_hi
    var mid = p1 + p2
    var mid_carry: UInt64 = UInt64(1) if mid < p1 else UInt64(0)
    var lo = p0 + (mid << 32)
    var carry: UInt64 = UInt64(1) if lo < p0 else UInt64(0)
    var hi = p3 + (mid >> 32) + (mid_carry << 32) + carry
    return (hi, lo)


def _add128(
    a_hi: UInt64, a_lo: UInt64,
    b_hi: UInt64, b_lo: UInt64,
) -> Tuple[UInt64, UInt64]:
    var lo = a_lo + b_lo
    var carry: UInt64 = UInt64(1) if lo < a_lo else UInt64(0)
    return (a_hi + b_hi + carry, lo)


def fe_mul(a: Fe, b: Fe) -> Fe:
    """Schoolbook 5×5 multiply with 2^255≡19 reduction for high cross-terms."""
    var a0 = a.v[0]; var a1 = a.v[1]; var a2 = a.v[2]
    var a3 = a.v[3]; var a4 = a.v[4]
    var b0 = b.v[0]; var b1 = b.v[1]; var b2 = b.v[2]
    var b3 = b.v[3]; var b4 = b.v[4]
    var b1_19 = b1 * 19; var b2_19 = b2 * 19
    var b3_19 = b3 * 19; var b4_19 = b4 * 19

    var t0h: UInt64 = 0; var t0l: UInt64 = 0
    var t1h: UInt64 = 0; var t1l: UInt64 = 0
    var t2h: UInt64 = 0; var t2l: UInt64 = 0
    var t3h: UInt64 = 0; var t3l: UInt64 = 0
    var t4h: UInt64 = 0; var t4l: UInt64 = 0

    var ph: UInt64; var pl: UInt64
    # t[0]
    ph, pl = _mul64(a0, b0);    t0h, t0l = _add128(t0h, t0l, ph, pl)
    ph, pl = _mul64(a1, b4_19); t0h, t0l = _add128(t0h, t0l, ph, pl)
    ph, pl = _mul64(a2, b3_19); t0h, t0l = _add128(t0h, t0l, ph, pl)
    ph, pl = _mul64(a3, b2_19); t0h, t0l = _add128(t0h, t0l, ph, pl)
    ph, pl = _mul64(a4, b1_19); t0h, t0l = _add128(t0h, t0l, ph, pl)
    # t[1]
    ph, pl = _mul64(a0, b1);    t1h, t1l = _add128(t1h, t1l, ph, pl)
    ph, pl = _mul64(a1, b0);    t1h, t1l = _add128(t1h, t1l, ph, pl)
    ph, pl = _mul64(a2, b4_19); t1h, t1l = _add128(t1h, t1l, ph, pl)
    ph, pl = _mul64(a3, b3_19); t1h, t1l = _add128(t1h, t1l, ph, pl)
    ph, pl = _mul64(a4, b2_19); t1h, t1l = _add128(t1h, t1l, ph, pl)
    # t[2]
    ph, pl = _mul64(a0, b2);    t2h, t2l = _add128(t2h, t2l, ph, pl)
    ph, pl = _mul64(a1, b1);    t2h, t2l = _add128(t2h, t2l, ph, pl)
    ph, pl = _mul64(a2, b0);    t2h, t2l = _add128(t2h, t2l, ph, pl)
    ph, pl = _mul64(a3, b4_19); t2h, t2l = _add128(t2h, t2l, ph, pl)
    ph, pl = _mul64(a4, b3_19); t2h, t2l = _add128(t2h, t2l, ph, pl)
    # t[3]
    ph, pl = _mul64(a0, b3);    t3h, t3l = _add128(t3h, t3l, ph, pl)
    ph, pl = _mul64(a1, b2);    t3h, t3l = _add128(t3h, t3l, ph, pl)
    ph, pl = _mul64(a2, b1);    t3h, t3l = _add128(t3h, t3l, ph, pl)
    ph, pl = _mul64(a3, b0);    t3h, t3l = _add128(t3h, t3l, ph, pl)
    ph, pl = _mul64(a4, b4_19); t3h, t3l = _add128(t3h, t3l, ph, pl)
    # t[4]
    ph, pl = _mul64(a0, b4);    t4h, t4l = _add128(t4h, t4l, ph, pl)
    ph, pl = _mul64(a1, b3);    t4h, t4l = _add128(t4h, t4l, ph, pl)
    ph, pl = _mul64(a2, b2);    t4h, t4l = _add128(t4h, t4l, ph, pl)
    ph, pl = _mul64(a3, b1);    t4h, t4l = _add128(t4h, t4l, ph, pl)
    ph, pl = _mul64(a4, b0);    t4h, t4l = _add128(t4h, t4l, ph, pl)

    var r = Fe()
    var carry: UInt64

    r.v[0] = t0l & 0x0007FFFFFFFFFFFF
    carry = (t0l >> 51) | (t0h << 13)

    t1l += carry; t1h += UInt64(1) if t1l < carry else UInt64(0)
    r.v[1] = t1l & 0x0007FFFFFFFFFFFF
    carry = (t1l >> 51) | (t1h << 13)

    t2l += carry; t2h += UInt64(1) if t2l < carry else UInt64(0)
    r.v[2] = t2l & 0x0007FFFFFFFFFFFF
    carry = (t2l >> 51) | (t2h << 13)

    t3l += carry; t3h += UInt64(1) if t3l < carry else UInt64(0)
    r.v[3] = t3l & 0x0007FFFFFFFFFFFF
    carry = (t3l >> 51) | (t3h << 13)

    t4l += carry; t4h += UInt64(1) if t4l < carry else UInt64(0)
    r.v[4] = t4l & 0x0007FFFFFFFFFFFF
    carry = (t4l >> 51) | (t4h << 13)

    r.v[0] += carry * 19
    var c0f = r.v[0] >> 51; r.v[0] &= 0x0007FFFFFFFFFFFF
    r.v[1] += c0f
    return r^


def fe_sq(a: Fe) -> Fe:
    return fe_mul(a, a)


def fe_mul_scalar(a: Fe, s: UInt64) -> Fe:
    """Multiply by small scalar with proper 128-bit intermediates."""
    var r = Fe()
    var carry: UInt64 = 0
    var ph: UInt64; var pl: UInt64
    for i in range(5):
        ph, pl = _mul64(a.v[i], s)
        pl += carry
        ph += UInt64(1) if pl < carry else UInt64(0)
        r.v[i] = pl & 0x0007FFFFFFFFFFFF
        carry = (pl >> 51) | (ph << 13)
    # Wrap top carry: 2^255 ≡ 19 (mod p)
    r.v[0] += carry * 19
    var c0 = r.v[0] >> 51; r.v[0] &= 0x0007FFFFFFFFFFFF
    r.v[1] += c0
    return r^


def fe_cswap(mut a: Fe, mut b: Fe, swap: UInt64):
    """Constant-time conditional swap."""
    var mask: UInt64 = 0 - swap
    for i in range(5):
        var d = mask & (a.v[i] ^ b.v[i])
        a.v[i] ^= d
        b.v[i] ^= d


# ============================================================================
# Field inversion: z^(p-2) via DJB's Curve25519 addition chain
# ============================================================================

def fe_inv(z: Fe) -> Fe:
    """Compute z^(p-2) mod p = z^(-1) mod p (Fermat's little theorem)."""
    var t = fe_sq(z.copy())      # z^2
    var z2 = t.copy()
    t = fe_sq(t.copy())         # z^4
    t = fe_sq(t.copy())         # z^8
    t = fe_mul(t, z.copy())     # z^9
    var z9 = t.copy()
    t = fe_mul(t, z2.copy())    # z^11
    var z11 = t.copy()
    t = fe_sq(t.copy())         # z^22
    t = fe_mul(t, z9)           # z^31 = z^(2^5-1)
    var z2_5_0 = t.copy()

    # z^(2^10-1)
    t = fe_sq(t.copy()); t = fe_sq(t.copy()); t = fe_sq(t.copy())
    t = fe_sq(t.copy()); t = fe_sq(t.copy())
    t = fe_mul(t, z2_5_0.copy())
    var z2_10_0 = t.copy()

    # z^(2^20-1)
    t = fe_sq(t.copy()); t = fe_sq(t.copy()); t = fe_sq(t.copy())
    t = fe_sq(t.copy()); t = fe_sq(t.copy())
    t = fe_sq(t.copy()); t = fe_sq(t.copy()); t = fe_sq(t.copy())
    t = fe_sq(t.copy()); t = fe_sq(t.copy())
    t = fe_mul(t, z2_10_0.copy())
    var z2_20_0 = t.copy()

    # z^(2^40-1)
    t = fe_sq(t.copy()); t = fe_sq(t.copy()); t = fe_sq(t.copy())
    t = fe_sq(t.copy()); t = fe_sq(t.copy())
    t = fe_sq(t.copy()); t = fe_sq(t.copy()); t = fe_sq(t.copy())
    t = fe_sq(t.copy()); t = fe_sq(t.copy())
    t = fe_sq(t.copy()); t = fe_sq(t.copy()); t = fe_sq(t.copy())
    t = fe_sq(t.copy()); t = fe_sq(t.copy())
    t = fe_sq(t.copy()); t = fe_sq(t.copy()); t = fe_sq(t.copy())
    t = fe_sq(t.copy()); t = fe_sq(t.copy())
    t = fe_mul(t, z2_20_0)

    # z^(2^50-1)
    t = fe_sq(t.copy()); t = fe_sq(t.copy()); t = fe_sq(t.copy())
    t = fe_sq(t.copy()); t = fe_sq(t.copy())
    t = fe_sq(t.copy()); t = fe_sq(t.copy()); t = fe_sq(t.copy())
    t = fe_sq(t.copy()); t = fe_sq(t.copy())
    t = fe_mul(t, z2_10_0)
    var z2_50_0 = t.copy()

    # z^(2^100-1): 50 squarings
    t = fe_sq(t.copy()); t = fe_sq(t.copy()); t = fe_sq(t.copy())
    t = fe_sq(t.copy()); t = fe_sq(t.copy())
    t = fe_sq(t.copy()); t = fe_sq(t.copy()); t = fe_sq(t.copy())
    t = fe_sq(t.copy()); t = fe_sq(t.copy())
    t = fe_sq(t.copy()); t = fe_sq(t.copy()); t = fe_sq(t.copy())
    t = fe_sq(t.copy()); t = fe_sq(t.copy())
    t = fe_sq(t.copy()); t = fe_sq(t.copy()); t = fe_sq(t.copy())
    t = fe_sq(t.copy()); t = fe_sq(t.copy())
    t = fe_sq(t.copy()); t = fe_sq(t.copy()); t = fe_sq(t.copy())
    t = fe_sq(t.copy()); t = fe_sq(t.copy())
    t = fe_sq(t.copy()); t = fe_sq(t.copy()); t = fe_sq(t.copy())
    t = fe_sq(t.copy()); t = fe_sq(t.copy())
    t = fe_sq(t.copy()); t = fe_sq(t.copy()); t = fe_sq(t.copy())
    t = fe_sq(t.copy()); t = fe_sq(t.copy())
    t = fe_sq(t.copy()); t = fe_sq(t.copy()); t = fe_sq(t.copy())
    t = fe_sq(t.copy()); t = fe_sq(t.copy())
    t = fe_sq(t.copy()); t = fe_sq(t.copy()); t = fe_sq(t.copy())
    t = fe_sq(t.copy()); t = fe_sq(t.copy())
    t = fe_sq(t.copy()); t = fe_sq(t.copy()); t = fe_sq(t.copy())
    t = fe_sq(t.copy()); t = fe_sq(t.copy())
    t = fe_mul(t, z2_50_0.copy())
    var z2_100_0 = t.copy()

    # z^(2^200-1): 100 squarings
    t = fe_sq(t.copy()); t = fe_sq(t.copy()); t = fe_sq(t.copy())
    t = fe_sq(t.copy()); t = fe_sq(t.copy())
    t = fe_sq(t.copy()); t = fe_sq(t.copy()); t = fe_sq(t.copy())
    t = fe_sq(t.copy()); t = fe_sq(t.copy())
    t = fe_sq(t.copy()); t = fe_sq(t.copy()); t = fe_sq(t.copy())
    t = fe_sq(t.copy()); t = fe_sq(t.copy())
    t = fe_sq(t.copy()); t = fe_sq(t.copy()); t = fe_sq(t.copy())
    t = fe_sq(t.copy()); t = fe_sq(t.copy())
    t = fe_sq(t.copy()); t = fe_sq(t.copy()); t = fe_sq(t.copy())
    t = fe_sq(t.copy()); t = fe_sq(t.copy())
    t = fe_sq(t.copy()); t = fe_sq(t.copy()); t = fe_sq(t.copy())
    t = fe_sq(t.copy()); t = fe_sq(t.copy())
    t = fe_sq(t.copy()); t = fe_sq(t.copy()); t = fe_sq(t.copy())
    t = fe_sq(t.copy()); t = fe_sq(t.copy())
    t = fe_sq(t.copy()); t = fe_sq(t.copy()); t = fe_sq(t.copy())
    t = fe_sq(t.copy()); t = fe_sq(t.copy())
    t = fe_sq(t.copy()); t = fe_sq(t.copy()); t = fe_sq(t.copy())
    t = fe_sq(t.copy()); t = fe_sq(t.copy())
    t = fe_sq(t.copy()); t = fe_sq(t.copy()); t = fe_sq(t.copy())
    t = fe_sq(t.copy()); t = fe_sq(t.copy())
    t = fe_sq(t.copy()); t = fe_sq(t.copy()); t = fe_sq(t.copy())
    t = fe_sq(t.copy()); t = fe_sq(t.copy())
    t = fe_sq(t.copy()); t = fe_sq(t.copy()); t = fe_sq(t.copy())
    t = fe_sq(t.copy()); t = fe_sq(t.copy())
    t = fe_sq(t.copy()); t = fe_sq(t.copy()); t = fe_sq(t.copy())
    t = fe_sq(t.copy()); t = fe_sq(t.copy())
    t = fe_sq(t.copy()); t = fe_sq(t.copy()); t = fe_sq(t.copy())
    t = fe_sq(t.copy()); t = fe_sq(t.copy())
    t = fe_sq(t.copy()); t = fe_sq(t.copy()); t = fe_sq(t.copy())
    t = fe_sq(t.copy()); t = fe_sq(t.copy())
    t = fe_sq(t.copy()); t = fe_sq(t.copy()); t = fe_sq(t.copy())
    t = fe_sq(t.copy()); t = fe_sq(t.copy())
    t = fe_sq(t.copy()); t = fe_sq(t.copy()); t = fe_sq(t.copy())
    t = fe_sq(t.copy()); t = fe_sq(t.copy())
    t = fe_sq(t.copy()); t = fe_sq(t.copy()); t = fe_sq(t.copy())
    t = fe_sq(t.copy()); t = fe_sq(t.copy())
    t = fe_sq(t.copy()); t = fe_sq(t.copy()); t = fe_sq(t.copy())
    t = fe_sq(t.copy()); t = fe_sq(t.copy())
    t = fe_sq(t.copy()); t = fe_sq(t.copy()); t = fe_sq(t.copy())
    t = fe_sq(t.copy()); t = fe_sq(t.copy())
    t = fe_mul(t, z2_100_0)

    # z^(2^250-1): 50 squarings
    t = fe_sq(t.copy()); t = fe_sq(t.copy()); t = fe_sq(t.copy())
    t = fe_sq(t.copy()); t = fe_sq(t.copy())
    t = fe_sq(t.copy()); t = fe_sq(t.copy()); t = fe_sq(t.copy())
    t = fe_sq(t.copy()); t = fe_sq(t.copy())
    t = fe_sq(t.copy()); t = fe_sq(t.copy()); t = fe_sq(t.copy())
    t = fe_sq(t.copy()); t = fe_sq(t.copy())
    t = fe_sq(t.copy()); t = fe_sq(t.copy()); t = fe_sq(t.copy())
    t = fe_sq(t.copy()); t = fe_sq(t.copy())
    t = fe_sq(t.copy()); t = fe_sq(t.copy()); t = fe_sq(t.copy())
    t = fe_sq(t.copy()); t = fe_sq(t.copy())
    t = fe_sq(t.copy()); t = fe_sq(t.copy()); t = fe_sq(t.copy())
    t = fe_sq(t.copy()); t = fe_sq(t.copy())
    t = fe_sq(t.copy()); t = fe_sq(t.copy()); t = fe_sq(t.copy())
    t = fe_sq(t.copy()); t = fe_sq(t.copy())
    t = fe_sq(t.copy()); t = fe_sq(t.copy()); t = fe_sq(t.copy())
    t = fe_sq(t.copy()); t = fe_sq(t.copy())
    t = fe_sq(t.copy()); t = fe_sq(t.copy()); t = fe_sq(t.copy())
    t = fe_sq(t.copy()); t = fe_sq(t.copy())
    t = fe_sq(t.copy()); t = fe_sq(t.copy()); t = fe_sq(t.copy())
    t = fe_sq(t.copy()); t = fe_sq(t.copy())
    t = fe_mul(t, z2_50_0)

    # Final 5 squarings then multiply by z11 → z^(2^255-21) = z^(p-2)
    t = fe_sq(t.copy())  # z^(2^251-2)
    t = fe_sq(t.copy())  # z^(2^252-4)
    t = fe_sq(t.copy())  # z^(2^253-8)
    t = fe_sq(t.copy())  # z^(2^254-16)
    t = fe_sq(t.copy())  # z^(2^255-32)
    return fe_mul(t, z11)


# ============================================================================
# X25519 Montgomery ladder scalar multiply
# ============================================================================

def _clamp_scalar(s: List[UInt8]) -> List[UInt8]:
    """Apply RFC 7748 §5 scalar clamping."""
    var k = s.copy()
    k[0]  &= 248   # clear bits 0,1,2
    k[31] &= 127   # clear bit 255
    k[31] |= 64    # set bit 254
    return k^


def x25519(scalar: List[UInt8], u_point: List[UInt8]) -> List[UInt8]:
    """X25519 DH function (RFC 7748 §5).

    Args:
        scalar:  32-byte scalar (clamped internally)
        u_point: 32-byte u-coordinate of input point
    Returns:
        32-byte u-coordinate of scalar * point
    """
    var k = _clamp_scalar(scalar)
    var u = fe_from_bytes(u_point)

    # Montgomery ladder (RFC 7748 §5 pseudocode)
    var x_1 = u.copy()
    var x_2 = fe_one()
    var z_2 = fe_zero()
    var x_3 = u^
    var z_3 = fe_one()
    var swap: UInt64 = 0

    for i in range(254, -1, -1):
        var k_t: UInt64 = (UInt64(k[i >> 3]) >> UInt64(i & 7)) & 1
        swap ^= k_t
        fe_cswap(x_2, x_3, swap)
        fe_cswap(z_2, z_3, swap)
        swap = k_t

        var A  = fe_add(x_2.copy(), z_2.copy())
        var AA = fe_sq(A.copy())
        var B  = fe_sub(x_2, z_2)
        var BB = fe_sq(B.copy())
        var E  = fe_sub(AA.copy(), BB.copy())
        var C  = fe_add(x_3.copy(), z_3.copy())
        var D  = fe_sub(x_3, z_3)
        var DA = fe_mul(D, A)
        var CB = fe_mul(C, B)
        x_3 = fe_sq(fe_add(DA.copy(), CB.copy()))
        z_3 = fe_mul(x_1.copy(), fe_sq(fe_sub(DA, CB)))
        x_2 = fe_mul(AA.copy(), BB)
        var tmp = fe_mul_scalar(E.copy(), 121665)
        z_2 = fe_mul(E, fe_add(AA, tmp))

    fe_cswap(x_2, x_3, swap)
    fe_cswap(z_2, z_3, swap)

    var result = fe_mul(x_2, fe_inv(z_2))
    return fe_to_bytes(result)


def x25519_public_key(private_key: List[UInt8]) -> List[UInt8]:
    """Compute X25519 public key = scalar * base_point (u=9).

    Args:
        private_key: 32-byte private scalar
    Returns:
        32-byte public key u-coordinate
    """
    var base = List[UInt8](capacity=32)
    base.append(9)
    for _ in range(31):
        base.append(0)
    return x25519(private_key, base)
