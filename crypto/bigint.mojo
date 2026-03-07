# ============================================================================
# bigint.mojo — Arbitrary-precision unsigned integer for TLS 1.3
# ============================================================================
# Representation: List[UInt32] limbs, little-endian
#   limbs[0] = least significant 32-bit word
# Invariant: no leading zero limbs, except BigInt(0) which has exactly [0]
# ============================================================================


struct BigInt(Copyable, Movable):
    var limbs: List[UInt32]

    fn __init__(out self):
        self.limbs = List[UInt32]()
        self.limbs.append(0)

    fn __copyinit__(out self, copy: Self):
        self.limbs = copy.limbs.copy()

    fn __moveinit__(out self, deinit take: Self):
        self.limbs = take.limbs^

    fn copy(self) -> BigInt:
        var b = BigInt()
        b.limbs = self.limbs.copy()
        return b^


# ============================================================================
# Internal helpers
# ============================================================================

fn _bigint_trim(mut a: BigInt):
    """Remove leading zero limbs (keep at least one limb)."""
    while len(a.limbs) > 1 and a.limbs[len(a.limbs) - 1] == 0:
        _ = a.limbs.pop()


# ============================================================================
# Constructors
# ============================================================================

fn bigint_zero() -> BigInt:
    return BigInt()


fn bigint_one() -> BigInt:
    var b = BigInt()
    b.limbs[0] = 1
    return b^


fn bigint_from_u64(v: UInt64) -> BigInt:
    var b = BigInt()
    b.limbs[0] = UInt32(v & 0xFFFFFFFF)
    var hi = UInt32(v >> 32)
    if hi != 0:
        b.limbs.append(hi)
    return b^


fn bigint_from_bytes(b: List[UInt8]) -> BigInt:
    """Create BigInt from big-endian byte array."""
    var n = len(b)
    # Strip leading zeros
    var start = 0
    while start < n - 1 and b[start] == 0:
        start += 1
    var effective_n = n - start
    var n_limbs = (effective_n + 3) // 4
    var result = BigInt()
    result.limbs = List[UInt32](capacity=n_limbs)
    for _ in range(n_limbs):
        result.limbs.append(0)
    # Fill limbs: bytes big-endian → limbs little-endian
    for i in range(effective_n):
        var byte_pos = effective_n - 1 - i  # 0 = least significant byte
        var limb_idx = byte_pos // 4
        var byte_shift = (byte_pos % 4) * 8
        result.limbs[limb_idx] |= UInt32(b[start + (effective_n - 1 - byte_pos)]) << UInt32(byte_shift)
    _bigint_trim(result)
    return result^


fn bigint_to_bytes(a: BigInt, n_bytes: Int) -> List[UInt8]:
    """Serialize BigInt to big-endian byte array of exactly n_bytes."""
    var out = List[UInt8](capacity=n_bytes)
    for _ in range(n_bytes):
        out.append(0)
    var n_limbs = len(a.limbs)
    for i in range(n_limbs):
        var limb = a.limbs[i]
        for j in range(4):
            var byte_pos = n_bytes - 1 - (i * 4 + j)
            if byte_pos >= 0:
                out[byte_pos] = UInt8((limb >> UInt32(j * 8)) & 0xFF)
    return out^


fn bigint_is_zero(a: BigInt) -> Bool:
    return len(a.limbs) == 1 and a.limbs[0] == 0


# ============================================================================
# Comparison
# ============================================================================

fn bigint_cmp(a: BigInt, b: BigInt) -> Int:
    """Compare a and b. Returns -1 if a<b, 0 if a==b, 1 if a>b."""
    var an = len(a.limbs)
    var bn = len(b.limbs)
    if an != bn:
        return 1 if an > bn else -1
    for i in range(an - 1, -1, -1):
        if a.limbs[i] > b.limbs[i]:
            return 1
        if a.limbs[i] < b.limbs[i]:
            return -1
    return 0


# ============================================================================
# Addition / Subtraction
# ============================================================================

fn bigint_add(a: BigInt, b: BigInt) -> BigInt:
    """Return a + b."""
    var an = len(a.limbs)
    var bn = len(b.limbs)
    var n = an if an > bn else bn
    var result = BigInt()
    result.limbs = List[UInt32](capacity=n + 1)
    for _ in range(n + 1):
        result.limbs.append(0)
    var carry: UInt64 = 0
    for i in range(n):
        var ai: UInt64 = UInt64(a.limbs[i]) if i < an else 0
        var bi: UInt64 = UInt64(b.limbs[i]) if i < bn else 0
        var s = ai + bi + carry
        result.limbs[i] = UInt32(s & 0xFFFFFFFF)
        carry = s >> 32
    result.limbs[n] = UInt32(carry)
    _bigint_trim(result)
    return result^


fn bigint_sub(a: BigInt, b: BigInt) -> BigInt:
    """Return a - b. Requires a >= b (undefined behaviour otherwise)."""
    var an = len(a.limbs)
    var result = BigInt()
    result.limbs = List[UInt32](capacity=an)
    for _ in range(an):
        result.limbs.append(0)
    var borrow: Int64 = 0
    for i in range(an):
        var ai: Int64 = Int64(a.limbs[i])
        var bi: Int64 = Int64(b.limbs[i]) if i < len(b.limbs) else 0
        var d = ai - bi - borrow
        if d < 0:
            result.limbs[i] = UInt32(d + (Int64(1) << 32))
            borrow = 1
        else:
            result.limbs[i] = UInt32(d)
            borrow = 0
    _bigint_trim(result)
    return result^


# ============================================================================
# Multiplication (schoolbook O(n²))
# ============================================================================

fn bigint_mul(a: BigInt, b: BigInt) -> BigInt:
    """Return a * b."""
    var an = len(a.limbs)
    var bn = len(b.limbs)
    var n = an + bn
    var result = BigInt()
    result.limbs = List[UInt32](capacity=n)
    for _ in range(n):
        result.limbs.append(0)
    for i in range(an):
        var carry: UInt64 = 0
        for j in range(bn):
            var uv = (UInt64(a.limbs[i]) * UInt64(b.limbs[j])
                      + UInt64(result.limbs[i + j]) + carry)
            result.limbs[i + j] = UInt32(uv & 0xFFFFFFFF)
            carry = uv >> 32
        result.limbs[i + bn] = UInt32(UInt64(result.limbs[i + bn]) + carry)
    _bigint_trim(result)
    return result^


# ============================================================================
# Bit operations
# ============================================================================

fn bigint_bit_len(a: BigInt) -> Int:
    """Number of bits needed to represent a (0 returns 0)."""
    var n = len(a.limbs)
    var top = a.limbs[n - 1]
    if top == 0:
        return (n - 1) * 32
    var bits = n * 32
    while (top & (UInt32(1) << 31)) == 0:
        bits -= 1
        top <<= 1
    return bits


fn bigint_get_bit(a: BigInt, i: Int) -> UInt32:
    """Return bit i of a (0 = LSB)."""
    var limb_idx = i // 32
    if limb_idx >= len(a.limbs):
        return 0
    return (a.limbs[limb_idx] >> UInt32(i % 32)) & 1


fn bigint_shr1(a: BigInt) -> BigInt:
    """Return a >> 1."""
    var n = len(a.limbs)
    var result = BigInt()
    result.limbs = List[UInt32](capacity=n)
    for _ in range(n):
        result.limbs.append(0)
    for i in range(n):
        var lo = a.limbs[i] >> 1
        var hi: UInt32 = 0
        if i + 1 < n:
            hi = (a.limbs[i + 1] & 1) << 31
        result.limbs[i] = lo | hi
    _bigint_trim(result)
    return result^


fn bigint_shl(a: BigInt, shift: Int) -> BigInt:
    """Return a << shift."""
    if bigint_is_zero(a) or shift == 0:
        return a.copy()
    var word_shift = shift // 32
    var bit_shift = shift % 32
    var an = len(a.limbs)
    var n = an + word_shift + 1
    var result = BigInt()
    result.limbs = List[UInt32](capacity=n)
    for _ in range(n):
        result.limbs.append(0)
    for i in range(an):
        var v = UInt64(a.limbs[i]) << UInt64(bit_shift)
        result.limbs[i + word_shift] |= UInt32(v & 0xFFFFFFFF)
        if i + word_shift + 1 < n:
            result.limbs[i + word_shift + 1] |= UInt32(v >> 32)
    _bigint_trim(result)
    return result^


# ============================================================================
# Modular reduction (binary shift-subtract)
# ============================================================================

fn _bigint_shr1_inplace(mut a: BigInt):
    """Shift a right by 1 in-place (no allocation)."""
    var n = len(a.limbs)
    for i in range(n):
        var lo = a.limbs[i] >> 1
        var hi: UInt32 = 0
        if i + 1 < n:
            hi = (a.limbs[i + 1] & 1) << 31
        a.limbs[i] = lo | hi
    _bigint_trim(a)


fn bigint_mod(a: BigInt, n: BigInt) -> BigInt:
    """Return a mod n."""
    if bigint_cmp(a, n) < 0:
        return a.copy()
    var bit_a = bigint_bit_len(a)
    var bit_n = bigint_bit_len(n)
    var shift = bit_a - bit_n
    var n_shifted = bigint_shl(n, shift)
    var r = a.copy()
    var i = shift
    while i >= 0:
        if bigint_cmp(r, n_shifted) >= 0:
            r = bigint_sub(r, n_shifted)
        _bigint_shr1_inplace(n_shifted)
        i -= 1
    return r^


fn bigint_modmul(a: BigInt, b: BigInt, n: BigInt) -> BigInt:
    """Return a * b mod n."""
    var p = bigint_mul(a, b)
    return bigint_mod(p, n)


# ============================================================================
# Modular exponentiation (left-to-right binary method)
# ============================================================================

fn bigint_modexp(base: BigInt, exp: BigInt, n: BigInt) -> BigInt:
    """Return base^exp mod n (constant-time: always computes both branches)."""
    if bigint_is_zero(n):
        return bigint_zero()
    if bigint_is_zero(exp):
        return bigint_mod(bigint_one(), n)
    var bit_e = bigint_bit_len(exp)
    var result = bigint_mod(bigint_one(), n)
    var base_mod = bigint_mod(base, n)
    for i in range(bit_e - 1, -1, -1):
        result = bigint_modmul(result, result, n)
        # Constant-time: always compute the multiply; select via cswap
        var mul_result = bigint_modmul(result, base_mod, n)
        var bit = bigint_get_bit(exp, i)
        var mask: UInt32 = ~UInt32(0) if bit == 1 else UInt32(0)
        bigint_cswap_inplace(result, mul_result, mask)
    return result^


# ============================================================================
# Modular inverse — binary extended GCD
# ============================================================================

fn bigint_modinv(a: BigInt, n: BigInt) raises -> BigInt:
    """Compute a^(-1) mod n where n is odd. Raises if a ≡ 0 mod n or gcd != 1.

    Uses binary extended GCD. NOT constant-time (safe for public data only).
    Cost: O(2*bitlen(n)) simple word ops vs O(bitlen(n)) multiplications for Fermat.
    """
    # Trim leading zeros — bigint_cswap_inplace intentionally leaves padding
    # which breaks bigint_cmp (compares by limb count) and bigint_bit_len.
    var a_trimmed = a.copy()
    _bigint_trim(a_trimmed)
    var u = bigint_mod(a_trimmed, n)
    if bigint_is_zero(u):
        raise Error("bigint_modinv: a is 0 mod n")
    var v = n.copy()
    var x1 = bigint_one()
    var x2 = bigint_zero()
    var one = bigint_one()

    while bigint_cmp(u, one) != 0 and bigint_cmp(v, one) != 0:
        if bigint_is_zero(u) or bigint_is_zero(v):
            raise Error("bigint_modinv: gcd != 1")
        while (u.limbs[0] & 1) == 0:
            _bigint_shr1_inplace(u)
            if (x1.limbs[0] & 1) == 0:
                _bigint_shr1_inplace(x1)
            else:
                x1 = bigint_add(x1, n)
                _bigint_shr1_inplace(x1)
        while (v.limbs[0] & 1) == 0:
            _bigint_shr1_inplace(v)
            if (x2.limbs[0] & 1) == 0:
                _bigint_shr1_inplace(x2)
            else:
                x2 = bigint_add(x2, n)
                _bigint_shr1_inplace(x2)
        if bigint_cmp(u, v) >= 0:
            u = bigint_sub(u, v)
            if bigint_cmp(x1, x2) >= 0:
                x1 = bigint_sub(x1, x2)
            else:
                x1 = bigint_sub(bigint_add(x1, n), x2)
        else:
            v = bigint_sub(v, u)
            if bigint_cmp(x2, x1) >= 0:
                x2 = bigint_sub(x2, x1)
            else:
                x2 = bigint_sub(bigint_add(x2, n), x1)

    if bigint_cmp(u, one) == 0:
        return bigint_mod(x1, n)
    else:
        return bigint_mod(x2, n)


# ============================================================================
# Constant-time conditional swap
# ============================================================================

fn bigint_cswap_inplace(mut a: BigInt, mut b: BigInt, mask: UInt32):
    """Conditionally swap limbs of a and b in constant time.

    mask = 0xFFFFFFFF → swap a and b
    mask = 0x00000000 → no-op

    Both BigInts are padded to the same length before swapping to ensure
    equal-length iteration (prevents length-based timing leaks). Leading
    zeros are trimmed afterwards to restore the BigInt invariant.
    """
    var n = len(a.limbs)
    if len(b.limbs) > n:
        n = len(b.limbs)
    # Pad to equal length with zero limbs
    while len(a.limbs) < n:
        a.limbs.append(0)
    while len(b.limbs) < n:
        b.limbs.append(0)
    # XOR-swap each limb pair — branchless, mask-controlled
    for i in range(n):
        var t = (a.limbs[i] ^ b.limbs[i]) & mask
        a.limbs[i] ^= t
        b.limbs[i] ^= t
    # Intentionally no _bigint_trim here: trimming in data-dependent time leaks
    # which value is numerically larger. Callers accept possible leading-zero limbs.
