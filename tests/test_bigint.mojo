# ============================================================================
# test_bigint.mojo — BigInt arithmetic tests
# ============================================================================

from crypto.bigint import (
    BigInt,
    bigint_zero, bigint_one, bigint_from_u64,
    bigint_from_bytes, bigint_to_bytes,
    bigint_is_zero, bigint_cmp,
    bigint_add, bigint_sub, bigint_mul,
    bigint_mod, bigint_modmul, bigint_modexp, bigint_modinv,
    bigint_bit_len, bigint_get_bit,
)


def _hex_nibble(b: UInt8) raises -> UInt8:
    if b >= 48 and b <= 57: return b - 48
    if b >= 97 and b <= 102: return b - 87
    raise Error("bad hex char")


def hex_to_bytes(hex: String) raises -> List[UInt8]:
    var raw = hex.as_bytes()
    var n = len(raw)
    if n % 2 != 0: raise Error("odd hex length")
    var out = List[UInt8](capacity=n // 2)
    for i in range(0, n, 2):
        out.append((_hex_nibble(raw[i]) << 4) | _hex_nibble(raw[i + 1]))
    return out^


def bytes_to_hex(b: List[UInt8]) -> String:
    var digits = "0123456789abcdef".as_bytes()
    var result = List[UInt8](capacity=len(b) * 2)
    for i in range(len(b)):
        var byte = Int(b[i])
        result.append(digits[(byte >> 4) & 0xF])
        result.append(digits[byte & 0xF])
    return String(unsafe_from_utf8=result^)


def assert_hex_eq(got: List[UInt8], expected_hex: String, label: String) raises:
    var got_hex = bytes_to_hex(got)
    if got_hex != expected_hex:
        raise Error(label + ": got " + got_hex + ", want " + expected_hex)


def bigint_to_hex(a: BigInt, n_bytes: Int) raises -> String:
    return bytes_to_hex(bigint_to_bytes(a, n_bytes))


def assert_bigint_eq(a: BigInt, b: BigInt, label: String) raises:
    if bigint_cmp(a, b) != 0:
        raise Error(label + ": values not equal")


def assert_bigint_val(a: BigInt, expected_hex: String, n_bytes: Int, label: String) raises:
    var got = bytes_to_hex(bigint_to_bytes(a, n_bytes))
    if got != expected_hex:
        raise Error(label + ": got " + got + ", want " + expected_hex)


def run_test(name: String, mut passed: Int, mut failed: Int, test_fn: def () raises -> None):
    try:
        test_fn()
        print("  PASS:", name)
        passed += 1
    except e:
        print("  FAIL:", name, "-", String(e))
        failed += 1


# ============================================================================
# Construction tests
# ============================================================================

def test_zero_one() raises:
    var z = bigint_zero()
    var o = bigint_one()
    if not bigint_is_zero(z):
        raise Error("zero is not zero")
    if bigint_is_zero(o):
        raise Error("one is zero")
    if bigint_cmp(z, o) != -1:
        raise Error("zero should be < one")
    if bigint_cmp(o, z) != 1:
        raise Error("one should be > zero")
    if bigint_cmp(o, o.copy()) != 0:
        raise Error("one != one copy")


def test_from_u64() raises:
    var a = bigint_from_u64(0xDEADBEEFCAFEBABE)
    var b = bigint_from_bytes(hex_to_bytes("deadbeefcafebabe"))
    if bigint_cmp(a, b) != 0:
        raise Error("from_u64 vs from_bytes mismatch")


def test_from_to_bytes_roundtrip() raises:
    # 32-byte big-endian value
    var hex = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
    var b = hex_to_bytes(hex)
    var a = bigint_from_bytes(b)
    var got = bytes_to_hex(bigint_to_bytes(a, 32))
    if got != hex:
        raise Error("roundtrip: got " + got + ", want " + hex)


def test_from_to_bytes_leading_zeros() raises:
    # Leading zeros in byte array should be stripped, but to_bytes should pad
    var b = hex_to_bytes("000000ff")
    var a = bigint_from_bytes(b)
    # to_bytes with 4 bytes should restore
    var got = bytes_to_hex(bigint_to_bytes(a, 4))
    if got != "000000ff":
        raise Error("leading zeros: got " + got)


# ============================================================================
# Arithmetic tests
# ============================================================================

def test_add_carry() raises:
    # 0xFFFFFFFF + 1 = 0x100000000
    var a = bigint_from_u64(0xFFFFFFFF)
    var b = bigint_from_u64(1)
    var c = bigint_add(a, b)
    var got = bytes_to_hex(bigint_to_bytes(c, 5))
    if got != "0100000000":
        raise Error("add carry: got " + got)


def test_add_large() raises:
    # 2^64 - 1 + 2^64 - 1 = 2^65 - 2
    var a = bigint_from_u64(0xFFFFFFFFFFFFFFFF)
    var c = bigint_add(a, a.copy())
    # expected: 0x1FFFFFFFFFFFFFFFE
    var got = bytes_to_hex(bigint_to_bytes(c, 9))
    if got != "01fffffffffffffffe":
        raise Error("add large: got " + got)


def test_sub_borrow() raises:
    # 0x100000000 - 1 = 0xFFFFFFFF
    var a = bigint_from_u64(0x100000000)
    var b = bigint_from_u64(1)
    var c = bigint_sub(a, b)
    var got = bytes_to_hex(bigint_to_bytes(c, 4))
    if got != "ffffffff":
        raise Error("sub borrow: got " + got)


def test_sub_equal() raises:
    var a = bigint_from_u64(12345)
    var c = bigint_sub(a, a.copy())
    if not bigint_is_zero(c):
        raise Error("sub equal: expected zero, got " + bytes_to_hex(bigint_to_bytes(c, 4)))


def test_mul_basic() raises:
    # 0xFFFFFFFF * 0xFFFFFFFF = 0xFFFFFFFE00000001
    var a = bigint_from_u64(0xFFFFFFFF)
    var c = bigint_mul(a, a.copy())
    var got = bytes_to_hex(bigint_to_bytes(c, 8))
    if got != "fffffffe00000001":
        raise Error("mul basic: got " + got)


def test_mul_zero() raises:
    var a = bigint_from_u64(12345678)
    var z = bigint_zero()
    var c = bigint_mul(a, z)
    if not bigint_is_zero(c):
        raise Error("mul by zero: not zero")


def test_mul_one() raises:
    var a = bigint_from_u64(0xDEADBEEF)
    var o = bigint_one()
    var c = bigint_mul(a, o)
    if bigint_cmp(a, c) != 0:
        raise Error("mul by one: changed value")


# ============================================================================
# Bit length test
# ============================================================================

def test_bit_len() raises:
    if bigint_bit_len(bigint_zero()) != 0:
        raise Error("bit_len(0) != 0")
    if bigint_bit_len(bigint_one()) != 1:
        raise Error("bit_len(1) != 1")
    if bigint_bit_len(bigint_from_u64(0xFF)) != 8:
        raise Error("bit_len(0xFF) != 8")
    if bigint_bit_len(bigint_from_u64(0x100)) != 9:
        raise Error("bit_len(0x100) != 9")
    if bigint_bit_len(bigint_from_u64(0xFFFFFFFF)) != 32:
        raise Error("bit_len(2^32-1) != 32")
    if bigint_bit_len(bigint_from_u64(0x100000000)) != 33:
        raise Error("bit_len(2^32) != 33")


# ============================================================================
# Modular reduction
# ============================================================================

def test_mod_basic() raises:
    # 17 mod 5 = 2
    var a = bigint_from_u64(17)
    var n = bigint_from_u64(5)
    var r = bigint_mod(a, n)
    if bigint_cmp(r, bigint_from_u64(2)) != 0:
        raise Error("17 mod 5: got " + bytes_to_hex(bigint_to_bytes(r, 4)))


def test_mod_exact() raises:
    # 100 mod 10 = 0
    var a = bigint_from_u64(100)
    var n = bigint_from_u64(10)
    var r = bigint_mod(a, n)
    if not bigint_is_zero(r):
        raise Error("100 mod 10: not zero")


def test_mod_less_than_n() raises:
    # a < n → a mod n = a
    var a = bigint_from_u64(7)
    var n = bigint_from_u64(13)
    var r = bigint_mod(a, n)
    if bigint_cmp(r, a) != 0:
        raise Error("7 mod 13: expected 7")


# ============================================================================
# Modular exponentiation — textbook RSA (n=3233, e=17, d=2753)
# ============================================================================

def test_modexp_textbook_rsa_enc() raises:
    # 65^17 mod 3233 = 2790  (RSA encrypt)
    var base = bigint_from_u64(65)
    var exp  = bigint_from_u64(17)
    var n    = bigint_from_u64(3233)
    var r    = bigint_modexp(base, exp, n)
    if bigint_cmp(r, bigint_from_u64(2790)) != 0:
        raise Error("65^17 mod 3233: got " + bytes_to_hex(bigint_to_bytes(r, 4)))


def test_modexp_textbook_rsa_dec() raises:
    # 2790^2753 mod 3233 = 65  (RSA decrypt)
    var base = bigint_from_u64(2790)
    var exp  = bigint_from_u64(2753)
    var n    = bigint_from_u64(3233)
    var r    = bigint_modexp(base, exp, n)
    if bigint_cmp(r, bigint_from_u64(65)) != 0:
        raise Error("2790^2753 mod 3233: got " + bytes_to_hex(bigint_to_bytes(r, 4)))


def test_modexp_base0() raises:
    # 0^e mod n = 0
    var z = bigint_zero()
    var e = bigint_from_u64(65537)
    var n = bigint_from_u64(3233)
    var r = bigint_modexp(z, e, n)
    if not bigint_is_zero(r):
        raise Error("0^e mod n: not zero")


def test_modexp_exp0() raises:
    # b^0 mod n = 1
    var b = bigint_from_u64(12345)
    var e = bigint_zero()
    var n = bigint_from_u64(3233)
    var r = bigint_modexp(b, e, n)
    if bigint_cmp(r, bigint_one()) != 0:
        raise Error("b^0 mod n: not 1")


# ============================================================================
# Large modexp — Mersenne prime 2^127-1
# python3: pow(2, 65537, 2**127-1) = 32
# ============================================================================

def test_modexp_mersenne127() raises:
    # Modulus = 2^127 - 1 (Mersenne prime, 128-bit)
    var n_bytes = hex_to_bytes("7fffffffffffffffffffffffffffffff")
    var n = bigint_from_bytes(n_bytes)
    var base = bigint_from_u64(2)
    var exp  = bigint_from_u64(65537)
    var r    = bigint_modexp(base, exp, n)
    # Expected: 32 = 0x20
    if bigint_cmp(r, bigint_from_u64(32)) != 0:
        raise Error("2^65537 mod (2^127-1): got " +
                    bytes_to_hex(bigint_to_bytes(r, 16)))


# ============================================================================
# Large modexp — P-256 prime
# python3: pow(3, 65537, p256) =
#   1f0b20d5555cb1acbbe8ce8dada98c280312ed981c6e9320f24a37d6cc7d4104
# ============================================================================

def test_modexp_p256_prime() raises:
    # P-256 prime p = 2^256 - 2^224 + 2^192 + 2^96 - 1
    var p_hex = "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff"
    var p = bigint_from_bytes(hex_to_bytes(p_hex))
    var base = bigint_from_u64(3)
    var exp  = bigint_from_u64(65537)
    var r    = bigint_modexp(base, exp, p)
    var expected = "1f0b20d5555cb1acbbe8ce8dada98c280312ed981c6e9320f24a37d6cc7d4104"
    var got = bytes_to_hex(bigint_to_bytes(r, 32))
    if got != expected:
        raise Error("3^65537 mod p256: got " + got)


# ============================================================================
# Modular inverse — binary extended GCD
# ============================================================================

def test_modinv_small() raises:
    # 3^(-1) mod 7 = 5  (3*5=15 ≡ 1 mod 7)
    var r = bigint_modinv(bigint_from_u64(3), bigint_from_u64(7))
    if bigint_cmp(r, bigint_from_u64(5)) != 0:
        raise Error("modinv(3,7): got " + bytes_to_hex(bigint_to_bytes(r, 4)))
    # 2^(-1) mod 7 = 4  (2*4=8 ≡ 1 mod 7)
    var r2 = bigint_modinv(bigint_from_u64(2), bigint_from_u64(7))
    if bigint_cmp(r2, bigint_from_u64(4)) != 0:
        raise Error("modinv(2,7): got " + bytes_to_hex(bigint_to_bytes(r2, 4)))
    # 1^(-1) mod 7 = 1
    var r3 = bigint_modinv(bigint_from_u64(1), bigint_from_u64(7))
    if bigint_cmp(r3, bigint_from_u64(1)) != 0:
        raise Error("modinv(1,7): got " + bytes_to_hex(bigint_to_bytes(r3, 4)))


def test_modinv_consistency() raises:
    # Verify modinv is consistent with modexp: a * modinv(a, p) ≡ 1 mod p
    # Use a = 12345, p = 2^127 - 1 (Mersenne prime)
    var p_bytes = hex_to_bytes("7fffffffffffffffffffffffffffffff")
    var p = bigint_from_bytes(p_bytes)
    var a = bigint_from_u64(12345)
    var inv = bigint_modinv(a, p)
    var product = bigint_modmul(a, inv, p)
    if bigint_cmp(product, bigint_one()) != 0:
        raise Error("modinv consistency: a * inv != 1 mod p")


def test_modinv_p256_order() raises:
    # Verify modinv on P-256 order n matches modexp(a, n-2, n)
    # a = 3, n = P-256 order
    var n_hex = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"
    var n = bigint_from_bytes(hex_to_bytes(n_hex))
    var a = bigint_from_u64(3)
    var inv_gcd = bigint_modinv(a, n)
    var nm2 = bigint_sub(n, bigint_from_u64(2))
    var inv_fer = bigint_modexp(a, nm2, n)
    if bigint_cmp(inv_gcd, inv_fer) != 0:
        raise Error("modinv(3, n256): GCD != Fermat result")


def main() raises:
    var passed = 0
    var failed = 0
    print("=== BigInt Tests ===")
    print()
    run_test("zero and one",                   passed, failed, test_zero_one)
    run_test("from_u64",                       passed, failed, test_from_u64)
    run_test("from/to bytes roundtrip",        passed, failed, test_from_to_bytes_roundtrip)
    run_test("from bytes leading zeros",       passed, failed, test_from_to_bytes_leading_zeros)
    run_test("add with carry",                 passed, failed, test_add_carry)
    run_test("add large values",               passed, failed, test_add_large)
    run_test("sub with borrow",                passed, failed, test_sub_borrow)
    run_test("sub equal → zero",              passed, failed, test_sub_equal)
    run_test("mul basic",                      passed, failed, test_mul_basic)
    run_test("mul by zero",                    passed, failed, test_mul_zero)
    run_test("mul by one",                     passed, failed, test_mul_one)
    run_test("bit length",                     passed, failed, test_bit_len)
    run_test("mod basic (17 mod 5)",           passed, failed, test_mod_basic)
    run_test("mod exact (100 mod 10)",         passed, failed, test_mod_exact)
    run_test("mod < n identity",               passed, failed, test_mod_less_than_n)
    run_test("modexp RSA encrypt (65^17 mod 3233)", passed, failed, test_modexp_textbook_rsa_enc)
    run_test("modexp RSA decrypt (2790^2753 mod 3233)", passed, failed, test_modexp_textbook_rsa_dec)
    run_test("modexp base=0",                  passed, failed, test_modexp_base0)
    run_test("modexp exp=0",                   passed, failed, test_modexp_exp0)
    run_test("modexp Mersenne-127 (2^65537)",  passed, failed, test_modexp_mersenne127)
    run_test("modexp P-256 prime (3^65537)",   passed, failed, test_modexp_p256_prime)
    run_test("modinv small (3 mod 7, 2 mod 7, 1 mod 7)", passed, failed, test_modinv_small)
    run_test("modinv consistency (a * inv ≡ 1)", passed, failed, test_modinv_consistency)
    run_test("modinv P-256 order (GCD == Fermat)", passed, failed, test_modinv_p256_order)
    print()
    print("Results:", passed, "passed,", failed, "failed")
    if failed > 0:
        raise Error(String(failed) + " test(s) failed")
