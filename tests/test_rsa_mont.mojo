# ============================================================================
# test_rsa_mont.mojo — Montgomery RSA exponentiation (crypto/rsa.mojo _rsa_raw)
# against BigInt bigint_modexp
# ============================================================================
# Random odd moduli at sizes that fill the top 64-bit limb and sizes that do
# not (1032, 2056 bits: R mod n then needs extra doublings), exponents 3, 17,
# 65537 and random, bases up to n - 1. Plus the input checks: s >= n, even n,
# e = 0, leading zero bytes in n.
# ============================================================================

from crypto.rsa import _rsa_raw
from crypto.bigint import bigint_from_bytes, bigint_to_bytes, bigint_modexp
from crypto.random import csprng_bytes


def run_test[test_fn: def() thin raises -> None](name: String, mut passed: Int, mut failed: Int):
    try:
        test_fn()
        print("  PASS:", name)
        passed += 1
    except e:
        print("  FAIL:", name, "-", String(e))
        failed += 1


def _modulus(bytes: Int) raises -> List[UInt8]:
    var n = csprng_bytes(bytes)
    n[0] |= 0x80
    n[bytes - 1] |= 0x01
    return n^


def _below(n: List[UInt8]) raises -> List[UInt8]:
    var b = csprng_bytes(len(n))
    b[0] = n[0] >> 1  # top byte smaller than n's: b < n
    return b^


def _reference(base: List[UInt8], e: List[UInt8], n: List[UInt8]) -> List[UInt8]:
    return bigint_to_bytes(bigint_modexp(bigint_from_bytes(base), bigint_from_bytes(e), bigint_from_bytes(n)), len(n))


def test_matches_bigint_modexp() raises:
    var sizes: List[Int] = [128, 129, 192, 256, 257, 384, 512]  # bytes: 1024..4096 bits
    var exps = List[List[UInt8]]()
    exps.append([3])
    exps.append([17])
    exps.append([1, 0, 1])
    var rnd = csprng_bytes(4)
    rnd[3] |= 1
    exps.append(rnd^)
    for size in sizes:
        for e in exps:
            var n = _modulus(size)
            var base = _below(n)
            var got = _rsa_raw(base, n, e, size)
            if got != _reference(base, e, n):
                raise Error("n " + String(8 * size) + " bits, e of " + String(len(e)) + " bytes")
    # extremes: base 1 and n - 1
    var n = _modulus(256)
    var one = List[UInt8](length=256, fill=0)
    one[255] = 1
    var e65537: List[UInt8] = [1, 0, 1]
    if _rsa_raw(one, n, e65537, 256) != one:
        raise Error("1^e != 1")
    var nm1 = n.copy()
    nm1[255] ^= 1  # n odd: n - 1 clears the low bit
    if _rsa_raw(nm1, n, e65537, 256) != _reference(nm1, e65537, n):
        raise Error("(n-1)^e")


def test_8192_bit_modulus() raises:
    var n = _modulus(1024)
    var base = _below(n)
    var e: List[UInt8] = [3]
    if _rsa_raw(base, n, e, 1024) != _reference(base, e, n):
        raise Error("8192-bit modulus")


def test_input_checks() raises:
    var n = _modulus(256)
    var e: List[UInt8] = [1, 0, 1]
    var cases = List[String]()
    try:
        _ = _rsa_raw(n, n, e, 256)  # s == n
    except err:
        cases.append(String(err))
    var even = n.copy()
    even[255] &= 0xFE
    try:
        _ = _rsa_raw(_below(n), even, e, 256)
    except err:
        cases.append(String(err))
    var zero: List[UInt8] = [0]
    try:
        _ = _rsa_raw(_below(n), n, zero, 256)
    except err:
        cases.append(String(err))
    var huge = _modulus(1025)
    try:
        _ = _rsa_raw(_below(huge), huge, e, 1025)
    except err:
        cases.append(String(err))
    if len(cases) != 4:
        raise Error("only " + String(len(cases)) + " of 4 bad inputs rejected")
    if cases[0].find("out of range") < 0 or cases[1].find("odd") < 0 or cases[2].find("zero") < 0 or cases[3].find("too large") < 0:
        raise Error("unexpected messages: " + cases[0] + " | " + cases[1] + " | " + cases[2] + " | " + cases[3])
    # a modulus with leading zero bytes is the same modulus
    var padded: List[UInt8] = [0, 0]
    for b in n:
        padded.append(b)
    var base = _below(n)
    if _rsa_raw(base, padded, e, 256) != _rsa_raw(base, n, e, 256):
        raise Error("leading zeros in n changed the result")


def main() raises:
    var passed = 0
    var failed = 0
    print("test_rsa_mont")
    run_test[test_matches_bigint_modexp]("Montgomery modexp == BigInt modexp (1024..4096 bits, odd sizes, 4 exponents)", passed, failed)
    run_test[test_8192_bit_modulus]("8192-bit modulus", passed, failed)
    run_test[test_input_checks]("rejects s >= n, even n, e = 0, n > 8192 bits; ignores leading zeros", passed, failed)
    print("Results:", passed, "passed,", failed, "failed")
    if failed > 0:
        raise Error(String(failed) + " test(s) failed")
