# ============================================================================
# test_hmac.mojo — HMAC-SHA256 / HMAC-SHA384 RFC 4231 known-answer tests
# ============================================================================

from crypto.hmac import hmac_sha256, hmac_sha384, hmac_equal


# ============================================================================
# Helpers
# ============================================================================


fn _hex_nibble(b: UInt8) raises -> UInt8:
    if b >= 48 and b <= 57:
        return b - 48
    if b >= 97 and b <= 102:
        return b - 87
    raise Error("bad hex char")


fn hex_to_bytes(hex: String) raises -> List[UInt8]:
    var raw = hex.as_bytes()
    var n = len(raw)
    if n % 2 != 0:
        raise Error("odd hex length")
    var out = List[UInt8](capacity=n // 2)
    for i in range(0, n, 2):
        out.append((_hex_nibble(raw[i]) << 4) | _hex_nibble(raw[i + 1]))
    return out^


fn bytes_to_hex(b: List[UInt8]) -> String:
    var digits = "0123456789abcdef".as_bytes()
    var result = List[UInt8](capacity=len(b) * 2)
    for i in range(len(b)):
        var byte = Int(b[i])
        result.append(digits[(byte >> 4) & 0xF])
        result.append(digits[byte & 0xF])
    return String(unsafe_from_utf8=result^)


fn str_to_bytes(s: String) -> List[UInt8]:
    var raw = s.as_bytes()
    var out = List[UInt8](capacity=len(raw))
    for i in range(len(raw)):
        out.append(raw[i])
    return out^


fn repeat_byte(b: UInt8, n: Int) -> List[UInt8]:
    var out = List[UInt8](capacity=n)
    for _ in range(n):
        out.append(b)
    return out^


fn assert_hex_eq(got: List[UInt8], expected_hex: String, label: String) raises:
    var got_hex = bytes_to_hex(got)
    if got_hex != expected_hex:
        raise Error(label + ": got " + got_hex + ", want " + expected_hex)


fn run_test(
    name: String,
    mut passed: Int,
    mut failed: Int,
    test_fn: fn () raises -> None,
):
    try:
        test_fn()
        print("  PASS:", name)
        passed += 1
    except e:
        print("  FAIL:", name, "-", String(e))
        failed += 1


# ============================================================================
# RFC 4231 Test Cases — HMAC-SHA256
# ============================================================================


fn test_hmac256_tc1() raises:
    # key = 0x0b * 20, data = "Hi There"
    var key = repeat_byte(0x0B, 20)
    var data = str_to_bytes("Hi There")
    var result = hmac_sha256(key, data)
    assert_hex_eq(
        result,
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
        "hmac256_tc1",
    )


fn test_hmac256_tc2() raises:
    # key = "Jefe", data = "what do ya want for nothing?"
    var key = str_to_bytes("Jefe")
    var data = str_to_bytes("what do ya want for nothing?")
    var result = hmac_sha256(key, data)
    assert_hex_eq(
        result,
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
        "hmac256_tc2",
    )


fn test_hmac256_tc3() raises:
    # key = 0xaa * 20, data = 0xdd * 50
    var key = repeat_byte(0xAA, 20)
    var data = repeat_byte(0xDD, 50)
    var result = hmac_sha256(key, data)
    assert_hex_eq(
        result,
        "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
        "hmac256_tc3",
    )


fn test_hmac256_tc4() raises:
    # key = 0x01..0x19 (25 bytes), data = 0xcd * 50
    var key = List[UInt8](capacity=25)
    for i in range(1, 26):
        key.append(UInt8(i))
    var data = repeat_byte(0xCD, 50)
    var result = hmac_sha256(key, data)
    assert_hex_eq(
        result,
        "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b",
        "hmac256_tc4",
    )


fn test_hmac256_tc5() raises:
    # key = 0x0c * 20, data = "Test With Truncation"
    var key = repeat_byte(0x0C, 20)
    var data = str_to_bytes("Test With Truncation")
    var result = hmac_sha256(key, data)
    assert_hex_eq(
        result,
        "a3b6167473100ee06e0c796c2955552bfa6f7c0a6a8aef8b93f860aab0cd20c5",
        "hmac256_tc5",
    )


fn test_hmac256_tc6() raises:
    # key = 0xaa * 131 (longer than block size), data = "Test Using Larger..."
    var key = repeat_byte(0xAA, 131)
    var data = str_to_bytes(
        "Test Using Larger Than Block-Size Key - Hash Key First"
    )
    var result = hmac_sha256(key, data)
    assert_hex_eq(
        result,
        "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
        "hmac256_tc6",
    )


fn test_hmac256_tc7() raises:
    # key = 0xaa * 131, data = long string
    var key = repeat_byte(0xAA, 131)
    var data = str_to_bytes(
        "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm."
    )
    var result = hmac_sha256(key, data)
    assert_hex_eq(
        result,
        "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2",
        "hmac256_tc7",
    )


# ============================================================================
# RFC 4231 Test Cases — HMAC-SHA384
# ============================================================================


fn test_hmac384_tc1() raises:
    var key = repeat_byte(0x0B, 20)
    var data = str_to_bytes("Hi There")
    var result = hmac_sha384(key, data)
    assert_hex_eq(
        result,
        "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6",
        "hmac384_tc1",
    )


fn test_hmac384_tc2() raises:
    var key = str_to_bytes("Jefe")
    var data = str_to_bytes("what do ya want for nothing?")
    var result = hmac_sha384(key, data)
    assert_hex_eq(
        result,
        "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649",
        "hmac384_tc2",
    )


fn test_hmac384_tc3() raises:
    var key = repeat_byte(0xAA, 20)
    var data = repeat_byte(0xDD, 50)
    var result = hmac_sha384(key, data)
    assert_hex_eq(
        result,
        "88062608d3e6ad8a0aa2ace014c8a86f0aa635d947ac9febe83ef4e55966144b2a5ab39dc13814b94e3ab6e101a34f27",
        "hmac384_tc3",
    )


fn test_hmac384_tc4() raises:
    var key = List[UInt8](capacity=25)
    for i in range(1, 26):
        key.append(UInt8(i))
    var data = repeat_byte(0xCD, 50)
    var result = hmac_sha384(key, data)
    assert_hex_eq(
        result,
        "3e8a69b7783c25851933ab6290af6ca77a9981480850009cc5577c6e1f573b4e6801dd23c4a7d679ccf8a386c674cffb",
        "hmac384_tc4",
    )


fn test_hmac384_tc6() raises:
    var key = repeat_byte(0xAA, 131)
    var data = str_to_bytes(
        "Test Using Larger Than Block-Size Key - Hash Key First"
    )
    var result = hmac_sha384(key, data)
    assert_hex_eq(
        result,
        "4ece084485813e9088d2c63a041bc5b44f9ef1012a2b588f3cd11f05033ac4c60c2ef6ab4030fe8296248df163f44952",
        "hmac384_tc6",
    )


fn test_hmac384_tc7() raises:
    var key = repeat_byte(0xAA, 131)
    var data = str_to_bytes(
        "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm."
    )
    var result = hmac_sha384(key, data)
    assert_hex_eq(
        result,
        "6617178e941f020d351e2f254e8fd32c602420feb0b8fb9adccebb82461e99c5a678cc31e799176d3860e6110c46523e",
        "hmac384_tc7",
    )


# ============================================================================
# hmac_equal — constant-time comparison
# ============================================================================


fn test_hmac_equal_same() raises:
    var a = repeat_byte(0x42, 32)
    var b = repeat_byte(0x42, 32)
    if not hmac_equal(a, b):
        raise Error("hmac_equal: same bytes returned False")


fn test_hmac_equal_diff() raises:
    var a = repeat_byte(0x42, 32)
    var b = repeat_byte(0x43, 32)
    if hmac_equal(a, b):
        raise Error("hmac_equal: different bytes returned True")


fn test_hmac_equal_length_mismatch() raises:
    var a = repeat_byte(0x42, 32)
    var b = repeat_byte(0x42, 31)
    if hmac_equal(a, b):
        raise Error("hmac_equal: different lengths returned True")


fn test_hmac_equal_one_bit() raises:
    # Differ by a single bit in the last byte
    var a = repeat_byte(0x00, 32)
    var b = repeat_byte(0x00, 32)
    b[31] = 0x01
    if hmac_equal(a, b):
        raise Error("hmac_equal: single-bit diff returned True")


# ============================================================================
# Main
# ============================================================================


fn main() raises:
    var passed = 0
    var failed = 0

    print("=== HMAC-SHA256 / SHA384 Tests ===")
    print()

    run_test("HMAC-SHA256 TC1 (short key)", passed, failed, test_hmac256_tc1)
    run_test("HMAC-SHA256 TC2 (string key)", passed, failed, test_hmac256_tc2)
    run_test("HMAC-SHA256 TC3 (0xdd data)", passed, failed, test_hmac256_tc3)
    run_test("HMAC-SHA256 TC4 (seq key)", passed, failed, test_hmac256_tc4)
    run_test("HMAC-SHA256 TC5 (truncation)", passed, failed, test_hmac256_tc5)
    run_test("HMAC-SHA256 TC6 (long key)", passed, failed, test_hmac256_tc6)
    run_test("HMAC-SHA256 TC7 (long key+data)", passed, failed, test_hmac256_tc7)

    run_test("HMAC-SHA384 TC1 (short key)", passed, failed, test_hmac384_tc1)
    run_test("HMAC-SHA384 TC2 (string key)", passed, failed, test_hmac384_tc2)
    run_test("HMAC-SHA384 TC3 (0xdd data)", passed, failed, test_hmac384_tc3)
    run_test("HMAC-SHA384 TC4 (seq key)", passed, failed, test_hmac384_tc4)
    run_test("HMAC-SHA384 TC6 (long key)", passed, failed, test_hmac384_tc6)
    run_test("HMAC-SHA384 TC7 (long key+data)", passed, failed, test_hmac384_tc7)

    run_test("hmac_equal same bytes", passed, failed, test_hmac_equal_same)
    run_test("hmac_equal different bytes", passed, failed, test_hmac_equal_diff)
    run_test("hmac_equal length mismatch", passed, failed, test_hmac_equal_length_mismatch)
    run_test("hmac_equal single-bit diff", passed, failed, test_hmac_equal_one_bit)

    print()
    print("Results:", passed, "passed,", failed, "failed")
    if failed > 0:
        raise Error(String(failed) + " test(s) failed")
