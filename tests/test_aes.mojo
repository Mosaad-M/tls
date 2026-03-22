# ============================================================================
# test_aes.mojo — AES block cipher NIST FIPS 197 known-answer tests
# ============================================================================

from crypto.aes import AES


# ============================================================================
# Helpers
# ============================================================================


def _hex_nibble(b: UInt8) raises -> UInt8:
    if b >= 48 and b <= 57:
        return b - 48
    if b >= 97 and b <= 102:
        return b - 87
    raise Error("bad hex char")


def hex_to_bytes(hex: String) raises -> List[UInt8]:
    var raw = hex.as_bytes()
    var n = len(raw)
    if n % 2 != 0:
        raise Error("odd hex length")
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


def run_test(
    name: String,
    mut passed: Int,
    mut failed: Int,
    test_fn: def () raises -> None,
):
    try:
        test_fn()
        print("  PASS:", name)
        passed += 1
    except e:
        print("  FAIL:", name, "-", String(e))
        failed += 1


# ============================================================================
# AES-128 Tests (NIST FIPS 197)
# ============================================================================


def test_aes128_fips197_b() raises:
    # FIPS 197 Appendix B
    var key = hex_to_bytes("2b7e151628aed2a6abf7158809cf4f3c")
    var pt  = hex_to_bytes("3243f6a8885a308d313198a2e0370734")
    var aes = AES(key)
    var ct  = aes.encrypt_block(pt)
    assert_hex_eq(ct, "3925841d02dc09fbdc118597196a0b32", "fips197_b")


def test_aes128_fips197_c1() raises:
    # FIPS 197 Appendix C.1
    var key = hex_to_bytes("000102030405060708090a0b0c0d0e0f")
    var pt  = hex_to_bytes("00112233445566778899aabbccddeeff")
    var aes = AES(key)
    var ct  = aes.encrypt_block(pt)
    assert_hex_eq(ct, "69c4e0d86a7b0430d8cdb78070b4c55a", "fips197_c1")


def test_aes128_zero() raises:
    # AES-128, zero key, zero plaintext
    var key = List[UInt8](capacity=16)
    for _ in range(16):
        key.append(0x00)
    var pt = List[UInt8](capacity=16)
    for _ in range(16):
        pt.append(0x00)
    var aes = AES(key)
    var ct  = aes.encrypt_block(pt)
    assert_hex_eq(ct, "66e94bd4ef8a2c3b884cfa59ca342b2e", "aes128_zero")


def test_aes128_all_ff() raises:
    # AES-128, 0xff key, 0xff plaintext
    var key = List[UInt8](capacity=16)
    for _ in range(16):
        key.append(0xFF)
    var pt = List[UInt8](capacity=16)
    for _ in range(16):
        pt.append(0xFF)
    var aes = AES(key)
    var ct  = aes.encrypt_block(pt)
    # Verified with OpenSSL: echo -n 'ffffffffffffffffffffffffffffffff' | xxd -r -p | openssl enc -aes-128-ecb -nosalt -nopad -K ffffffffffffffffffffffffffffffff -e | xxd -p
    assert_hex_eq(ct, "bcbf217cb280cf30b2517052193ab979", "aes128_all_ff")


# ============================================================================
# AES-256 Tests (NIST FIPS 197)
# ============================================================================


def test_aes256_fips197_c3() raises:
    # FIPS 197 Appendix C.3
    var key = hex_to_bytes(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
    )
    var pt  = hex_to_bytes("00112233445566778899aabbccddeeff")
    var aes = AES(key)
    var ct  = aes.encrypt_block(pt)
    assert_hex_eq(ct, "8ea2b7ca516745bfeafc49904b496089", "fips197_c3")


def test_aes256_zero() raises:
    # AES-256, zero key, zero plaintext
    var key = List[UInt8](capacity=32)
    for _ in range(32):
        key.append(0x00)
    var pt = List[UInt8](capacity=16)
    for _ in range(16):
        pt.append(0x00)
    var aes = AES(key)
    var ct  = aes.encrypt_block(pt)
    assert_hex_eq(ct, "dc95c078a2408989ad48a21492842087", "aes256_zero")


def test_aes256_known() raises:
    # AES-256 with known key/pt pair (from NIST test vectors)
    var key = hex_to_bytes(
        "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"
    )
    var pt  = hex_to_bytes("6bc1bee22e409f96e93d7e117393172a")
    var aes = AES(key)
    var ct  = aes.encrypt_block(pt)
    assert_hex_eq(ct, "f3eed1bdb5d2a03c064b5a7e3db181f8", "aes256_known")


# ============================================================================
# Main
# ============================================================================


def main() raises:
    var passed = 0
    var failed = 0

    print("=== AES Block Cipher Tests ===")
    print()

    run_test("AES-128 FIPS 197 Appendix B", passed, failed, test_aes128_fips197_b)
    run_test("AES-128 FIPS 197 Appendix C.1", passed, failed, test_aes128_fips197_c1)
    run_test("AES-128 zero key/pt", passed, failed, test_aes128_zero)
    run_test("AES-128 all-0xFF key/pt", passed, failed, test_aes128_all_ff)

    run_test("AES-256 FIPS 197 Appendix C.3", passed, failed, test_aes256_fips197_c3)
    run_test("AES-256 zero key/pt", passed, failed, test_aes256_zero)
    run_test("AES-256 NIST known vector", passed, failed, test_aes256_known)

    print()
    print("Results:", passed, "passed,", failed, "failed")
    if failed > 0:
        raise Error(String(failed) + " test(s) failed")
