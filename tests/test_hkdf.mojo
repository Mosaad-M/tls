# ============================================================================
# test_hkdf.mojo — HKDF-SHA256 RFC 5869 known-answer tests
# ============================================================================

from crypto.hkdf import hkdf_extract, hkdf_expand, hkdf_expand_label


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


def repeat_byte(b: UInt8, n: Int) -> List[UInt8]:
    var out = List[UInt8](capacity=n)
    for _ in range(n):
        out.append(b)
    return out^


def seq_bytes(start: Int, end_excl: Int) -> List[UInt8]:
    var out = List[UInt8](capacity=end_excl - start)
    for i in range(start, end_excl):
        out.append(UInt8(i))
    return out^


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
# RFC 5869 Appendix A — Test Case 1 (SHA-256, basic)
# ============================================================================


def test_hkdf_tc1_extract() raises:
    # IKM  = 0x0b * 22
    # Salt = 000102030405060708090a0b0c
    # PRK  = 077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5
    var ikm = repeat_byte(0x0B, 22)
    var salt = hex_to_bytes("000102030405060708090a0b0c")
    var prk = hkdf_extract(salt, ikm)
    assert_hex_eq(
        prk,
        "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
        "tc1_extract",
    )


def test_hkdf_tc1_expand() raises:
    var prk = hex_to_bytes(
        "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
    )
    var info = hex_to_bytes("f0f1f2f3f4f5f6f7f8f9")
    var okm = hkdf_expand(prk, info, 42)
    assert_hex_eq(
        okm,
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
        "tc1_expand",
    )


# ============================================================================
# RFC 5869 Appendix A — Test Case 2 (SHA-256, longer inputs)
# ============================================================================


def test_hkdf_tc2_extract() raises:
    # IKM  = 0x00..0x4f (80 bytes)
    # Salt = 0x60..0xaf (80 bytes)
    # PRK  = 06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244
    var ikm = seq_bytes(0x00, 0x50)
    var salt = seq_bytes(0x60, 0xB0)
    var prk = hkdf_extract(salt, ikm)
    assert_hex_eq(
        prk,
        "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244",
        "tc2_extract",
    )


def test_hkdf_tc2_expand() raises:
    var prk = hex_to_bytes(
        "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244"
    )
    var info = seq_bytes(0xB0, 0x100)
    var okm = hkdf_expand(prk, info, 82)
    assert_hex_eq(
        okm,
        "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87",
        "tc2_expand",
    )


# ============================================================================
# RFC 5869 Appendix A — Test Case 3 (SHA-256, zero-length salt and info)
# ============================================================================


def test_hkdf_tc3_extract() raises:
    # IKM  = 0x0b * 22, no salt (treat as 0x00 * HashLen = 32 zeros)
    # PRK  = 19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04
    var ikm = repeat_byte(0x0B, 22)
    var salt = repeat_byte(0x00, 32)   # default salt = 0^HashLen
    var prk = hkdf_extract(salt, ikm)
    assert_hex_eq(
        prk,
        "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04",
        "tc3_extract",
    )


def test_hkdf_tc3_expand() raises:
    # info = empty, length = 42
    var prk = hex_to_bytes(
        "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04"
    )
    var info = List[UInt8]()
    var okm = hkdf_expand(prk, info, 42)
    assert_hex_eq(
        okm,
        "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
        "tc3_expand",
    )


# ============================================================================
# TLS 1.3 hkdf_expand_label (RFC 8446 §7.1)
# ============================================================================


def test_expand_label_derived() raises:
    # Derive the "derived" secret from a zero 32-byte secret (early_secret stage)
    # Using SHA-256 hash of empty string as context, label="derived", length=32
    # Verified against Python reference implementation
    var secret = repeat_byte(0x00, 32)
    var context = hex_to_bytes(
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )  # SHA-256("")
    var result = hkdf_expand_label(secret, "derived", context, 32)
    assert_hex_eq(
        result,
        "70735bf7c7bab21c1f802d8eab67e6fac3c48974f1c9caf8c99962acd585bbd8",
        "expand_label_derived",
    )


def test_expand_label_tls13_early_chain() raises:
    # TLS 1.3 early_secret (HKDF-Extract(0^32, 0^32)) then "derived" label
    # Matches RFC 8448 §3 reference
    var zero32 = repeat_byte(0x00, 32)
    var early_secret = hkdf_extract(zero32, zero32)
    assert_hex_eq(
        early_secret,
        "33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a",
        "early_secret",
    )
    var empty_hash = hex_to_bytes(
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )
    var derived = hkdf_expand_label(early_secret, "derived", empty_hash, 32)
    assert_hex_eq(
        derived,
        "6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba",
        "derived_from_early_secret",
    )


# ============================================================================
# Main
# ============================================================================


def main() raises:
    var passed = 0
    var failed = 0

    print("=== HKDF-SHA256 Tests ===")
    print()

    run_test("RFC 5869 TC1 extract", passed, failed, test_hkdf_tc1_extract)
    run_test("RFC 5869 TC1 expand (42 bytes)", passed, failed, test_hkdf_tc1_expand)
    run_test("RFC 5869 TC2 extract", passed, failed, test_hkdf_tc2_extract)
    run_test("RFC 5869 TC2 expand (82 bytes)", passed, failed, test_hkdf_tc2_expand)
    run_test("RFC 5869 TC3 extract (no salt)", passed, failed, test_hkdf_tc3_extract)
    run_test("RFC 5869 TC3 expand (empty info)", passed, failed, test_hkdf_tc3_expand)
    run_test("TLS 1.3 expand_label 'derived'", passed, failed, test_expand_label_derived)
    run_test("TLS 1.3 early_secret chain", passed, failed, test_expand_label_tls13_early_chain)

    print()
    print("Results:", passed, "passed,", failed, "failed")
    if failed > 0:
        raise Error(String(failed) + " test(s) failed")
