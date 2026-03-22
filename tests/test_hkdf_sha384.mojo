# ============================================================================
# test_hkdf_sha384.mojo — HKDF-SHA384 tests
# ============================================================================
# Test vectors generated with Python (hmac/hashlib), RFC 5869 compliant.
#
# EXTRACT_SALT = bytes(range(48))
# EXTRACT_IKM  = bytes(range(48, 96))
# EXTRACT_PRK  = 92ee50c3...bc32
#
# EXPAND_INFO  = b"test info vector"
# EXPAND_OKM64 = 64 bytes of output
#
# LABEL_DERIVED: hkdf_expand_label_sha384(PRK, "derived", SHA384(""), 48)
# ============================================================================

from crypto.hkdf import hkdf_extract_sha384, hkdf_expand_sha384, hkdf_expand_label_sha384
from crypto.hash import sha384


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


def run_test(name: String, mut passed: Int, mut failed: Int, test_fn: def () raises -> None):
    try:
        test_fn()
        print("  PASS:", name)
        passed += 1
    except e:
        print("  FAIL:", name, "-", String(e))
        failed += 1


# ============================================================================
# Test 1: HKDF-Extract-SHA384
# salt = bytes(range(48)), ikm = bytes(range(48, 96))
# Expected PRK (Python): hmac.new(salt, ikm, sha384).digest()
# ============================================================================

def test_hkdf_extract_sha384() raises:
    var salt = List[UInt8](capacity=48)
    for i in range(48):
        salt.append(UInt8(i))
    var ikm = List[UInt8](capacity=48)
    for i in range(48, 96):
        ikm.append(UInt8(i))
    var prk = hkdf_extract_sha384(salt, ikm)
    assert_hex_eq(
        prk,
        "92ee50c3a8d3af16665209c5085fa2540646325b5a45b43b247c9b528703d7661af064635f18710f30c1db81d221bc32",
        "hkdf_extract_sha384",
    )


# ============================================================================
# Test 2: HKDF-Expand-SHA384 — 64-byte output
# prk  = EXTRACT_PRK above
# info = b"test info vector"
# Expected OKM (Python, length=64):
# b84ad59c5463e1e741c5f2747f88730d2d09121d057b7c165730428e59bd0b7b
# fb54441b9dfaf0ed2946fed803cb9b74777d4e40d58cf2de7d66a6bc82491da9
# ============================================================================

def test_hkdf_expand_sha384() raises:
    var prk = hex_to_bytes(
        "92ee50c3a8d3af16665209c5085fa2540646325b5a45b43b247c9b528703d7661af064635f18710f30c1db81d221bc32"
    )
    # info = "test info vector"
    var info_str = "test info vector"
    var info_bytes_span = info_str.as_bytes()
    var info = List[UInt8](capacity=len(info_bytes_span))
    for i in range(len(info_bytes_span)):
        info.append(info_bytes_span[i])
    var okm = hkdf_expand_sha384(prk, info, 64)
    assert_hex_eq(
        okm,
        "b84ad59c5463e1e741c5f2747f88730d2d09121d057b7c165730428e59bd0b7bfb54441b9dfaf0ed2946fed803cb9b74777d4e40d58cf2de7d66a6bc82491da9",
        "hkdf_expand_sha384_64",
    )


# ============================================================================
# Test 3: HKDF-Expand-Label-SHA384 with "derived" label
# secret  = EXTRACT_PRK
# label   = "derived"
# context = SHA384("")
# length  = 48
# Expected (Python): 78bc208897348d83c1b9de02fb72b8e476239ba8685ea40541564a2405e07b8478f23bca8d1b56da0f923c5d0882a7c4
# ============================================================================

def test_hkdf_expand_label_sha384() raises:
    var secret = hex_to_bytes(
        "92ee50c3a8d3af16665209c5085fa2540646325b5a45b43b247c9b528703d7661af064635f18710f30c1db81d221bc32"
    )
    var empty = List[UInt8]()
    var context = sha384(empty)
    var result = hkdf_expand_label_sha384(secret, "derived", context, 48)
    assert_hex_eq(
        result,
        "78bc208897348d83c1b9de02fb72b8e476239ba8685ea40541564a2405e07b8478f23bca8d1b56da0f923c5d0882a7c4",
        "hkdf_expand_label_sha384_derived",
    )


def main() raises:
    var passed = 0
    var failed = 0
    print("=== HKDF-SHA384 Tests ===")
    print()
    run_test("hkdf_extract_sha384 matches Python HMAC-SHA384",    passed, failed, test_hkdf_extract_sha384)
    run_test("hkdf_expand_sha384 64-byte output",                 passed, failed, test_hkdf_expand_sha384)
    run_test("hkdf_expand_label_sha384 'derived' label",          passed, failed, test_hkdf_expand_label_sha384)
    print()
    print("Results:", passed, "passed,", failed, "failed")
    if failed > 0:
        raise Error(String(failed) + " test(s) failed")
