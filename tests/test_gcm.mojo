# ============================================================================
# test_gcm.mojo — AES-GCM AEAD NIST SP 800-38D known-answer tests
# ============================================================================

from crypto.gcm import gcm_encrypt, gcm_decrypt


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
# AES-128-GCM Tests (NIST SP 800-38D)
# ============================================================================


def test_gcm128_tc1_empty() raises:
    # TC1: zero key/IV, empty PT and AAD
    var key = hex_to_bytes("00000000000000000000000000000000")
    var iv  = hex_to_bytes("000000000000000000000000")
    var res = gcm_encrypt(key, iv, List[UInt8](), List[UInt8]())
    var ct  = res[0].copy()
    var tag = res[1].copy()
    assert_hex_eq(ct, "", "gcm128_tc1_ct")
    assert_hex_eq(tag, "58e2fccefa7e3061367f1d57a4e7455a", "gcm128_tc1_tag")


def test_gcm128_tc2_zero_pt() raises:
    # TC2: zero key/IV, 16-byte zero PT, no AAD
    var key = hex_to_bytes("00000000000000000000000000000000")
    var iv  = hex_to_bytes("000000000000000000000000")
    var pt  = List[UInt8](capacity=16)
    for _ in range(16):
        pt.append(0x00)
    var res = gcm_encrypt(key, iv, pt, List[UInt8]())
    var ct  = res[0].copy()
    var tag = res[1].copy()
    assert_hex_eq(ct,  "0388dace60b6a392f328c2b971b2fe78", "gcm128_tc2_ct")
    assert_hex_eq(tag, "ab6e47d42cec13bdf53a67b21257bddf", "gcm128_tc2_tag")


def test_gcm128_tc3_known_key() raises:
    # TC3: real key/IV, 64-byte PT, no AAD
    var key = hex_to_bytes("feffe9928665731c6d6a8f9467308308")
    var iv  = hex_to_bytes("cafebabefacedbaddecaf888")
    var pt  = hex_to_bytes(
        "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
        "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255"
    )
    var res = gcm_encrypt(key, iv, pt, List[UInt8]())
    var ct  = res[0].copy()
    var tag = res[1].copy()
    assert_hex_eq(
        ct,
        "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e"
        "21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985",
        "gcm128_tc3_ct",
    )
    assert_hex_eq(tag, "4d5c2af327cd64a62cf35abd2ba6fab4", "gcm128_tc3_tag")


def test_gcm128_tc4_with_aad() raises:
    # TC4: real key/IV, 60-byte PT, 20-byte AAD
    var key = hex_to_bytes("feffe9928665731c6d6a8f9467308308")
    var iv  = hex_to_bytes("cafebabefacedbaddecaf888")
    var pt  = hex_to_bytes(
        "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
        "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39"
    )
    var aad = hex_to_bytes("feedfacedeadbeeffeedfacedeadbeefabaddad2")
    var res = gcm_encrypt(key, iv, pt, aad)
    var ct  = res[0].copy()
    var tag = res[1].copy()
    assert_hex_eq(
        ct,
        "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e"
        "21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091",
        "gcm128_tc4_ct",
    )
    assert_hex_eq(tag, "5bc94fbc3221a5db94fae95ae7121a47", "gcm128_tc4_tag")


# ============================================================================
# AES-256-GCM Tests
# ============================================================================


def test_gcm256_tc1_empty() raises:
    var key = hex_to_bytes("00000000000000000000000000000000"
                           "00000000000000000000000000000000")
    var iv  = hex_to_bytes("000000000000000000000000")
    var res = gcm_encrypt(key, iv, List[UInt8](), List[UInt8]())
    var ct  = res[0].copy()
    var tag = res[1].copy()
    assert_hex_eq(ct, "", "gcm256_tc1_ct")
    assert_hex_eq(tag, "530f8afbc74536b9a963b4f1c4cb738b", "gcm256_tc1_tag")


def test_gcm256_tc2_zero_pt() raises:
    var key = hex_to_bytes("00000000000000000000000000000000"
                           "00000000000000000000000000000000")
    var iv  = hex_to_bytes("000000000000000000000000")
    var pt  = List[UInt8](capacity=16)
    for _ in range(16):
        pt.append(0x00)
    var res = gcm_encrypt(key, iv, pt, List[UInt8]())
    var ct  = res[0].copy()
    var tag = res[1].copy()
    assert_hex_eq(ct,  "cea7403d4d606b6e074ec5d3baf39d18", "gcm256_tc2_ct")
    assert_hex_eq(tag, "d0d1c8a799996bf0265b98b5d48ab919", "gcm256_tc2_tag")


def test_gcm256_tc4_with_aad() raises:
    var key = hex_to_bytes(
        "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308"
    )
    var iv  = hex_to_bytes("cafebabefacedbaddecaf888")
    var pt  = hex_to_bytes(
        "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
        "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39"
    )
    var aad = hex_to_bytes("feedfacedeadbeeffeedfacedeadbeefabaddad2")
    var res = gcm_encrypt(key, iv, pt, aad)
    var ct  = res[0].copy()
    var tag = res[1].copy()
    assert_hex_eq(
        ct,
        "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa"
        "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662",
        "gcm256_tc4_ct",
    )
    assert_hex_eq(tag, "76fc6ece0f4e1768cddf8853bb2d551b", "gcm256_tc4_tag")


# ============================================================================
# Decrypt round-trip and tamper rejection
# ============================================================================


def test_gcm_decrypt_roundtrip() raises:
    # Encrypt then decrypt, compare to original plaintext
    var key = hex_to_bytes("feffe9928665731c6d6a8f9467308308")
    var iv  = hex_to_bytes("cafebabefacedbaddecaf888")
    var pt  = hex_to_bytes("d9313225f88406e5a55909c5aff5269a")
    var aad = hex_to_bytes("feedfacedeadbeef")
    var enc = gcm_encrypt(key, iv, pt, aad)
    var ct  = enc[0].copy()
    var tag = enc[1].copy()
    var recovered = gcm_decrypt(key, iv, ct, tag, aad)
    assert_hex_eq(recovered, "d9313225f88406e5a55909c5aff5269a", "roundtrip")


def test_gcm_reject_tampered_ct() raises:
    var key = hex_to_bytes("feffe9928665731c6d6a8f9467308308")
    var iv  = hex_to_bytes("cafebabefacedbaddecaf888")
    var pt  = hex_to_bytes("d9313225f88406e5a55909c5aff5269a")
    var enc = gcm_encrypt(key, iv, pt, List[UInt8]())
    var ct  = enc[0].copy()
    var tag = enc[1].copy()
    ct[0] ^= 0x01  # flip a bit in ciphertext
    var raised = False
    try:
        _ = gcm_decrypt(key, iv, ct, tag, List[UInt8]())
    except:
        raised = True
    if not raised:
        raise Error("tampered CT was not rejected")


def test_gcm_reject_tampered_tag() raises:
    var key = hex_to_bytes("feffe9928665731c6d6a8f9467308308")
    var iv  = hex_to_bytes("cafebabefacedbaddecaf888")
    var pt  = hex_to_bytes("d9313225f88406e5a55909c5aff5269a")
    var enc = gcm_encrypt(key, iv, pt, List[UInt8]())
    var ct  = enc[0].copy()
    var tag = enc[1].copy()
    tag[15] ^= 0x01
    var raised = False
    try:
        _ = gcm_decrypt(key, iv, ct, tag, List[UInt8]())
    except:
        raised = True
    if not raised:
        raise Error("tampered tag was not rejected")


def test_gcm_reject_tampered_aad() raises:
    var key = hex_to_bytes("feffe9928665731c6d6a8f9467308308")
    var iv  = hex_to_bytes("cafebabefacedbaddecaf888")
    var pt  = hex_to_bytes("d9313225f88406e5a55909c5aff5269a")
    var aad = hex_to_bytes("feedfacedeadbeef")
    var enc = gcm_encrypt(key, iv, pt, aad)
    var ct  = enc[0].copy()
    var tag = enc[1].copy()
    aad[0] ^= 0x01
    var raised = False
    try:
        _ = gcm_decrypt(key, iv, ct, tag, aad)
    except:
        raised = True
    if not raised:
        raise Error("tampered AAD was not rejected")


# ============================================================================
# Main
# ============================================================================


def main() raises:
    var passed = 0
    var failed = 0

    print("=== AES-GCM Tests ===")
    print()

    run_test("AES-128-GCM TC1 (empty PT/AAD)", passed, failed, test_gcm128_tc1_empty)
    run_test("AES-128-GCM TC2 (16-byte zero PT)", passed, failed, test_gcm128_tc2_zero_pt)
    run_test("AES-128-GCM TC3 (64-byte PT, no AAD)", passed, failed, test_gcm128_tc3_known_key)
    run_test("AES-128-GCM TC4 (60-byte PT + AAD)", passed, failed, test_gcm128_tc4_with_aad)

    run_test("AES-256-GCM TC1 (empty PT/AAD)", passed, failed, test_gcm256_tc1_empty)
    run_test("AES-256-GCM TC2 (16-byte zero PT)", passed, failed, test_gcm256_tc2_zero_pt)
    run_test("AES-256-GCM TC4 (60-byte PT + AAD)", passed, failed, test_gcm256_tc4_with_aad)

    run_test("GCM decrypt round-trip", passed, failed, test_gcm_decrypt_roundtrip)
    run_test("GCM rejects tampered CT", passed, failed, test_gcm_reject_tampered_ct)
    run_test("GCM rejects tampered tag", passed, failed, test_gcm_reject_tampered_tag)
    run_test("GCM rejects tampered AAD", passed, failed, test_gcm_reject_tampered_aad)

    print()
    print("Results:", passed, "passed,", failed, "failed")
    if failed > 0:
        raise Error(String(failed) + " test(s) failed")
