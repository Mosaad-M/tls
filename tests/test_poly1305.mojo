# ============================================================================
# test_poly1305.mojo — Poly1305 MAC + ChaCha20-Poly1305 AEAD RFC 8439 tests
# ============================================================================

from crypto.poly1305 import poly1305_mac, chacha20_poly1305_encrypt, chacha20_poly1305_decrypt


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


def run_test(name: String, mut passed: Int, mut failed: Int, test_fn: def () raises -> None):
    try:
        test_fn()
        print("  PASS:", name)
        passed += 1
    except e:
        print("  FAIL:", name, "-", String(e))
        failed += 1


# ============================================================================
# RFC 8439 §2.5.2 — Poly1305 MAC
# ============================================================================

def test_poly1305_mac_rfc8439() raises:
    # RFC 8439 §2.5.2 test vector
    # Key: 85d6be7857556d337f4452fe42d506a8 0103808afb0db2fd4abff6af4149f51b
    var key = hex_to_bytes(
        "85d6be7857556d337f4452fe42d506a8"
        "0103808afb0db2fd4abff6af4149f51b"
    )
    # Message: "Cryptographic Forum Research Group"
    var msg = List[UInt8]()
    var s = "Cryptographic Forum Research Group"
    for b in s.as_bytes():
        msg.append(b)
    var tag = poly1305_mac(key, msg)
    assert_hex_eq(tag, "a8061dc1305136c6c22b8baf0c0127a9", "poly1305_mac")


# ============================================================================
# RFC 8439 §2.8.2 — ChaCha20-Poly1305 AEAD
# ============================================================================

def test_chacha20_poly1305_encrypt_rfc8439() raises:
    # Key: 80 81 82 ... 9f (32 bytes)
    var key = List[UInt8](capacity=32)
    for i in range(32): key.append(UInt8(0x80 + i))
    # Nonce
    var nonce = hex_to_bytes("070000004041424344454647")
    # AAD
    var aad = hex_to_bytes("50515253c0c1c2c3c4c5c6c7")
    # Plaintext
    var s = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
    var pt = List[UInt8]()
    for b in s.as_bytes():
        pt.append(b)

    var res = chacha20_poly1305_encrypt(key, nonce, aad, pt)
    var ct  = res[0].copy()
    var tag = res[1].copy()

    assert_hex_eq(
        ct,
        "d31a8d34648e60db7b86afbc53ef7ec2"
        "a4aded51296e08fea9e2b5a736ee62d6"
        "3dbea45e8ca9671282fafb69da92728b"
        "1a71de0a9e060b2905d6a5b67ecd3b36"
        "92ddbd7f2d778b8c9803aee328091b58"
        "fab324e4fad675945585808b4831d7bc"
        "3ff4def08e4b7a9de576d26586cec64b"
        "6116",
        "aead_ct",
    )
    assert_hex_eq(tag, "1ae10b594f09e26a7e902ecbd0600691", "aead_tag")


# ============================================================================
# Decrypt round-trip
# ============================================================================

def test_chacha20_poly1305_roundtrip() raises:
    var key = List[UInt8](capacity=32)
    for i in range(32): key.append(UInt8(i))
    var nonce = hex_to_bytes("000000000000000000000000")
    var aad = hex_to_bytes("feedfacedeadbeef")
    var pt = hex_to_bytes("d9313225f88406e5a55909c5aff5269a")

    var enc = chacha20_poly1305_encrypt(key, nonce, aad, pt)
    var ct  = enc[0].copy()
    var tag = enc[1].copy()
    var recovered = chacha20_poly1305_decrypt(key, nonce, aad, ct, tag)
    assert_hex_eq(recovered, "d9313225f88406e5a55909c5aff5269a", "roundtrip")


# ============================================================================
# Tamper rejection
# ============================================================================

def test_reject_tampered_ct() raises:
    var key = List[UInt8](capacity=32)
    for i in range(32): key.append(UInt8(i))
    var nonce = hex_to_bytes("000000000000000000000000")
    var pt = hex_to_bytes("d9313225f88406e5a55909c5aff5269a")
    var enc = chacha20_poly1305_encrypt(key, nonce, List[UInt8](), pt)
    var ct  = enc[0].copy()
    var tag = enc[1].copy()
    ct[0] ^= 0x01
    var raised = False
    try:
        _ = chacha20_poly1305_decrypt(key, nonce, List[UInt8](), ct, tag)
    except:
        raised = True
    if not raised:
        raise Error("tampered CT not rejected")


def test_reject_tampered_tag() raises:
    var key = List[UInt8](capacity=32)
    for i in range(32): key.append(UInt8(i))
    var nonce = hex_to_bytes("000000000000000000000000")
    var pt = hex_to_bytes("d9313225f88406e5a55909c5aff5269a")
    var enc = chacha20_poly1305_encrypt(key, nonce, List[UInt8](), pt)
    var ct  = enc[0].copy()
    var tag = enc[1].copy()
    tag[15] ^= 0x01
    var raised = False
    try:
        _ = chacha20_poly1305_decrypt(key, nonce, List[UInt8](), ct, tag)
    except:
        raised = True
    if not raised:
        raise Error("tampered tag not rejected")


def test_reject_tampered_aad() raises:
    var key = List[UInt8](capacity=32)
    for i in range(32): key.append(UInt8(i))
    var nonce = hex_to_bytes("000000000000000000000000")
    var aad = hex_to_bytes("feedfacedeadbeef")
    var pt = hex_to_bytes("d9313225f88406e5a55909c5aff5269a")
    var enc = chacha20_poly1305_encrypt(key, nonce, aad, pt)
    var ct  = enc[0].copy()
    var tag = enc[1].copy()
    aad[0] ^= 0x01
    var raised = False
    try:
        _ = chacha20_poly1305_decrypt(key, nonce, aad, ct, tag)
    except:
        raised = True
    if not raised:
        raise Error("tampered AAD not rejected")


def main() raises:
    var passed = 0
    var failed = 0
    print("=== Poly1305 / ChaCha20-Poly1305 Tests ===")
    print()
    run_test("RFC 8439 §2.5.2 Poly1305 MAC",          passed, failed, test_poly1305_mac_rfc8439)
    run_test("RFC 8439 §2.8.2 AEAD encrypt",           passed, failed, test_chacha20_poly1305_encrypt_rfc8439)
    run_test("AEAD decrypt roundtrip",                 passed, failed, test_chacha20_poly1305_roundtrip)
    run_test("AEAD rejects tampered ciphertext",       passed, failed, test_reject_tampered_ct)
    run_test("AEAD rejects tampered tag",              passed, failed, test_reject_tampered_tag)
    run_test("AEAD rejects tampered AAD",              passed, failed, test_reject_tampered_aad)
    print()
    print("Results:", passed, "passed,", failed, "failed")
    if failed > 0:
        raise Error(String(failed) + " test(s) failed")
