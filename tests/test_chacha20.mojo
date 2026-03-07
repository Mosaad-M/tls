# ============================================================================
# test_chacha20.mojo — ChaCha20 RFC 8439 known-answer tests
# ============================================================================

from crypto.chacha20 import chacha20_block, chacha20_encrypt


fn _hex_nibble(b: UInt8) raises -> UInt8:
    if b >= 48 and b <= 57: return b - 48
    if b >= 97 and b <= 102: return b - 87
    raise Error("bad hex char")


fn hex_to_bytes(hex: String) raises -> List[UInt8]:
    var raw = hex.as_bytes()
    var n = len(raw)
    if n % 2 != 0: raise Error("odd hex length")
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


fn assert_hex_eq(got: List[UInt8], expected_hex: String, label: String) raises:
    var got_hex = bytes_to_hex(got)
    if got_hex != expected_hex:
        raise Error(label + ": got " + got_hex + ", want " + expected_hex)


fn run_test(name: String, mut passed: Int, mut failed: Int, test_fn: fn () raises -> None):
    try:
        test_fn()
        print("  PASS:", name)
        passed += 1
    except e:
        print("  FAIL:", name, "-", String(e))
        failed += 1


# ============================================================================
# RFC 8439 §2.3.2 — ChaCha20 block function
# Key: 00..1f (32 bytes), Nonce: 000000090000004a00000000, Counter: 1
# ============================================================================

fn test_chacha20_block() raises:
    var key = List[UInt8](capacity=32)
    for i in range(32): key.append(UInt8(i))
    var nonce = hex_to_bytes("000000090000004a00000000")
    var block = chacha20_block(key, 1, nonce)
    assert_hex_eq(
        block,
        "10f1e7e4d13b5915500fdd1fa32071c4"
        "c7d1f4c733c068030422aa9ac3d46c4e"
        "d2826446079faa0914c2d705d98b02a2"
        "b5129cd1de164eb9cbd083e8a2503c4e",
        "chacha20_block",
    )


# ============================================================================
# RFC 8439 §2.4.2 — ChaCha20 encryption
# Key: 00..1f, Nonce: 000000000000004a00000000, Counter: 1
# Plaintext: "Ladies and Gentlemen of the class of '99: ..."
# ============================================================================

fn test_chacha20_encrypt() raises:
    var key = List[UInt8](capacity=32)
    for i in range(32): key.append(UInt8(i))
    var nonce = hex_to_bytes("000000000000004a00000000")

    # Plaintext from RFC 8439 §2.4.2 (114 bytes) — encode via String
    var plaintext = List[UInt8]()
    var s = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
    for b in s.as_bytes():
        plaintext.append(b)

    var ct = chacha20_encrypt(key, nonce, 1, plaintext)
    assert_hex_eq(
        ct,
        "6e2e359a2568f98041ba0728dd0d6981"
        "e97e7aec1d4360c20a27afccfd9fae0b"
        "f91b65c5524733ab8f593dabcd62b357"
        "1639d624e65152ab8f530c359f0861d8"
        "07ca0dbf500d6a6156a38e088a22b65e"
        "52bc514d16ccf806818ce91ab7793736"
        "5af90bbf74a35be6b40b8eedf2785e42"
        "874d",
        "chacha20_encrypt",
    )


# ============================================================================
# Decrypt is the same operation (XOR is its own inverse)
# ============================================================================

fn test_chacha20_decrypt_roundtrip() raises:
    var key = List[UInt8](capacity=32)
    for i in range(32): key.append(UInt8(i))
    var nonce = List[UInt8](capacity=12)
    for _ in range(12): nonce.append(0x00)
    var pt = List[UInt8](capacity=64)
    for i in range(64): pt.append(UInt8(i))
    var ct = chacha20_encrypt(key, nonce, 1, pt)
    var recovered = chacha20_encrypt(key, nonce, 1, ct)
    var pt_hex = bytes_to_hex(pt)
    var rec_hex = bytes_to_hex(recovered)
    if pt_hex != rec_hex:
        raise Error("decrypt roundtrip failed")


fn main() raises:
    var passed = 0
    var failed = 0
    print("=== ChaCha20 Tests ===")
    print()
    run_test("RFC 8439 §2.3.2 block function", passed, failed, test_chacha20_block)
    run_test("RFC 8439 §2.4.2 encrypt",        passed, failed, test_chacha20_encrypt)
    run_test("decrypt roundtrip",              passed, failed, test_chacha20_decrypt_roundtrip)
    print()
    print("Results:", passed, "passed,", failed, "failed")
    if failed > 0:
        raise Error(String(failed) + " test(s) failed")
