# ============================================================================
# test_curve25519.mojo — X25519 RFC 7748 known-answer tests
# ============================================================================

from crypto.curve25519 import x25519, x25519_public_key


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
# RFC 7748 §6.1 — X25519 function test vectors
# ============================================================================

fn test_x25519_rfc7748_alice() raises:
    # Alice's private key (scalar) — RFC 7748 §6.1
    var alice_priv = hex_to_bytes(
        "77076d0a7318a57d3c16c17251b26645"
        "df4c2f87ebc0992ab177fba51db92c2a"
    )
    # Alice's public key (u-coordinate of scalar * base point)
    var alice_pub = x25519_public_key(alice_priv)
    assert_hex_eq(
        alice_pub,
        "8520f0098930a754748b7ddcb43ef75a"
        "0dbf3a0d26381af4eba4a98eaa9b4e6a",
        "alice_pub",
    )


fn test_x25519_rfc7748_bob() raises:
    # Bob's private key — RFC 7748 §6.1
    var bob_priv = hex_to_bytes(
        "5dab087e624a8a4b79e17f8b83800ee6"
        "6f3bb1292618b6fd1c2f8b27ff88e0eb"
    )
    # Bob's public key
    var bob_pub = x25519_public_key(bob_priv)
    assert_hex_eq(
        bob_pub,
        "de9edb7d7b7dc1b4d35b61c2ece43537"
        "3f8343c85b78674dadfc7e146f882b4f",
        "bob_pub",
    )


fn test_x25519_rfc7748_shared_secret() raises:
    var alice_priv = hex_to_bytes(
        "77076d0a7318a57d3c16c17251b26645"
        "df4c2f87ebc0992ab177fba51db92c2a"
    )
    var bob_pub = hex_to_bytes(
        "de9edb7d7b7dc1b4d35b61c2ece43537"
        "3f8343c85b78674dadfc7e146f882b4f"
    )
    var bob_priv = hex_to_bytes(
        "5dab087e624a8a4b79e17f8b83800ee6"
        "6f3bb1292618b6fd1c2f8b27ff88e0eb"
    )
    var alice_pub = hex_to_bytes(
        "8520f0098930a754748b7ddcb43ef75a"
        "0dbf3a0d26381af4eba4a98eaa9b4e6a"
    )
    # Both sides compute the same shared secret
    var shared_alice = x25519(alice_priv, bob_pub)
    var shared_bob   = x25519(bob_priv, alice_pub)
    var expected = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
    assert_hex_eq(shared_alice, expected, "shared_alice")
    assert_hex_eq(shared_bob,   expected, "shared_bob")


# ============================================================================
# RFC 7748 §6.1 — Iterated test (u=9, apply 1000×)
# ============================================================================

fn test_x25519_iterated_1000() raises:
    # Start: k = u = 9 (encoded as 32 LE bytes)
    var k = List[UInt8](capacity=32)
    k.append(9)
    for _ in range(31): k.append(0)
    var u = k.copy()

    # After 1 iteration
    var tmp = x25519(k.copy(), u.copy())
    u = k^
    k = tmp^

    # After 1000 iterations total
    for _ in range(999):
        tmp = x25519(k.copy(), u.copy())
        u = k^
        k = tmp^

    assert_hex_eq(
        k,
        "684cf59ba83309552800ef566f2f4d3c"
        "1c3887c49360e3875f2eb94d99532c51",
        "iterated_1000",
    )


# ============================================================================
# Low-order point rejection
# ============================================================================

fn test_x25519_reject_low_order() raises:
    # The all-zeros u-coordinate is a low-order point; x25519 must return 0
    # (RFC 7748 §6 — implementations SHOULD reject but RFC doesn't mandate it)
    # We verify that our implementation returns all-zero (i.e., the result is
    # identifiable) rather than crashing or producing garbage.
    var scalar = hex_to_bytes(
        "77076d0a7318a57d3c16c17251b26645"
        "c820949606b2ee7a76f50d2e49f8d4c9"
    )
    var zero_u = List[UInt8](capacity=32)
    for _ in range(32): zero_u.append(0)
    var result = x25519(scalar, zero_u)
    # Result must be all zeros (low-order point contributes nothing)
    assert_hex_eq(
        result,
        "0000000000000000000000000000000000000000000000000000000000000000",
        "low_order_zero",
    )


fn main() raises:
    var passed = 0
    var failed = 0
    print("=== X25519 / Curve25519 Tests ===")
    print()
    run_test("RFC 7748 Alice public key",        passed, failed, test_x25519_rfc7748_alice)
    run_test("RFC 7748 Bob public key",          passed, failed, test_x25519_rfc7748_bob)
    run_test("RFC 7748 shared secret",           passed, failed, test_x25519_rfc7748_shared_secret)
    run_test("RFC 7748 iterated ×1000",          passed, failed, test_x25519_iterated_1000)
    run_test("Low-order point → all-zero",       passed, failed, test_x25519_reject_low_order)
    print()
    print("Results:", passed, "passed,", failed, "failed")
    if failed > 0:
        raise Error(String(failed) + " test(s) failed")
