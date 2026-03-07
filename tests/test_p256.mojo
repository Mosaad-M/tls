# ============================================================================
# test_p256.mojo — P-256 ECDH and ECDSA tests
# ============================================================================

from crypto.p256 import p256_public_key, p256_ecdh, p256_ecdsa_verify


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
# Generator validation — scalar = 1 must return the generator itself
# ============================================================================

fn test_generator_identity() raises:
    var priv = List[UInt8](capacity=32)
    for _ in range(31): priv.append(0)
    priv.append(1)  # scalar = 1
    var pub = p256_public_key(priv)
    # Expected: 04 || Gx || Gy
    var gx = "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
    var gy = "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
    if pub[0] != 0x04:
        raise Error("generator_identity: bad prefix byte")
    var got_x = List[UInt8](capacity=32)
    var got_y = List[UInt8](capacity=32)
    for i in range(32): got_x.append(pub[1 + i])
    for i in range(32): got_y.append(pub[33 + i])
    assert_hex_eq(got_x, gx, "Gx")
    assert_hex_eq(got_y, gy, "Gy")


# ============================================================================
# RFC 6979 / NIST — Alice public key derivation
#   d = c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721
#   Qx = 60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6
#   Qy = 7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299
# ============================================================================

fn test_public_key_alice() raises:
    var d = hex_to_bytes(
        "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721"
    )
    var pub = p256_public_key(d)
    var got_x = List[UInt8](capacity=32)
    var got_y = List[UInt8](capacity=32)
    for i in range(32): got_x.append(pub[1 + i])
    for i in range(32): got_y.append(pub[33 + i])
    assert_hex_eq(
        got_x,
        "60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6",
        "alice_Qx",
    )
    assert_hex_eq(
        got_y,
        "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299",
        "alice_Qy",
    )


# ============================================================================
# Bob public key derivation
#   d = 0f56db78ca460b055c500064824bed999a25aaf48ebb519ac201537b85479813
#   Qx = e266ddfdc12668db30d4ca3e8f7749432c416044f2d2b8c10bf3d4012aeffa8a
#   Qy = bfa86404a2e9ffe67d47c587ef7a97a7f456b863b4d02cfc6928973ab5b1cb39
# ============================================================================

fn test_public_key_bob() raises:
    var d = hex_to_bytes(
        "0f56db78ca460b055c500064824bed999a25aaf48ebb519ac201537b85479813"
    )
    var pub = p256_public_key(d)
    var got_x = List[UInt8](capacity=32)
    var got_y = List[UInt8](capacity=32)
    for i in range(32): got_x.append(pub[1 + i])
    for i in range(32): got_y.append(pub[33 + i])
    assert_hex_eq(
        got_x,
        "e266ddfdc12668db30d4ca3e8f7749432c416044f2d2b8c10bf3d4012aeffa8a",
        "bob_Qx",
    )
    assert_hex_eq(
        got_y,
        "bfa86404a2e9ffe67d47c587ef7a97a7f456b863b4d02cfc6928973ab5b1cb39",
        "bob_Qy",
    )


# ============================================================================
# ECDH shared secret
#   shared = 90223373f75e989ab8965d8cc88f01ceb4c622875861771da7bf1a0faccae374
# ============================================================================

fn test_ecdh_shared_secret() raises:
    var d_alice = hex_to_bytes(
        "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721"
    )
    var d_bob = hex_to_bytes(
        "0f56db78ca460b055c500064824bed999a25aaf48ebb519ac201537b85479813"
    )
    # Derive public keys
    var pub_alice = p256_public_key(d_alice)
    var pub_bob   = p256_public_key(d_bob)
    # Alice computes shared secret using her private key + Bob's public key
    var shared_alice = p256_ecdh(d_alice, pub_bob)
    # Bob computes shared secret using his private key + Alice's public key
    var shared_bob   = p256_ecdh(d_bob, pub_alice)
    var expected = "90223373f75e989ab8965d8cc88f01ceb4c622875861771da7bf1a0faccae374"
    assert_hex_eq(shared_alice, expected, "ecdh_alice")
    assert_hex_eq(shared_bob,   expected, "ecdh_bob")


# ============================================================================
# ECDSA signature verification
#   msg = "sample", SHA-256 hash = af2bdbe1aa9b6ec1e2ade1d694f41fc71a831d0268e9891562113d8a62add1bf
#   Signature generated with Alice's private key (deterministic k from RFC 6979)
#   r = b9ac954c7a7bcb0f2bd7f6b07cab9cde997be9b9d8e2cf0ea61b132827bccbbf
#   s = f329be41981bd8ff57968566f3f399c9a397fc409b3e4890f655b5d226a04790
# ============================================================================

fn test_ecdsa_verify() raises:
    var pub = hex_to_bytes(
        "04"
        "60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6"
        "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299"
    )
    var hash = hex_to_bytes(
        "af2bdbe1aa9b6ec1e2ade1d694f41fc71a831d0268e9891562113d8a62add1bf"
    )
    var r = hex_to_bytes(
        "b9ac954c7a7bcb0f2bd7f6b07cab9cde997be9b9d8e2cf0ea61b132827bccbbf"
    )
    var s = hex_to_bytes(
        "f329be41981bd8ff57968566f3f399c9a397fc409b3e4890f655b5d226a04790"
    )
    p256_ecdsa_verify(pub, hash, r, s)  # raises on failure


fn test_ecdsa_reject_bad_sig() raises:
    var pub = hex_to_bytes(
        "04"
        "60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6"
        "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299"
    )
    var hash = hex_to_bytes(
        "af2bdbe1aa9b6ec1e2ade1d694f41fc71a831d0268e9891562113d8a62add1bf"
    )
    var r = hex_to_bytes(
        "b9ac954c7a7bcb0f2bd7f6b07cab9cde997be9b9d8e2cf0ea61b132827bccbbf"
    )
    # Tamper s by flipping a bit
    var s = hex_to_bytes(
        "f329be41981bd8ff57968566f3f399c9a397fc409b3e4890f655b5d226a04791"
    )
    var raised = False
    try:
        p256_ecdsa_verify(pub, hash, r, s)
    except:
        raised = True
    if not raised:
        raise Error("ecdsa_reject: tampered signature was not rejected")


fn main() raises:
    var passed = 0
    var failed = 0
    print("=== P-256 Tests ===")
    print()
    run_test("scalar=1 → generator",         passed, failed, test_generator_identity)
    run_test("Alice public key derivation",   passed, failed, test_public_key_alice)
    run_test("Bob public key derivation",     passed, failed, test_public_key_bob)
    run_test("ECDH shared secret",            passed, failed, test_ecdh_shared_secret)
    run_test("ECDSA verify valid signature",  passed, failed, test_ecdsa_verify)
    run_test("ECDSA reject tampered sig",     passed, failed, test_ecdsa_reject_bad_sig)
    print()
    print("Results:", passed, "passed,", failed, "failed")
    if failed > 0:
        raise Error(String(failed) + " test(s) failed")
