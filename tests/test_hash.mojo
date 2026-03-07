# ============================================================================
# test_hash.mojo — SHA-256 / SHA-384 known-answer tests
# ============================================================================

from crypto.hash import sha256, sha384, SHA256, SHA384


# ============================================================================
# Helpers
# ============================================================================


fn _hex_nibble(b: UInt8) raises -> UInt8:
    if b >= 48 and b <= 57:   # '0'..'9'
        return b - 48
    if b >= 97 and b <= 102:  # 'a'..'f'
        return b - 87
    raise Error("hex_to_bytes: bad char")


fn bytes_to_hex(b: List[UInt8]) -> String:
    """Encode bytes to lowercase hex string."""
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
# SHA-256 Tests
# ============================================================================


fn test_sha256_empty() raises:
    var result = sha256(List[UInt8]())
    assert_hex_eq(
        result,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "sha256_empty",
    )


fn test_sha256_abc() raises:
    var data = str_to_bytes("abc")
    var result = sha256(data)
    assert_hex_eq(
        result,
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        "sha256_abc",
    )


fn test_sha256_448bit() raises:
    # 56-byte message — fits in one block with padding
    var data = str_to_bytes(
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
    )
    var result = sha256(data)
    assert_hex_eq(
        result,
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
        "sha256_448bit",
    )


fn test_sha256_896bit() raises:
    # 112-byte message — requires two blocks
    var data = str_to_bytes(
        "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
    )
    var result = sha256(data)
    assert_hex_eq(
        result,
        "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1",
        "sha256_896bit",
    )


fn test_sha256_one_million_a() raises:
    var data = List[UInt8](capacity=1_000_000)
    for _ in range(1_000_000):
        data.append(UInt8(97))  # ord('a')
    var result = sha256(data)
    assert_hex_eq(
        result,
        "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0",
        "sha256_1m_a",
    )


fn test_sha256_streaming() raises:
    # Feed 1 byte at a time — same as sha256_abc
    var h = SHA256()
    var data = str_to_bytes("abc")
    for i in range(len(data)):
        var chunk = List[UInt8](capacity=1)
        chunk.append(data[i])
        h.update(chunk)
    var result = h.finalize()
    assert_hex_eq(
        result,
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        "sha256_streaming",
    )


fn test_sha256_two_block() raises:
    # 64 bytes = exactly one full block; padding goes into second block
    var data = List[UInt8](capacity=64)
    for i in range(64):
        data.append(UInt8(i))
    var result = sha256(data)
    assert_hex_eq(
        result,
        "fdeab9acf3710362bd2658cdc9a29e8f9c757fcf9811603a8c447cd1d9151108",
        "sha256_two_block",
    )


# ============================================================================
# SHA-384 Tests
# ============================================================================


fn test_sha384_empty() raises:
    var result = sha384(List[UInt8]())
    assert_hex_eq(
        result,
        "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b",
        "sha384_empty",
    )


fn test_sha384_abc() raises:
    var data = str_to_bytes("abc")
    var result = sha384(data)
    assert_hex_eq(
        result,
        "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
        "sha384_abc",
    )


fn test_sha384_448bit() raises:
    var data = str_to_bytes(
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
    )
    var result = sha384(data)
    assert_hex_eq(
        result,
        "3391fdddfc8dc7393707a65b1b4709397cf8b1d162af05abfe8f450de5f36bc6b0455a8520bc4e6f5fe95b1fe3c8452b",
        "sha384_448bit",
    )


fn test_sha384_896bit() raises:
    var data = str_to_bytes(
        "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
    )
    var result = sha384(data)
    assert_hex_eq(
        result,
        "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039",
        "sha384_896bit",
    )


fn test_sha384_one_million_a() raises:
    var data = List[UInt8](capacity=1_000_000)
    for _ in range(1_000_000):
        data.append(UInt8(97))  # ord('a')
    var result = sha384(data)
    assert_hex_eq(
        result,
        "9d0e1809716474cb086e834e310a4a1ced149e9c00f248527972cec5704c2a5b07b8b3dc38ecc4ebae97ddd87f3d8985",
        "sha384_1m_a",
    )


fn test_sha384_streaming() raises:
    var h = SHA384()
    var data = str_to_bytes("abc")
    for i in range(len(data)):
        var chunk = List[UInt8](capacity=1)
        chunk.append(data[i])
        h.update(chunk)
    var result = h.finalize()
    assert_hex_eq(
        result,
        "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
        "sha384_streaming",
    )


# ============================================================================
# Main
# ============================================================================


fn main() raises:
    var passed = 0
    var failed = 0

    print("=== SHA-256 / SHA-384 Tests ===")
    print()

    run_test("SHA-256 empty string", passed, failed, test_sha256_empty)
    run_test("SHA-256 'abc'", passed, failed, test_sha256_abc)
    run_test("SHA-256 448-bit message", passed, failed, test_sha256_448bit)
    run_test("SHA-256 896-bit message", passed, failed, test_sha256_896bit)
    run_test("SHA-256 1,000,000 x 'a'", passed, failed, test_sha256_one_million_a)
    run_test("SHA-256 streaming (1-byte)", passed, failed, test_sha256_streaming)
    run_test("SHA-256 64-byte block boundary", passed, failed, test_sha256_two_block)

    run_test("SHA-384 empty string", passed, failed, test_sha384_empty)
    run_test("SHA-384 'abc'", passed, failed, test_sha384_abc)
    run_test("SHA-384 448-bit message", passed, failed, test_sha384_448bit)
    run_test("SHA-384 896-bit message", passed, failed, test_sha384_896bit)
    run_test("SHA-384 1,000,000 x 'a'", passed, failed, test_sha384_one_million_a)
    run_test("SHA-384 streaming (1-byte)", passed, failed, test_sha384_streaming)

    print()
    print("Results:", passed, "passed,", failed, "failed")
    if failed > 0:
        raise Error(String(failed) + " test(s) failed")
