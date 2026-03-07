# ============================================================================
# test_base64.mojo — RFC 4648 Base64 known-answer tests
# ============================================================================

from crypto.base64 import base64_encode, base64_decode


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


fn str_to_bytes(s: String) -> List[UInt8]:
    var raw = s.as_bytes()
    var out = List[UInt8](capacity=len(raw))
    for i in range(len(raw)):
        out.append(raw[i])
    return out^


fn bytes_eq(a: List[UInt8], b: List[UInt8]) -> Bool:
    if len(a) != len(b):
        return False
    for i in range(len(a)):
        if a[i] != b[i]:
            return False
    return True


# ── RFC 4648 §10 encode tests ──────────────────────────────────────────────

fn test_encode_empty() raises:
    var r = base64_encode(List[UInt8]())
    if r != "":
        raise Error("expected '', got '" + r + "'")


fn test_encode_f() raises:
    var r = base64_encode(str_to_bytes("f"))
    if r != "Zg==":
        raise Error("expected 'Zg==', got '" + r + "'")


fn test_encode_fo() raises:
    var r = base64_encode(str_to_bytes("fo"))
    if r != "Zm8=":
        raise Error("expected 'Zm8=', got '" + r + "'")


fn test_encode_foo() raises:
    var r = base64_encode(str_to_bytes("foo"))
    if r != "Zm9v":
        raise Error("expected 'Zm9v', got '" + r + "'")


fn test_encode_foobar() raises:
    var r = base64_encode(str_to_bytes("foobar"))
    if r != "Zm9vYmFy":
        raise Error("expected 'Zm9vYmFy', got '" + r + "'")


fn test_encode_32_binary() raises:
    # bytes.fromhex("00112233445566778899aabbccddeeff" * 2)
    var data = List[UInt8](capacity=32)
    var src = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
    var src_bytes = src.as_bytes()
    for i in range(32):
        var hi = src_bytes[i * 2]
        var lo = src_bytes[i * 2 + 1]
        var h: UInt8 = (hi - 48) if hi <= 57 else (hi - 87)
        var l: UInt8 = (lo - 48) if lo <= 57 else (lo - 87)
        data.append((h << 4) | l)
    var r = base64_encode(data)
    var expected = "ABEiM0RVZneImaq7zN3u/wARIjNEVWZ3iJmqu8zd7v8="
    if r != expected:
        raise Error("expected '" + expected + "', got '" + r + "'")


# ── Decode round-trip tests ────────────────────────────────────────────────

fn test_decode_f() raises:
    var r = base64_decode("Zg==")
    var expected = str_to_bytes("f")
    if not bytes_eq(r, expected):
        raise Error("decode 'Zg==' failed")


fn test_decode_fo() raises:
    var r = base64_decode("Zm8=")
    var expected = str_to_bytes("fo")
    if not bytes_eq(r, expected):
        raise Error("decode 'Zm8=' failed")


fn test_decode_foo() raises:
    var r = base64_decode("Zm9v")
    var expected = str_to_bytes("foo")
    if not bytes_eq(r, expected):
        raise Error("decode 'Zm9v' failed")


fn test_decode_bad_char() raises:
    var raised = False
    try:
        _ = base64_decode("Z!==")
    except:
        raised = True
    if not raised:
        raise Error("expected raise on bad char '!'")


fn main() raises:
    var passed = 0
    var failed = 0

    print("=== Base64 Tests ===")
    print()

    run_test("encode ''", passed, failed, test_encode_empty)
    run_test("encode 'f'", passed, failed, test_encode_f)
    run_test("encode 'fo'", passed, failed, test_encode_fo)
    run_test("encode 'foo'", passed, failed, test_encode_foo)
    run_test("encode 'foobar'", passed, failed, test_encode_foobar)
    run_test("encode 32 binary bytes", passed, failed, test_encode_32_binary)
    run_test("decode 'Zg=='", passed, failed, test_decode_f)
    run_test("decode 'Zm8='", passed, failed, test_decode_fo)
    run_test("decode 'Zm9v'", passed, failed, test_decode_foo)
    run_test("decode bad char raises", passed, failed, test_decode_bad_char)

    print()
    print("Results:", passed, "passed,", failed, "failed")
    if failed > 0:
        raise Error(String(failed) + " test(s) failed")
