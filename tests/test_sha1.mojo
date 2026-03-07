# ============================================================================
# tests/test_sha1.mojo — SHA-1 (FIPS 180-4) test vectors
# ============================================================================
#
# Vectors generated/verified with Python:
#   import hashlib, base64
#   hashlib.sha1(b"").hexdigest()
#   hashlib.sha1(b"abc").hexdigest()
#   ...
#
# WebSocket accept-key vector (RFC 6455 §1.3 example):
#   key = "dGhlIHNhbXBsZSBub25jZQ=="
#   magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
#   sha1(key + magic) base64 = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
# ============================================================================

from crypto.sha1 import sha1, SHA1
from crypto.base64 import base64_encode


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


fn hex_to_bytes(h: String) -> List[UInt8]:
    var raw = h.as_bytes()
    var n = len(raw) // 2
    var out = List[UInt8](capacity=n)
    for i in range(n):
        var hi = raw[i * 2]
        var lo = raw[i * 2 + 1]
        var h_val: UInt8 = (hi - 48) if hi <= 57 else (hi - 87)
        var l_val: UInt8 = (lo - 48) if lo <= 57 else (lo - 87)
        out.append((h_val << 4) | l_val)
    return out^


fn bytes_to_hex(b: List[UInt8]) -> String:
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


# ── Test 1: sha1(b"") — empty message ──────────────────────────────────────
# Python: hashlib.sha1(b"").hexdigest() = "da39a3ee5e6b4b0d3255bfef95601890afd80709"

fn test_sha1_empty() raises:
    var data = List[UInt8]()
    var digest = sha1(data)
    var got = bytes_to_hex(digest)
    var want = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
    if got != want:
        raise Error("sha1('') = " + got + ", want " + want)


# ── Test 2: sha1(b"abc") — 3-byte message ──────────────────────────────────
# Python: hashlib.sha1(b"abc").hexdigest() = "a9993e364706816aba3e25717850c26c9cd0d89d"

fn test_sha1_abc() raises:
    var data = str_to_bytes("abc")
    var digest = sha1(data)
    var got = bytes_to_hex(digest)
    var want = "a9993e364706816aba3e25717850c26c9cd0d89d"
    if got != want:
        raise Error("sha1('abc') = " + got + ", want " + want)


# ── Test 3: sha1 — 448-bit (56-byte) boundary message ──────────────────────
# Message fills padding to exactly 56 bytes (no second block needed for length).
# Python: hashlib.sha1(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq").hexdigest()
#       = "84983e441c3bd26ebaae4aa1f95129e5e54670f1"

fn test_sha1_448bit() raises:
    var data = str_to_bytes("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
    var digest = sha1(data)
    var got = bytes_to_hex(digest)
    var want = "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
    if got != want:
        raise Error("sha1(448-bit msg) = " + got + ", want " + want)


# ── Test 4: sha1 — multi-block message (>512 bits) ─────────────────────────
# Python: hashlib.sha1(b"a" * 100).hexdigest() = "7f9000257a4918d7072655ea468540cdcbd42e0c"

fn test_sha1_multiblock() raises:
    var data = List[UInt8](capacity=100)
    for _ in range(100):
        data.append(UInt8(ord("a")))
    var digest = sha1(data)
    var got = bytes_to_hex(digest)
    var want = "7f9000257a4918d7072655ea468540cdcbd42e0c"
    if got != want:
        raise Error("sha1('a'*100) = " + got + ", want " + want)


# ── Test 5: WebSocket accept-key derivation (RFC 6455 §1.3) ────────────────
# key   = "dGhlIHNhbXBsZSBub25jZQ=="
# magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
# Python:
#   import hashlib, base64
#   concat = "dGhlIHNhbXBsZSBub25jZQ==" + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
#   base64.b64encode(hashlib.sha1(concat.encode()).digest()).decode()
#   = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="

fn test_sha1_websocket_accept() raises:
    var concat = str_to_bytes(
        "dGhlIHNhbXBsZSBub25jZQ==258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
    )
    var hash = sha1(concat)
    var accept = base64_encode(hash)
    var want = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
    if accept != want:
        raise Error("ws accept key = '" + accept + "', want '" + want + "'")


fn main() raises:
    var passed = 0
    var failed = 0

    print("=== SHA-1 Tests ===")
    print()

    run_test("sha1('') = da39...", passed, failed, test_sha1_empty)
    run_test("sha1('abc') = a999...", passed, failed, test_sha1_abc)
    run_test("sha1(448-bit msg) = 8498...", passed, failed, test_sha1_448bit)
    run_test("sha1('a'*100) multi-block", passed, failed, test_sha1_multiblock)
    run_test("sha1 WebSocket accept-key (RFC 6455 §1.3)", passed, failed, test_sha1_websocket_accept)

    print()
    print("Results:", passed, "passed,", failed, "failed")
    if failed > 0:
        raise Error(String(failed) + " test(s) failed")
