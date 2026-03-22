# ============================================================================
# test_record.mojo — TLS 1.3 record layer tests
# ============================================================================
# Test vectors generated with Python cryptography library.
# ============================================================================

from crypto.record import (
    record_seal, record_open,
    CIPHER_AES_128_GCM, CIPHER_AES_256_GCM, CIPHER_CHACHA20_POLY1305,
    CTYPE_HANDSHAKE, CTYPE_APPLICATION_DATA,
)


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
# Test: AES-128-GCM seal produces known ciphertext
# key = 00112233445566778899aabbccddeeff
# iv  = aabbccddeeff001122334455
# pt  = "Hello, TLS 1.3!"  (content_type = 0x16 handshake)
# seq = 0 → record = 1703030020b25b...
# ============================================================================

def test_aes128_known_vector() raises:
    var key = hex_to_bytes("00112233445566778899aabbccddeeff")
    var iv  = hex_to_bytes("aabbccddeeff001122334455")
    var pt  = hex_to_bytes("48656c6c6f2c20544c5320312e3321")  # "Hello, TLS 1.3!"

    var record = record_seal(CIPHER_AES_128_GCM, key, iv, 0, CTYPE_HANDSHAKE, pt)
    assert_hex_eq(
        record,
        "1703030020b25bfe5a44dc36d41ba1f6fcb32275396f00dfc55106d82c8c755ffb0116c875",
        "aes128_seal",
    )


# ============================================================================
# Test: AES-128-GCM round-trip (seal then open)
# ============================================================================

def test_aes128_round_trip() raises:
    var key = hex_to_bytes("00112233445566778899aabbccddeeff")
    var iv  = hex_to_bytes("aabbccddeeff001122334455")
    var pt  = hex_to_bytes("48656c6c6f2c20544c5320312e3321")

    var record = record_seal(CIPHER_AES_128_GCM, key, iv, 0, CTYPE_HANDSHAKE, pt)
    var res = record_open(CIPHER_AES_128_GCM, key, iv, 0, record)
    var got_ctype = res[0]
    var got_pt    = res[1].copy()

    if got_ctype != CTYPE_HANDSHAKE:
        raise Error("aes128_round_trip: wrong content type: " + String(Int(got_ctype)))
    assert_hex_eq(got_pt, "48656c6c6f2c20544c5320312e3321", "aes128_pt")


# ============================================================================
# Test: seqno 0 and seqno 1 produce different ciphertexts (nonce changes)
# Verify using the known vectors for seq=0 and seq=1.
# ============================================================================

def test_aes128_seqno() raises:
    var key = hex_to_bytes("00112233445566778899aabbccddeeff")
    var iv  = hex_to_bytes("aabbccddeeff001122334455")
    var pt  = hex_to_bytes("48656c6c6f2c20544c5320312e3321")

    var r0 = record_seal(CIPHER_AES_128_GCM, key, iv, 0, CTYPE_HANDSHAKE, pt)
    var r1 = record_seal(CIPHER_AES_128_GCM, key, iv, 1, CTYPE_HANDSHAKE, pt)

    # seq=0 known
    assert_hex_eq(r0, "1703030020b25bfe5a44dc36d41ba1f6fcb32275396f00dfc55106d82c8c755ffb0116c875", "seq0")
    # seq=1 known
    assert_hex_eq(r1, "17030300206e8fbc257f89beb6350c072fd2ea49243418ddbfd958b6d020a90ef791625760", "seq1")

    # Open seq=1 record
    var res1 = record_open(CIPHER_AES_128_GCM, key, iv, 1, r1)
    if res1[0] != CTYPE_HANDSHAKE:
        raise Error("aes128_seqno: wrong content type for seq=1")


# ============================================================================
# Test: AES-256-GCM round-trip
# key = 000102...1f  (32 bytes), iv = a0a1...ab
# pt  = "AES-256-GCM test"  content_type = 0x17
# ============================================================================

def test_aes256_round_trip() raises:
    var key = hex_to_bytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
    var iv  = hex_to_bytes("a0a1a2a3a4a5a6a7a8a9aaab")
    var pt  = hex_to_bytes("4145532d3235362d47434d2074657374")  # "AES-256-GCM test"

    var record = record_seal(CIPHER_AES_256_GCM, key, iv, 0, CTYPE_APPLICATION_DATA, pt)
    # Verify against known vector
    assert_hex_eq(
        record,
        "1703030021a75d2f0077fe34922526caf3731fb3aa676d9acba29405bdf5ad09183f89f718bf",
        "aes256_seal",
    )

    var res = record_open(CIPHER_AES_256_GCM, key, iv, 0, record)
    if res[0] != CTYPE_APPLICATION_DATA:
        raise Error("aes256_round_trip: wrong content type")
    assert_hex_eq(res[1].copy(), "4145532d3235362d47434d2074657374", "aes256_pt")


# ============================================================================
# Test: ChaCha20-Poly1305 round-trip
# ============================================================================

def test_chacha20_round_trip() raises:
    var key = hex_to_bytes("404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f")
    var iv  = hex_to_bytes("b0b1b2b3b4b5b6b7b8b9babb")
    var pt  = hex_to_bytes("43686143686132302d506f6c793133303521")  # "ChaCha20-Poly1305!"

    var record = record_seal(CIPHER_CHACHA20_POLY1305, key, iv, 0, CTYPE_APPLICATION_DATA, pt)
    # Verify against known vector
    assert_hex_eq(
        record,
        "170303002312b860a5c428596ca47e5e151d3f80862147560f1c1a227e8a107e8f1cfccd72712969",
        "chacha_seal",
    )

    var res = record_open(CIPHER_CHACHA20_POLY1305, key, iv, 0, record)
    if res[0] != CTYPE_APPLICATION_DATA:
        raise Error("chacha_round_trip: wrong content type")
    assert_hex_eq(res[1].copy(), "43686143686132302d506f6c793133303521", "chacha_pt")


# ============================================================================
# Test: tampered record fails authentication
# ============================================================================

def test_reject_tampered() raises:
    var key = hex_to_bytes("00112233445566778899aabbccddeeff")
    var iv  = hex_to_bytes("aabbccddeeff001122334455")
    var pt  = hex_to_bytes("48656c6c6f2c20544c5320312e3321")

    var record = record_seal(CIPHER_AES_128_GCM, key, iv, 0, CTYPE_HANDSHAKE, pt)
    # Flip a byte in the ciphertext
    record[10] ^= 0x01
    var raised = False
    try:
        _ = record_open(CIPHER_AES_128_GCM, key, iv, 0, record)
    except:
        raised = True
    if not raised:
        raise Error("reject_tampered: tampered record should not decrypt")


# ============================================================================
# Test: wrong seqno fails authentication (different nonce → bad tag)
# ============================================================================

def test_reject_wrong_seqno() raises:
    var key = hex_to_bytes("00112233445566778899aabbccddeeff")
    var iv  = hex_to_bytes("aabbccddeeff001122334455")
    var pt  = hex_to_bytes("48656c6c6f2c20544c5320312e3321")

    var record = record_seal(CIPHER_AES_128_GCM, key, iv, 0, CTYPE_HANDSHAKE, pt)
    # Try to open with wrong sequence number → different nonce → auth failure
    var raised = False
    try:
        _ = record_open(CIPHER_AES_128_GCM, key, iv, 999, record)
    except:
        raised = True
    if not raised:
        raise Error("reject_wrong_seqno: wrong seqno should fail")


def main() raises:
    var passed = 0
    var failed = 0
    print("=== TLS 1.3 Record Layer Tests ===")
    print()
    run_test("AES-128-GCM known vector",       passed, failed, test_aes128_known_vector)
    run_test("AES-128-GCM round-trip",         passed, failed, test_aes128_round_trip)
    run_test("AES-128-GCM seqno changes nonce", passed, failed, test_aes128_seqno)
    run_test("AES-256-GCM round-trip",         passed, failed, test_aes256_round_trip)
    run_test("ChaCha20-Poly1305 round-trip",   passed, failed, test_chacha20_round_trip)
    run_test("reject tampered record",         passed, failed, test_reject_tampered)
    run_test("reject wrong seqno",             passed, failed, test_reject_wrong_seqno)
    print()
    print("Results:", passed, "passed,", failed, "failed")
    if failed > 0:
        raise Error(String(failed) + " test(s) failed")
