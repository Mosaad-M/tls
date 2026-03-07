# ============================================================================
# test_record12.mojo — TLS 1.2 AEAD record layer tests
# ============================================================================
# Test vectors generated with Python (cryptography library):
#
#   from cryptography.hazmat.primitives.ciphers.aead import AESGCM
#   import struct
#   def seal_tls12(key, iv_implicit, seqno, content_type, plaintext):
#       explicit_nonce = struct.pack('>Q', seqno)
#       nonce = iv_implicit + explicit_nonce
#       aad = struct.pack('>Q', seqno) + bytes([content_type, 3, 3]) + struct.pack('>H', len(plaintext))
#       ct_with_tag = AESGCM(key).encrypt(nonce, plaintext, aad)
#       return explicit_nonce + ct_with_tag
#
# Vectors:
#   AES-128, key=0x01*16, iv4=0x02*4, pt=b"Hello, TLS 1.2!"
#   seqno=0: 000000000000000099d33fcefb9d20b568a06504a4856ff35012e743ff2893885b370e52c07bb2
#   seqno=1: 00000000000000017f4342529c40d9840aef1af50f12c7f4e83fb96261362bdaf5f1692ac8f3c5
#   AES-256, key=0x03*32, seqno=0: 0000000000000000840de22c8a19b43a617cee886322382a3c54c4981cd0f4b1e8cfcc12bd6132
# ============================================================================

from crypto.record import (
    record_seal_12, record_open_12,
    CIPHER_AES_128_GCM, CIPHER_AES_256_GCM,
)


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


fn make_bytes(value: UInt8, count: Int) -> List[UInt8]:
    var out = List[UInt8](capacity=count)
    for i in range(count):
        out.append(value)
    return out^


fn bytes_equal(a: List[UInt8], b: List[UInt8]) -> Bool:
    if len(a) != len(b):
        return False
    for i in range(len(a)):
        if a[i] != b[i]:
            return False
    return True


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


# ── Tests ──────────────────────────────────────────────────────────────────

fn test_seal_12_aes128_seqno0() raises:
    """record_seal_12 AES-128-GCM, seqno=0 matches Python vector."""
    var key  = make_bytes(0x01, 16)
    var iv4  = make_bytes(0x02, 4)
    var pt_str = String("Hello, TLS 1.2!")
    var pt_raw = pt_str.as_bytes()
    var pt = List[UInt8](capacity=len(pt_raw))
    for i in range(len(pt_raw)):
        pt.append(pt_raw[i])
    var expected = hex_to_bytes(
        "000000000000000099d33fcefb9d20b568a06504a4856ff35012e743ff2893885b370e52c07bb2"
    )
    var got = record_seal_12(CIPHER_AES_128_GCM, key, iv4, UInt64(0), 0x17, pt)
    if not bytes_equal(got, expected):
        raise Error("AES-128 seqno=0 mismatch")


fn test_seal_12_aes128_seqno1() raises:
    """record_seal_12 AES-128-GCM, seqno=1: explicit nonce differs."""
    var key  = make_bytes(0x01, 16)
    var iv4  = make_bytes(0x02, 4)
    var pt_str = String("Hello, TLS 1.2!")
    var pt_raw = pt_str.as_bytes()
    var pt = List[UInt8](capacity=len(pt_raw))
    for i in range(len(pt_raw)):
        pt.append(pt_raw[i])
    var expected = hex_to_bytes(
        "00000000000000017f4342529c40d9840aef1af50f12c7f4e83fb96261362bdaf5f1692ac8f3c5"
    )
    var got = record_seal_12(CIPHER_AES_128_GCM, key, iv4, UInt64(1), 0x17, pt)
    if not bytes_equal(got, expected):
        raise Error("AES-128 seqno=1 mismatch")


fn test_seal_12_aes256_seqno0() raises:
    """record_seal_12 AES-256-GCM, seqno=0 matches Python vector."""
    var key  = make_bytes(0x03, 32)
    var iv4  = make_bytes(0x02, 4)
    var pt_str = String("Hello, TLS 1.2!")
    var pt_raw = pt_str.as_bytes()
    var pt = List[UInt8](capacity=len(pt_raw))
    for i in range(len(pt_raw)):
        pt.append(pt_raw[i])
    var expected = hex_to_bytes(
        "0000000000000000840de22c8a19b43a617cee886322382a3c54c4981cd0f4b1e8cfcc12bd6132"
    )
    var got = record_seal_12(CIPHER_AES_256_GCM, key, iv4, UInt64(0), 0x17, pt)
    if not bytes_equal(got, expected):
        raise Error("AES-256 seqno=0 mismatch")


fn test_open_12_roundtrip() raises:
    """record_open_12 roundtrip: seal then open → original plaintext."""
    var key  = make_bytes(0x01, 16)
    var iv4  = make_bytes(0x02, 4)
    var pt   = make_bytes(0xAB, 64)
    var sealed = record_seal_12(CIPHER_AES_128_GCM, key, iv4, UInt64(42), 0x17, pt)
    var opened = record_open_12(CIPHER_AES_128_GCM, key, iv4, UInt64(42), 0x17, sealed)
    if not bytes_equal(opened, pt):
        raise Error("roundtrip plaintext mismatch")


fn test_open_12_tampered_tag_raises() raises:
    """record_open_12: tampered tag raises authentication error."""
    var key  = make_bytes(0x01, 16)
    var iv4  = make_bytes(0x02, 4)
    var pt   = make_bytes(0xAB, 32)
    var sealed = record_seal_12(CIPHER_AES_128_GCM, key, iv4, UInt64(0), 0x17, pt)
    # Flip last byte of tag
    sealed[len(sealed) - 1] ^= 0xFF
    var raised = False
    try:
        _ = record_open_12(CIPHER_AES_128_GCM, key, iv4, UInt64(0), 0x17, sealed)
    except:
        raised = True
    if not raised:
        raise Error("expected raise for tampered tag")


fn test_open_12_wrong_seqno_raises() raises:
    """record_open_12: decrypting with wrong seqno raises (AAD mismatch)."""
    var key  = make_bytes(0x01, 16)
    var iv4  = make_bytes(0x02, 4)
    var pt   = make_bytes(0xAB, 32)
    var sealed = record_seal_12(CIPHER_AES_128_GCM, key, iv4, UInt64(0), 0x17, pt)
    # Try to open with seqno=1 (wrong AAD)
    var raised = False
    try:
        _ = record_open_12(CIPHER_AES_128_GCM, key, iv4, UInt64(1), 0x17, sealed)
    except:
        raised = True
    if not raised:
        raise Error("expected raise for wrong seqno")


fn main() raises:
    var passed = 0
    var failed = 0

    print("=== TLS 1.2 Record Layer Tests ===")
    print()

    run_test("record_seal_12 AES-128 seqno=0", passed, failed, test_seal_12_aes128_seqno0)
    run_test("record_seal_12 AES-128 seqno=1", passed, failed, test_seal_12_aes128_seqno1)
    run_test("record_seal_12 AES-256 seqno=0", passed, failed, test_seal_12_aes256_seqno0)
    run_test("record_open_12 roundtrip", passed, failed, test_open_12_roundtrip)
    run_test("record_open_12 tampered tag raises", passed, failed, test_open_12_tampered_tag_raises)
    run_test("record_open_12 wrong seqno raises", passed, failed, test_open_12_wrong_seqno_raises)

    print()
    print("Results:", passed, "passed,", failed, "failed")
    if failed > 0:
        raise Error(String(failed) + " test(s) failed")
