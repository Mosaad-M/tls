# ============================================================================
# test_handshake.mojo — TLS 1.3 key schedule and handshake primitive tests
# ============================================================================
# Test vectors computed with Python (hashlib/hmac), matching RFC 8446 §7.1.
# ============================================================================

from crypto.handshake import (
    tls13_early_secret, tls13_handshake_secret, tls13_master_secret,
    tls13_derive_secret, tls13_traffic_keys,
    tls13_finished_key, tls13_compute_finished, tls13_verify_finished,
    tls13_early_secret_sha384, tls13_handshake_secret_sha384,
    tls13_derive_secret_sha384, tls13_finished_key_sha384,
    tls13_compute_finished_sha384, tls13_verify_finished_sha384,
    tls13_cert_verify_input,
    CERT_VERIFY_SERVER_CTX,
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
# Test: Early Secret = HKDF-Extract(0^32, 0^32)
# Expected: 33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a
# ============================================================================

def test_early_secret() raises:
    var es = tls13_early_secret()
    assert_hex_eq(
        es,
        "33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a",
        "early_secret",
    )


# ============================================================================
# Test: HKDF-Expand-Label with "derived" label and SHA256("") context
# secret  = 0^32
# label   = "derived"
# context = SHA256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
# Expected: 70735bf7c7bab21c1f802d8eab67e6fac3c48974f1c9caf8c99962acd585bbd8
# ============================================================================

def test_expand_label_derived() raises:
    from crypto.hkdf import hkdf_expand_label
    from crypto.hash import sha256
    var secret = List[UInt8](capacity=32)
    for _ in range(32):
        secret.append(0)
    var empty = List[UInt8]()
    var h_empty = sha256(empty)
    var result = hkdf_expand_label(secret, "derived", h_empty, 32)
    assert_hex_eq(
        result,
        "70735bf7c7bab21c1f802d8eab67e6fac3c48974f1c9caf8c99962acd585bbd8",
        "expand_label_derived",
    )


# ============================================================================
# Test: derive_secret(0^32, "c hs traffic", SHA256("test message transcript"))
# SHA256("test message transcript") = cfc3cf260e995dd398c33824084b0feacaf293d729cff2ff643d1251b10a81c6
# Expected: 59bdc36ca7a0b92470b1d838b920e314f6de79f9d7dc836899e667c01a2a1a9a
# ============================================================================

def test_derive_secret() raises:
    from crypto.hash import sha256
    var secret = List[UInt8](capacity=32)
    for _ in range(32):
        secret.append(0)
    var transcript_bytes = String("test message transcript").as_bytes()
    var msg = List[UInt8](capacity=len(transcript_bytes))
    for i in range(len(transcript_bytes)):
        msg.append(transcript_bytes[i])
    var h = sha256(msg)
    var result = tls13_derive_secret(secret, "c hs traffic", h)
    assert_hex_eq(
        result,
        "59bdc36ca7a0b92470b1d838b920e314f6de79f9d7dc836899e667c01a2a1a9a",
        "derive_secret",
    )


# ============================================================================
# Test: traffic key and IV derivation
# traffic_secret = b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21
# key (16 bytes) = dbfaa693d1762c5b666af5d950258d01
# iv  (12 bytes) = 5bd3c71b836e0b76bb73265f
# ============================================================================

def test_traffic_keys() raises:
    var ts = hex_to_bytes("b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21")
    var res = tls13_traffic_keys(ts, 16, 12)
    var key = res[0].copy()
    var iv  = res[1].copy()
    assert_hex_eq(key, "dbfaa693d1762c5b666af5d950258d01", "traffic_key")
    assert_hex_eq(iv,  "5bd3c71b836e0b76bb73265f",         "traffic_iv")


# ============================================================================
# Test: Finished key derivation
# traffic_secret = b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21
# finished_key   = b80ad01015fb2f0bd65ff7d4da5d6bf83f84821d1f87fdc7d3c75b5a7b42d9c4
# ============================================================================

def test_finished_key() raises:
    var ts = hex_to_bytes("b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21")
    var fk = tls13_finished_key(ts)
    assert_hex_eq(
        fk,
        "b80ad01015fb2f0bd65ff7d4da5d6bf83f84821d1f87fdc7d3c75b5a7b42d9c4",
        "finished_key",
    )


# ============================================================================
# Test: compute Finished verify_data
# finished_key    = b80ad01015fb2f0bd65ff7d4da5d6bf83f84821d1f87fdc7d3c75b5a7b42d9c4
# transcript_hash = SHA256("handshake messages transcript")
#                 = c4a8cabd160340f436c4f95972737b4342f51dd9fb27a3df639c274f396200e3
# verify_data     = fa98033e572d3521bf44e8d9eb56631df6860d76e28d795e359901a0eacccc37
# ============================================================================

def test_compute_finished() raises:
    from crypto.hash import sha256
    var transcript_bytes = String("handshake messages transcript").as_bytes()
    var msg = List[UInt8](capacity=len(transcript_bytes))
    for i in range(len(transcript_bytes)):
        msg.append(transcript_bytes[i])
    var th = sha256(msg)

    var ts = hex_to_bytes("b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21")
    var fk = tls13_finished_key(ts)
    var vd = tls13_compute_finished(fk, th)
    assert_hex_eq(
        vd,
        "fa98033e572d3521bf44e8d9eb56631df6860d76e28d795e359901a0eacccc37",
        "compute_finished",
    )


# ============================================================================
# Test: verify_finished accepts valid verify_data
# ============================================================================

def test_verify_finished_valid() raises:
    from crypto.hash import sha256
    var transcript_bytes = String("handshake messages transcript").as_bytes()
    var msg = List[UInt8](capacity=len(transcript_bytes))
    for i in range(len(transcript_bytes)):
        msg.append(transcript_bytes[i])
    var th = sha256(msg)

    var ts = hex_to_bytes("b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21")
    var fk = tls13_finished_key(ts)
    var vd = hex_to_bytes("fa98033e572d3521bf44e8d9eb56631df6860d76e28d795e359901a0eacccc37")
    tls13_verify_finished(fk, th, vd)  # must not raise


# ============================================================================
# Test: verify_finished rejects wrong verify_data
# ============================================================================

def test_verify_finished_reject() raises:
    from crypto.hash import sha256
    var transcript_bytes = String("handshake messages transcript").as_bytes()
    var msg = List[UInt8](capacity=len(transcript_bytes))
    for i in range(len(transcript_bytes)):
        msg.append(transcript_bytes[i])
    var th = sha256(msg)

    var ts = hex_to_bytes("b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21")
    var fk = tls13_finished_key(ts)
    # Flip a byte in verify_data
    var vd = hex_to_bytes("fa98033e572d3521bf44e8d9eb56631df6860d76e28d795e359901a0eacccc37")
    vd[0] ^= 0x01
    var raised = False
    try:
        tls13_verify_finished(fk, th, vd)
    except:
        raised = True
    if not raised:
        raise Error("verify_finished_reject: wrong MAC not rejected")


# ============================================================================
# Test: CertificateVerify input construction
# The first 64 bytes must all be 0x20 (space), then context, then 0x00, then hash.
# ============================================================================

def test_cert_verify_input() raises:
    from crypto.hash import sha256
    var transcript_bytes = String("handshake messages transcript").as_bytes()
    var msg = List[UInt8](capacity=len(transcript_bytes))
    for i in range(len(transcript_bytes)):
        msg.append(transcript_bytes[i])
    var th = sha256(msg)

    var cv_input = tls13_cert_verify_input(CERT_VERIFY_SERVER_CTX, th)

    # First 64 bytes must be 0x20
    for i in range(64):
        if cv_input[i] != 0x20:
            raise Error("cert_verify_input: byte " + String(i) + " is not 0x20")

    # The separator 0x00 is right after the context string
    var ctx_bytes = CERT_VERIFY_SERVER_CTX.as_bytes()
    var sep_pos = 64 + len(ctx_bytes)
    if cv_input[sep_pos] != 0x00:
        raise Error("cert_verify_input: separator byte not 0x00")

    # Remaining 32 bytes are the transcript hash
    for i in range(32):
        if cv_input[sep_pos + 1 + i] != th[i]:
            raise Error("cert_verify_input: transcript hash mismatch at byte " + String(i))


# ============================================================================
# Test: full key schedule round-trip
# ES → HS → MS (using RFC 8448 DHE shared value)
# Expected ES = 33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a
# ============================================================================

def test_full_key_schedule() raises:
    # RFC 8448 §3 DHE shared secret (x25519)
    var dhe = hex_to_bytes("8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d")

    var es = tls13_early_secret()
    assert_hex_eq(
        es,
        "33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a",
        "early_secret",
    )

    var hs = tls13_handshake_secret(es, dhe)
    # Expected from Python: HS = HKDF-Extract(HKDF-Expand-Label(ES, "derived", H(""), 32), dhe)
    assert_hex_eq(
        hs,
        "1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac",
        "handshake_secret",
    )

    var ms = tls13_master_secret(hs)
    assert_hex_eq(
        ms,
        "18df06843d13a08bf2a449844c5f8a478001bc4d4c627984d5a41da8d0402919",
        "master_secret",
    )


# ============================================================================
# SHA-384 Key Schedule Tests
# ============================================================================

def test_early_secret_sha384() raises:
    # HKDF-Extract-SHA384(0^48, 0^48)
    var es = tls13_early_secret_sha384()
    if len(es) != 48:
        raise Error("early_secret_sha384: expected 48 bytes, got " + String(len(es)))
    assert_hex_eq(
        es,
        "7ee8206f5570023e6dc7519eb1073bc4e791ad37b5c382aa10ba18e2357e716971f9362f2c2fe2a76bfd78dfec4ea9b5",
        "early_secret_sha384",
    )


def test_handshake_secret_sha384() raises:
    # Use RFC 8448 DHE shared secret with SHA-384 key schedule
    var dhe = hex_to_bytes("8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d")
    var es  = tls13_early_secret_sha384()
    var hs  = tls13_handshake_secret_sha384(es, dhe)
    if len(hs) != 48:
        raise Error("handshake_secret_sha384: expected 48 bytes, got " + String(len(hs)))
    assert_hex_eq(
        hs,
        "984e65f4ea6ac0dece14762ac3752b71867a045c60d3fe7808b31949d2ce27d3142e6da6d92a68437f77c26509ce0b2b",
        "handshake_secret_sha384",
    )


def test_derive_secret_sha384() raises:
    # derive_secret_sha384(0^48, "c hs traffic", SHA384("test message transcript"))
    from crypto.hash import sha384
    var secret = List[UInt8](capacity=48)
    for _ in range(48):
        secret.append(0)
    var transcript_bytes = String("test message transcript").as_bytes()
    var msg = List[UInt8](capacity=len(transcript_bytes))
    for i in range(len(transcript_bytes)):
        msg.append(transcript_bytes[i])
    var h = sha384(msg)
    var result = tls13_derive_secret_sha384(secret, "c hs traffic", h)
    if len(result) != 48:
        raise Error("derive_secret_sha384: expected 48 bytes, got " + String(len(result)))
    assert_hex_eq(
        result,
        "4acac262c66dc8965226cdbe112ef3c06476b5cd86a8e9a32bdba0216a404a169abf249e4136ffcf49858b29d8d1bf42",
        "derive_secret_sha384",
    )


def test_finished_sha384() raises:
    # finished_key_sha384 + compute_finished_sha384
    # traffic_secret = bytes(range(48))
    from crypto.hash import sha384
    var ts = List[UInt8](capacity=48)
    for i in range(48):
        ts.append(UInt8(i))
    var fk = tls13_finished_key_sha384(ts)
    if len(fk) != 48:
        raise Error("finished_key_sha384: expected 48 bytes, got " + String(len(fk)))
    assert_hex_eq(
        fk,
        "fcbe325d88fe0a23ac276c591cdbfe90895612d7c0cbcdb21e3d1ffc20d96ed8148a1610d115f29b6771bccdf7a29fe2",
        "finished_key_sha384",
    )

    # verify_data = HMAC-SHA384(fk, SHA384("handshake messages transcript"))
    var transcript_bytes = String("handshake messages transcript").as_bytes()
    var msg = List[UInt8](capacity=len(transcript_bytes))
    for i in range(len(transcript_bytes)):
        msg.append(transcript_bytes[i])
    var th = sha384(msg)
    var vd = tls13_compute_finished_sha384(fk, th)
    if len(vd) != 48:
        raise Error("compute_finished_sha384: expected 48 bytes, got " + String(len(vd)))
    assert_hex_eq(
        vd,
        "4001e365b483cd4152458fd166b4cd0c121c4aef279514c80b488b17c638dfeb632e437be4874ef599bb469f14316e0d",
        "compute_finished_sha384",
    )


def test_verify_finished_sha384_accept_reject() raises:
    from crypto.hash import sha384
    var ts = List[UInt8](capacity=48)
    for i in range(48):
        ts.append(UInt8(i))
    var transcript_bytes = String("handshake messages transcript").as_bytes()
    var msg = List[UInt8](capacity=len(transcript_bytes))
    for i in range(len(transcript_bytes)):
        msg.append(transcript_bytes[i])
    var th = sha384(msg)
    var fk = tls13_finished_key_sha384(ts)
    var vd = tls13_compute_finished_sha384(fk, th)

    # Valid — must not raise
    tls13_verify_finished_sha384(fk, th, vd)

    # Invalid — flip a byte, must raise
    vd[0] ^= 0x01
    var raised = False
    try:
        tls13_verify_finished_sha384(fk, th, vd)
    except:
        raised = True
    if not raised:
        raise Error("verify_finished_sha384_reject: bad MAC not rejected")


def main() raises:
    var passed = 0
    var failed = 0
    print("=== TLS 1.3 Handshake Key Schedule Tests ===")
    print()
    run_test("Early Secret (0^32 PSK)",       passed, failed, test_early_secret)
    run_test("HKDF-Expand-Label 'derived'",   passed, failed, test_expand_label_derived)
    run_test("Derive-Secret",                 passed, failed, test_derive_secret)
    run_test("Traffic key and IV derivation", passed, failed, test_traffic_keys)
    run_test("Finished key derivation",       passed, failed, test_finished_key)
    run_test("Compute Finished verify_data",  passed, failed, test_compute_finished)
    run_test("Verify Finished valid",         passed, failed, test_verify_finished_valid)
    run_test("Verify Finished reject bad",    passed, failed, test_verify_finished_reject)
    run_test("CertificateVerify input",                passed, failed, test_cert_verify_input)
    run_test("Full key schedule (RFC 8448)",           passed, failed, test_full_key_schedule)
    run_test("SHA-384 Early Secret",                   passed, failed, test_early_secret_sha384)
    run_test("SHA-384 Handshake Secret (RFC 8448 DHE)", passed, failed, test_handshake_secret_sha384)
    run_test("SHA-384 Derive-Secret",                  passed, failed, test_derive_secret_sha384)
    run_test("SHA-384 Finished key + compute",         passed, failed, test_finished_sha384)
    run_test("SHA-384 Verify Finished accept + reject", passed, failed, test_verify_finished_sha384_accept_reject)
    print()
    print("Results:", passed, "passed,", failed, "failed")
    if failed > 0:
        raise Error(String(failed) + " test(s) failed")
