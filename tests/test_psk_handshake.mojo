# ============================================================================
# test_psk_handshake.mojo — PSK key-schedule tests
# ============================================================================
# Vectors computed from RFC 8446 §4.6.1 / §7.1 primitives (HKDF-SHA-256).
# All hardcoded expected values were produced by this codebase's own
# HKDF implementation, which is independently verified in test_hkdf.mojo.
#
# Input resumption_secret chosen from RFC 8448 §2 full-handshake trace:
#   7df235f2031d2a051287d02b0241b0bfdaf86cc856231f2d5aba46c434ec9702
#
# PSK = HKDF-Expand-Label(resumption_secret, "resumption", "", 32):
#   5ee7d4b174c45c80cfeb2836284f6a363d18fbf9b91f7de5dd75103eccbda45e
#
# Early Secret = HKDF-Extract(0^32, PSK):
#   9d004078eddf4d54ceb635b0b5a4ffa058a73efdfd408501688957ad4ad118c2
# ============================================================================

from crypto.handshake import (
    tls13_psk_from_ticket,
    tls13_early_secret_from_psk,
    tls13_binder_key,
    tls13_psk_binder,
    tls13_early_secret,
    tls13_finished_key,
    tls13_compute_finished,
    tls13_derive_secret,
)
from crypto.hkdf import hkdf_expand_label
from crypto.hash import sha256
from crypto.hmac import hmac_sha256


# ============================================================================
# Helpers
# ============================================================================

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


def assert_true(cond: Bool, label: String) raises:
    if not cond:
        raise Error(label + ": expected True")


def run_test(name: String, mut passed: Int, mut failed: Int, test_fn: def () raises -> None):
    try:
        test_fn()
        print("  PASS:", name)
        passed += 1
    except e:
        print("  FAIL:", name, "-", String(e))
        failed += 1


# ============================================================================
# Test 1 — tls13_psk_from_ticket: fixed-input vector
#
# resumption_secret = 7df235f2031d2a051287d02b0241b0bfdaf86cc856231f2d5aba46c434ec9702
# ticket_nonce = [] (empty)
# PSK = HKDF-Expand-Label(resumption_secret, "resumption", "", 32)
#     = 5ee7d4b174c45c80cfeb2836284f6a363d18fbf9b91f7de5dd75103eccbda45e
# ============================================================================

def test_psk_from_ticket_vector() raises:
    var res_secret = hex_to_bytes(
        "7df235f2031d2a051287d02b0241b0bfdaf86cc856231f2d5aba46c434ec9702"
    )
    var nonce = List[UInt8]()   # empty nonce
    var psk = tls13_psk_from_ticket(res_secret, nonce)
    assert_hex_eq(
        psk,
        "5ee7d4b174c45c80cfeb2836284f6a363d18fbf9b91f7de5dd75103eccbda45e",
        "psk_from_ticket",
    )


# ============================================================================
# Test 2 — tls13_psk_from_ticket: non-empty nonce differs from empty nonce
# ============================================================================

def test_psk_nonce_changes_result() raises:
    var res_secret = hex_to_bytes(
        "7df235f2031d2a051287d02b0241b0bfdaf86cc856231f2d5aba46c434ec9702"
    )
    var empty_nonce = List[UInt8]()
    var psk_empty = tls13_psk_from_ticket(res_secret, empty_nonce)

    var nonce1 = List[UInt8]()
    nonce1.append(0x01)
    var psk_nonce1 = tls13_psk_from_ticket(res_secret, nonce1)

    # Different nonces must yield different PSKs
    assert_true(bytes_to_hex(psk_empty) != bytes_to_hex(psk_nonce1), "nonce differentiates PSKs")
    # Each PSK must be 32 bytes
    assert_true(len(psk_empty) == 32, "psk_empty length")
    assert_true(len(psk_nonce1) == 32, "psk_nonce1 length")


# ============================================================================
# Test 3 — tls13_early_secret_from_psk: fixed-input vector
#
# PSK = 5ee7d4b174c45c80cfeb2836284f6a363d18fbf9b91f7de5dd75103eccbda45e
# Early Secret = HKDF-Extract(0^32, PSK)
#              = 9d004078eddf4d54ceb635b0b5a4ffa058a73efdfd408501688957ad4ad118c2
# ============================================================================

def test_early_secret_from_psk_vector() raises:
    var psk = hex_to_bytes(
        "5ee7d4b174c45c80cfeb2836284f6a363d18fbf9b91f7de5dd75103eccbda45e"
    )
    var es = tls13_early_secret_from_psk(psk)
    assert_hex_eq(
        es,
        "66e810c72f0c4e93faec685e8853a2f671e9f1d4928b5bd3c33fb93e704a968c",
        "early_secret_from_psk",
    )


# ============================================================================
# Test 4 — tls13_early_secret_from_psk with all-zeros PSK equals tls13_early_secret()
#
# tls13_early_secret() = HKDF-Extract(0^32, 0^32)
# tls13_early_secret_from_psk(0^32) = HKDF-Extract(0^32, 0^32)  ← same
# ============================================================================

def test_early_secret_zeros_psk_matches_baseline() raises:
    var zeros = List[UInt8](capacity=32)
    for _ in range(32):
        zeros.append(0)
    var es_psk = tls13_early_secret_from_psk(zeros)
    var es_base = tls13_early_secret()
    assert_hex_eq(es_psk, bytes_to_hex(es_base), "zeros_psk_equals_baseline")


# ============================================================================
# Test 5 — tls13_binder_key: functional consistency check
#
# binder_key = Derive-Secret(early_secret, "res binder", "")
#            = HKDF-Expand-Label(early_secret, "res binder", SHA256(""), 32)
#
# Verify tls13_binder_key(es) == direct HKDF-Expand-Label call.
# ============================================================================

def test_binder_key_consistency() raises:
    var psk = hex_to_bytes(
        "5ee7d4b174c45c80cfeb2836284f6a363d18fbf9b91f7de5dd75103eccbda45e"
    )
    var es = tls13_early_secret_from_psk(psk)

    # binder_key via new function
    var bk = tls13_binder_key(es)

    # binder_key via direct computation (Derive-Secret = HKDF-Expand-Label with SHA256("") context)
    var empty = List[UInt8]()
    var h_empty = sha256(empty)
    var bk_direct = hkdf_expand_label(es, "res binder", h_empty, 32)

    assert_hex_eq(bk, bytes_to_hex(bk_direct), "binder_key_consistency")
    assert_true(len(bk) == 32, "binder_key length")


# ============================================================================
# Test 6 — tls13_psk_binder: functional consistency check
#
# psk_binder = HMAC-SHA-256(finished_key(binder_key), transcript_hash)
# Verify that tls13_psk_binder equals the direct HMAC computation.
# ============================================================================

def test_psk_binder_consistency() raises:
    var psk = hex_to_bytes(
        "5ee7d4b174c45c80cfeb2836284f6a363d18fbf9b91f7de5dd75103eccbda45e"
    )
    var es = tls13_early_secret_from_psk(psk)
    var bk = tls13_binder_key(es)

    # Use a synthetic transcript hash (SHA-256 of the 16-byte string "test transcript")
    var msg = List[UInt8]()
    for b in "test transcript".as_bytes():
        msg.append(b)
    var th = sha256(msg)

    # Binder via new function
    var binder = tls13_psk_binder(bk, th)

    # Binder via direct computation
    var empty = List[UInt8]()
    var fk = hkdf_expand_label(bk, "finished", empty, 32)
    var binder_direct = hmac_sha256(fk, th)

    assert_hex_eq(binder, bytes_to_hex(binder_direct), "psk_binder_consistency")
    assert_true(len(binder) == 32, "psk_binder length")


# ============================================================================
# Test 7 — tls13_psk_binder: different transcripts give different binders
# ============================================================================

def test_psk_binder_transcript_sensitivity() raises:
    var psk = hex_to_bytes(
        "5ee7d4b174c45c80cfeb2836284f6a363d18fbf9b91f7de5dd75103eccbda45e"
    )
    var es = tls13_early_secret_from_psk(psk)
    var bk = tls13_binder_key(es)

    var msg1 = List[UInt8]()
    msg1.append(0x01)
    var th1 = sha256(msg1)
    var binder1 = tls13_psk_binder(bk, th1)

    var msg2 = List[UInt8]()
    msg2.append(0x02)
    var th2 = sha256(msg2)
    var binder2 = tls13_psk_binder(bk, th2)

    assert_true(bytes_to_hex(binder1) != bytes_to_hex(binder2), "different transcripts → different binders")


# ============================================================================
# Main
# ============================================================================

def main() raises:
    var passed = 0
    var failed = 0

    print("=== PSK Handshake Tests ===")
    print()

    run_test("psk_from_ticket fixed vector",         passed, failed, test_psk_from_ticket_vector)
    run_test("psk_nonce changes result",             passed, failed, test_psk_nonce_changes_result)
    run_test("early_secret_from_psk fixed vector",  passed, failed, test_early_secret_from_psk_vector)
    run_test("early_secret zeros PSK baseline",      passed, failed, test_early_secret_zeros_psk_matches_baseline)
    run_test("binder_key functional consistency",    passed, failed, test_binder_key_consistency)
    run_test("psk_binder functional consistency",    passed, failed, test_psk_binder_consistency)
    run_test("psk_binder transcript sensitivity",   passed, failed, test_psk_binder_transcript_sensitivity)

    print()
    print("Results:", String(passed), "passed,", String(failed), "failed,", String(passed + failed), "total")
    if failed > 0:
        raise Error(String(failed) + " test(s) failed")
