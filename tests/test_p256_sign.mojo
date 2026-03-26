# ============================================================================
# test_p256_sign.mojo — P-256 ECDSA signing tests
# ============================================================================
# Tests use p256_ecdsa_sign + p256_ecdsa_verify round-trips and edge cases.
# The sign function uses HMAC-SHA-256 based deterministic nonce derivation.
# ============================================================================

from crypto.p256 import p256_ecdsa_sign, p256_ecdsa_verify, p256_public_key
from crypto.hash import sha256


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


# Fixed test key — private scalar in [1, n-1], not a real key
def _test_priv() raises -> List[UInt8]:
    return hex_to_bytes("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721")


def _test_hash() raises -> List[UInt8]:
    # SHA-256("test message")
    var msg = List[UInt8]()
    for b in "test message".as_bytes():
        msg.append(b)
    return sha256(msg)


def _test_nonce() raises -> List[UInt8]:
    return hex_to_bytes("af2bdbe1aa9b6ec1e2ade1d694f41fc71a831d0268e9891562113d8a62add1bf")


# ============================================================================
# Test 1 — Round-trip: sign then verify
# ============================================================================

def test_sign_verify_roundtrip() raises:
    var priv = _test_priv()
    var hash = _test_hash()
    var nonce = _test_nonce()

    var pub = p256_public_key(priv.copy())
    var sig = p256_ecdsa_sign(priv, hash.copy(), nonce)
    var r = sig[0].copy()
    var s = sig[1].copy()

    assert_true(len(r) == 32, "r length")
    assert_true(len(s) == 32, "s length")

    # Must verify without raising
    p256_ecdsa_verify(pub, hash, r, s)


# ============================================================================
# Test 2 — Deterministic: same inputs → same (r, s)
# ============================================================================

def test_deterministic() raises:
    var priv = _test_priv()
    var hash = _test_hash()
    var nonce = _test_nonce()

    var sig1 = p256_ecdsa_sign(priv.copy(), hash.copy(), nonce.copy())
    var sig2 = p256_ecdsa_sign(priv.copy(), hash.copy(), nonce.copy())

    assert_true(bytes_to_hex(sig1[0]) == bytes_to_hex(sig2[0]), "r deterministic")
    assert_true(bytes_to_hex(sig1[1]) == bytes_to_hex(sig2[1]), "s deterministic")


# ============================================================================
# Test 3 — Different nonce → different (r, s)
# ============================================================================

def test_different_nonce_different_sig() raises:
    var priv = _test_priv()
    var hash = _test_hash()

    var nonce1 = hex_to_bytes("af2bdbe1aa9b6ec1e2ade1d694f41fc71a831d0268e9891562113d8a62add1bf")
    var nonce2 = hex_to_bytes("af2bdbe1aa9b6ec1e2ade1d694f41fc71a831d0268e9891562113d8a62add1be")

    var sig1 = p256_ecdsa_sign(priv.copy(), hash.copy(), nonce1)
    var sig2 = p256_ecdsa_sign(priv.copy(), hash.copy(), nonce2)

    assert_true(bytes_to_hex(sig1[0]) != bytes_to_hex(sig2[0]), "different nonce → different r")


# ============================================================================
# Test 4 — Wrong hash fails verification
# ============================================================================

def test_wrong_hash_fails_verify() raises:
    var priv = _test_priv()
    var hash = _test_hash()
    var nonce = _test_nonce()
    var pub = p256_public_key(priv.copy())

    var sig = p256_ecdsa_sign(priv, hash.copy(), nonce)
    var r = sig[0].copy()
    var s = sig[1].copy()

    # Flip one bit in the hash
    var bad_hash = hash.copy()
    bad_hash[0] ^= 0x01

    var got_error = False
    try:
        p256_ecdsa_verify(pub, bad_hash, r, s)
    except:
        got_error = True
    assert_true(got_error, "wrong hash must fail verify")


# ============================================================================
# Test 5 — Wrong public key fails verification
# ============================================================================

def test_wrong_pubkey_fails_verify() raises:
    var priv = _test_priv()
    var hash = _test_hash()
    var nonce = _test_nonce()

    var sig = p256_ecdsa_sign(priv.copy(), hash.copy(), nonce)
    var r = sig[0].copy()
    var s = sig[1].copy()

    # Use a different private key → different public key
    var other_priv = hex_to_bytes("519b423d715f8b581f4fa8ee59f4771a5b44c8130b4e3eacca54a56dda72b464")
    var other_pub = p256_public_key(other_priv)

    var got_error = False
    try:
        p256_ecdsa_verify(other_pub, hash, r, s)
    except:
        got_error = True
    assert_true(got_error, "wrong pubkey must fail verify")


# ============================================================================
# Test 6 — Low-s: s is never > n/2
#
# P-256 group order n:
#   ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
# n/2 (floor):
#   7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8
# ============================================================================

def test_low_s_normalization() raises:
    var n_half = hex_to_bytes("7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8")
    var priv = _test_priv()
    var nonce_base = _test_nonce()

    # Test with 10 different messages to increase coverage
    for i in range(10):
        var msg = List[UInt8]()
        msg.append(UInt8(i))
        var hash = sha256(msg)

        var nonce = nonce_base.copy()
        nonce[31] = UInt8(i)   # vary nonce per iteration

        var sig = p256_ecdsa_sign(priv.copy(), hash, nonce)
        var s = sig[1].copy()

        # Compare s against n/2: s must be <= n/2
        # Compare byte-by-byte (big-endian)
        var s_gt_n_half = False
        for j in range(32):
            if Int(s[j]) > Int(n_half[j]):
                s_gt_n_half = True
                break
            elif Int(s[j]) < Int(n_half[j]):
                break
        assert_true(not s_gt_n_half, "low-s: s must be <= n/2 (iter " + String(i) + ")")


# ============================================================================
# Test 7 — Private key = 0 raises
# ============================================================================

def test_zero_private_key_raises() raises:
    var zero_priv = List[UInt8](capacity=32)
    for _ in range(32):
        zero_priv.append(0)
    var hash = _test_hash()
    var nonce = _test_nonce()

    var got_error = False
    try:
        _ = p256_ecdsa_sign(zero_priv, hash, nonce)
    except:
        got_error = True
    assert_true(got_error, "zero private key must raise")


# ============================================================================
# Test 8 — Private key = n raises (out of range)
# n = ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
# ============================================================================

def test_n_private_key_raises() raises:
    var n_priv = hex_to_bytes("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551")
    var hash = _test_hash()
    var nonce = _test_nonce()

    var got_error = False
    try:
        _ = p256_ecdsa_sign(n_priv, hash, nonce)
    except:
        got_error = True
    assert_true(got_error, "private key = n must raise")


# ============================================================================
# Test 9 — Signature is valid across multiple messages
# ============================================================================

def test_multi_message_roundtrip() raises:
    var priv = _test_priv()
    var pub = p256_public_key(priv.copy())
    var nonce_base = _test_nonce()

    for i in range(5):
        var msg = List[UInt8]()
        for b in ("message " + String(i)).as_bytes():
            msg.append(b)
        var hash = sha256(msg)

        var nonce = nonce_base.copy()
        nonce[0] = UInt8(i + 1)

        var sig = p256_ecdsa_sign(priv.copy(), hash.copy(), nonce)
        p256_ecdsa_verify(pub.copy(), hash, sig[0], sig[1])


# ============================================================================
# Test 10 — Wrong key length raises
# ============================================================================

def test_wrong_key_length_raises() raises:
    var short_key = List[UInt8](capacity=16)
    for _ in range(16):
        short_key.append(1)
    var hash = _test_hash()
    var nonce = _test_nonce()

    var got_error = False
    try:
        _ = p256_ecdsa_sign(short_key, hash, nonce)
    except:
        got_error = True
    assert_true(got_error, "short private key must raise")


# ============================================================================
# Main
# ============================================================================

def main() raises:
    var passed = 0
    var failed = 0

    print("=== P-256 ECDSA Sign Tests ===")
    print()

    run_test("sign-verify round-trip",          passed, failed, test_sign_verify_roundtrip)
    run_test("deterministic (same inputs)",      passed, failed, test_deterministic)
    run_test("different nonce → different sig", passed, failed, test_different_nonce_different_sig)
    run_test("wrong hash fails verify",          passed, failed, test_wrong_hash_fails_verify)
    run_test("wrong pubkey fails verify",        passed, failed, test_wrong_pubkey_fails_verify)
    run_test("low-s normalization",              passed, failed, test_low_s_normalization)
    run_test("zero private key raises",          passed, failed, test_zero_private_key_raises)
    run_test("private key = n raises",           passed, failed, test_n_private_key_raises)
    run_test("multi-message round-trip",         passed, failed, test_multi_message_roundtrip)
    run_test("wrong key length raises",          passed, failed, test_wrong_key_length_raises)

    print()
    print("Results:", String(passed), "passed,", String(failed), "failed,", String(passed + failed), "total")
    if failed > 0:
        raise Error(String(failed) + " test(s) failed")
