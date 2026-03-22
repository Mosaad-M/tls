# ============================================================================
# test_rsa.mojo — RSA-PKCS#1 v1.5 and RSA-PSS verification tests
# ============================================================================
# Test vectors generated with Python cryptography library (see comments).
# RSA-1024 key (insecure, fast for testing):
#   n   = 128-byte modulus
#   e   = 65537
# Message: b"test message for RSA"
# hash    = SHA-256(message) = fa48700ab9b800ac9b82e89f6ab90622988fb1f9a5498402fc19a99c1ec91018
# ============================================================================

from crypto.rsa import rsa_pkcs1_verify, rsa_pss_verify


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


def run_test(name: String, mut passed: Int, mut failed: Int, test_fn: def () raises -> None):
    try:
        test_fn()
        print("  PASS:", name)
        passed += 1
    except e:
        print("  FAIL:", name, "-", String(e))
        failed += 1


# ============================================================================
# Fixed RSA-1024 key and test vectors
# ============================================================================

def _rsa_n() raises -> List[UInt8]:
    return hex_to_bytes(
        "c7974be25680819d64991c0325af4d91"
        "cb1092fa736b1454ea401c3d73dcfcb5"
        "4359823535e405e8d0bac61dfc30e000"
        "d7b7388665f8190441fcbb1133dab063"
        "dc6325c3493a299e6f852b131149c11e"
        "0662e84c4bb1f59f8cc4605af5a77c27"
        "f9fc25f708ace1e18093fc1235341a4d"
        "e32f581caac6f7e780cd708142bacf95"
    )


def _rsa_e() raises -> List[UInt8]:
    return hex_to_bytes("00010001")  # 65537


def _msg_hash() raises -> List[UInt8]:
    # SHA-256("test message for RSA")
    return hex_to_bytes("fa48700ab9b800ac9b82e89f6ab90622988fb1f9a5498402fc19a99c1ec91018")


def _pkcs1_sig() raises -> List[UInt8]:
    return hex_to_bytes(
        "ad289740e8001c743fadfacccd83e34d"
        "378578e21ffcab5b0169ef41081740f1"
        "bea4a19adec7ca6fed12da7c91d2f030"
        "9dc606c170cf856c503d7e51839d0e40"
        "7633fb2bce82a8d09a15c104b4c97358"
        "7d68edca49444bfc3b8c3cb98069f4c9"
        "14c0c6e0f70d64be47817467cb302b3e"
        "6f63a95dd8c74d098af715efa3435930"
    )


def _pss_sig() raises -> List[UInt8]:
    return hex_to_bytes(
        "63a278b30f7eeae76e92545cfcbd7b2e"
        "e171e1612da892dd30c3196366acce08"
        "8cdfe5faab026a0aa2631c1e47a77c3a"
        "ed7c5814312605cf2f511cde7e6d408e"
        "ce4f34e796d674bcc717367f509a5af1"
        "c6cf5a020fb88bed17c96883af7e3a69"
        "c9507f95b5d87313e8821bdfd2d0787a"
        "ce00cfa018cdcd804131365ddde977a5"
    )


# ============================================================================
# PKCS#1 v1.5 tests
# ============================================================================

def test_pkcs1_valid() raises:
    rsa_pkcs1_verify(_rsa_n(), _rsa_e(), _msg_hash(), _pkcs1_sig())


def test_pkcs1_reject_wrong_hash() raises:
    # Flip a byte in the hash → verification must fail
    var h = _msg_hash()
    h[0] ^= 0x01
    var raised = False
    try:
        rsa_pkcs1_verify(_rsa_n(), _rsa_e(), h, _pkcs1_sig())
    except:
        raised = True
    if not raised:
        raise Error("pkcs1_reject_wrong_hash: bad hash not rejected")


def test_pkcs1_reject_tampered_sig() raises:
    var sig = _pkcs1_sig()
    sig[63] ^= 0x01   # Flip a bit in the middle of the signature
    var raised = False
    try:
        rsa_pkcs1_verify(_rsa_n(), _rsa_e(), _msg_hash(), sig)
    except:
        raised = True
    if not raised:
        raise Error("pkcs1_reject_tampered_sig: tampered sig not rejected")


# ============================================================================
# RSA-PSS tests
# ============================================================================

def test_pss_valid() raises:
    rsa_pss_verify(_rsa_n(), _rsa_e(), _msg_hash(), _pss_sig(), 32)


def test_pss_reject_wrong_hash() raises:
    var h = _msg_hash()
    h[15] ^= 0x01
    var raised = False
    try:
        rsa_pss_verify(_rsa_n(), _rsa_e(), h, _pss_sig(), 32)
    except:
        raised = True
    if not raised:
        raise Error("pss_reject_wrong_hash: bad hash not rejected")


def test_pss_reject_tampered_sig() raises:
    var sig = _pss_sig()
    sig[0] ^= 0x01
    var raised = False
    try:
        rsa_pss_verify(_rsa_n(), _rsa_e(), _msg_hash(), sig, 32)
    except:
        raised = True
    if not raised:
        raise Error("pss_reject_tampered_sig: tampered sig not rejected")


def main() raises:
    var passed = 0
    var failed = 0
    print("=== RSA Verification Tests ===")
    print()
    run_test("PKCS#1 v1.5 valid signature",        passed, failed, test_pkcs1_valid)
    run_test("PKCS#1 v1.5 reject wrong hash",       passed, failed, test_pkcs1_reject_wrong_hash)
    run_test("PKCS#1 v1.5 reject tampered sig",     passed, failed, test_pkcs1_reject_tampered_sig)
    run_test("RSA-PSS valid signature",             passed, failed, test_pss_valid)
    run_test("RSA-PSS reject wrong hash",           passed, failed, test_pss_reject_wrong_hash)
    run_test("RSA-PSS reject tampered sig",         passed, failed, test_pss_reject_tampered_sig)
    print()
    print("Results:", passed, "passed,", failed, "failed")
    if failed > 0:
        raise Error(String(failed) + " test(s) failed")
