# ============================================================================
# test_pem.mojo — PEM decoder tests
# ============================================================================
# Test vectors generated with Python:
#   der1 = bytes.fromhex("3082029f30820187")  → base64 = "MIICnzCCAYc="
#   der2 = bytes.fromhex("3081b030818f")      → base64 = "MIGwMIGP"
# ============================================================================

from crypto.pem import pem_decode


def run_test(
    name: String,
    mut passed: Int,
    mut failed: Int,
    test_fn: def () raises -> None,
):
    try:
        test_fn()
        print("  PASS:", name)
        passed += 1
    except e:
        print("  FAIL:", name, "-", String(e))
        failed += 1


def bytes_eq(a: List[UInt8], b: List[UInt8]) -> Bool:
    if len(a) != len(b):
        return False
    for i in range(len(a)):
        if a[i] != b[i]:
            return False
    return True


def hex_to_bytes(h: String) -> List[UInt8]:
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


# ── Tests ─────────────────────────────────────────────────────────────────────

def test_single_cert() raises:
    # Single CERTIFICATE block; DER = bytes.fromhex("3082029f30820187")
    var pem = String(
        "-----BEGIN CERTIFICATE-----\nMIICnzCCAYc=\n-----END CERTIFICATE-----\n"
    )
    var result = pem_decode(pem, "CERTIFICATE")
    if len(result) != 1:
        raise Error("expected 1 cert, got " + String(len(result)))
    var expected = hex_to_bytes("3082029f30820187")
    if not bytes_eq(result[0], expected):
        raise Error("DER mismatch in single cert test")


def test_two_certs() raises:
    # Two CERTIFICATE blocks
    var pem = String(
        "-----BEGIN CERTIFICATE-----\nMIICnzCCAYc=\n-----END CERTIFICATE-----\n"
        + "-----BEGIN CERTIFICATE-----\nMIGwMIGP\n-----END CERTIFICATE-----\n"
    )
    var result = pem_decode(pem, "CERTIFICATE")
    if len(result) != 2:
        raise Error("expected 2 certs, got " + String(len(result)))
    var expected1 = hex_to_bytes("3082029f30820187")
    var expected2 = hex_to_bytes("3081b030818f")
    if not bytes_eq(result[0], expected1):
        raise Error("DER mismatch in cert 0")
    if not bytes_eq(result[1], expected2):
        raise Error("DER mismatch in cert 1")


def test_wrong_label_raises() raises:
    var pem = String(
        "-----BEGIN CERTIFICATE-----\nMIICnzCCAYc=\n-----END CERTIFICATE-----\n"
    )
    var raised = False
    try:
        _ = pem_decode(pem, "PRIVATE KEY")
    except:
        raised = True
    if not raised:
        raise Error("expected raise for wrong label")


def test_malformed_base64_raises() raises:
    # Bad base64 content
    var pem = String(
        "-----BEGIN CERTIFICATE-----\nZ!==\n-----END CERTIFICATE-----\n"
    )
    var raised = False
    try:
        _ = pem_decode(pem, "CERTIFICATE")
    except:
        raised = True
    if not raised:
        raise Error("expected raise for malformed base64")


def main() raises:
    var passed = 0
    var failed = 0

    print("=== PEM Decoder Tests ===")
    print()

    run_test("single CERTIFICATE block", passed, failed, test_single_cert)
    run_test("two CERTIFICATE blocks", passed, failed, test_two_certs)
    run_test("wrong label raises", passed, failed, test_wrong_label_raises)
    run_test("malformed base64 raises", passed, failed, test_malformed_base64_raises)

    print()
    print("Results:", passed, "passed,", failed, "failed")
    if failed > 0:
        raise Error(String(failed) + " test(s) failed")
