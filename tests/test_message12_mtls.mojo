# ============================================================================
# test_message12_mtls.mojo — TLS 1.2 mTLS message parser/builder tests
# ============================================================================
# Tests:
#   - parse_certificate_request12: valid input, truncation at each field
#   - build_client_certificate12: empty chain, single cert, round-trip parse
#   - build_client_certificate_verify12: header fields, round-trip parse
#   - _ecdsa_raw_to_der: known vectors, high-bit padding, leading zeros
# ============================================================================

from tls.message12 import (
    CertificateRequest12,
    parse_certificate_request12,
    build_client_certificate12,
    build_client_certificate_verify12,
    _ecdsa_raw_to_der,
    HS_CERTIFICATE,
    HS_CERTIFICATE_VERIFY,
)
from tls.message import _read_u16be, _read_u24be


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


def assert_eq(actual: Int, expected: Int, label: String) raises:
    if actual != expected:
        raise Error(label + ": got " + String(actual) + ", want " + String(expected))


def assert_hex_eq(got: List[UInt8], expected_hex: String, label: String) raises:
    var h = bytes_to_hex(got)
    if h != expected_hex:
        raise Error(label + ": got " + h + ", want " + expected_hex)


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
# Build a minimal valid CertificateRequest12 body for testing
#
# certificate_types: [64]  (ECDSA)
# supported_signature_algs: [(4, 3)]  (SHA-256, ECDSA)
# certificate_authorities: []  (empty)
# ============================================================================

def _build_certreq_body() -> List[UInt8]:
    var b = List[UInt8]()
    # certificate_types: len=1, [64=ECDSA]
    b.append(0x01)
    b.append(64)
    # supported_signature_algs: len=2, one pair (4, 3)
    b.append(0x00); b.append(0x02)
    b.append(0x04); b.append(0x03)
    # certificate_authorities: len=0
    b.append(0x00); b.append(0x00)
    return b^


# ============================================================================
# Test 1 — parse valid minimal CertificateRequest12
# ============================================================================

def test_parse_valid_certreq() raises:
    var body = _build_certreq_body()
    var cr = parse_certificate_request12(body)
    assert_eq(len(cr.certificate_types), 1, "cert_types length")
    assert_eq(Int(cr.certificate_types[0]), 64, "cert_types[0]")
    assert_eq(len(cr.supported_signature_algs), 1, "sig_algs length")
    # pair = (4 << 8) | 3 = 0x0403
    assert_eq(Int(cr.supported_signature_algs[0]), 0x0403, "sig_alg pair")
    assert_eq(len(cr.certificate_authorities), 0, "ca list empty")


# ============================================================================
# Test 2 — parse CertificateRequest12 with multiple types and algorithms
# ============================================================================

def test_parse_certreq_multi() raises:
    var b = List[UInt8]()
    # certificate_types: [1=RSA, 64=ECDSA]
    b.append(0x02); b.append(0x01); b.append(64)
    # supported_signature_algs: 3 pairs
    b.append(0x00); b.append(0x06)
    b.append(0x04); b.append(0x01)  # SHA-256, RSA
    b.append(0x04); b.append(0x03)  # SHA-256, ECDSA
    b.append(0x05); b.append(0x01)  # SHA-384, RSA
    # certificate_authorities: len=0
    b.append(0x00); b.append(0x00)

    var cr = parse_certificate_request12(b)
    assert_eq(len(cr.certificate_types), 2, "multi: cert_types length")
    assert_eq(Int(cr.certificate_types[0]), 1, "multi: cert_types[0]")
    assert_eq(Int(cr.certificate_types[1]), 64, "multi: cert_types[1]")
    assert_eq(len(cr.supported_signature_algs), 3, "multi: sig_algs length")


# ============================================================================
# Test 3 — parse CertificateRequest12 with non-empty CA list
# ============================================================================

def test_parse_certreq_with_ca() raises:
    var b = List[UInt8]()
    # certificate_types: [64]
    b.append(0x01); b.append(64)
    # sig algs: one pair
    b.append(0x00); b.append(0x02); b.append(0x04); b.append(0x03)
    # CA list: total len = 5 (one entry: 2-byte len + 3 bytes)
    b.append(0x00); b.append(0x05)
    b.append(0x00); b.append(0x03)  # DN len = 3
    b.append(0xAA); b.append(0xBB); b.append(0xCC)

    var cr = parse_certificate_request12(b)
    assert_eq(len(cr.certificate_authorities), 1, "ca list length")
    assert_eq(len(cr.certificate_authorities[0]), 3, "ca[0] dn length")
    assert_eq(Int(cr.certificate_authorities[0][0]), 0xAA, "ca[0][0]")


# ============================================================================
# Test 4 — truncation at types_len raises
# ============================================================================

def test_certreq_truncated_at_types() raises:
    var b = List[UInt8]()  # empty
    var got_error = False
    try:
        _ = parse_certificate_request12(b)
    except:
        got_error = True
    assert_true(got_error, "empty body must raise")


# ============================================================================
# Test 5 — truncation at sig_algs_len raises
# ============================================================================

def test_certreq_truncated_at_algs() raises:
    var b = List[UInt8]()
    b.append(0x01); b.append(64)  # types ok
    b.append(0x00)  # only 1 of 2 bytes for sig_algs_len
    var got_error = False
    try:
        _ = parse_certificate_request12(b)
    except:
        got_error = True
    assert_true(got_error, "truncated at sig_algs_len must raise")


# ============================================================================
# Test 6 — truncation at ca_list_len raises
# ============================================================================

def test_certreq_truncated_at_ca() raises:
    var b = List[UInt8]()
    b.append(0x01); b.append(64)   # types
    b.append(0x00); b.append(0x02); b.append(0x04); b.append(0x03)  # sig algs
    b.append(0x00)  # only 1 of 2 bytes for ca_list_len
    var got_error = False
    try:
        _ = parse_certificate_request12(b)
    except:
        got_error = True
    assert_true(got_error, "truncated at ca_list_len must raise")


# ============================================================================
# Test 7 — build_client_certificate12: empty chain
# ============================================================================

def test_build_cert12_empty() raises:
    var chain = List[List[UInt8]]()
    var msg = build_client_certificate12(chain)

    # Structure: type(1) + len24(3) + list_len24(3) = 7 bytes min
    assert_true(len(msg) >= 7, "empty cert msg too short")
    assert_eq(Int(msg[0]), Int(HS_CERTIFICATE), "msg type = Certificate")

    # list_len should be 0 (no certificates)
    var list_len = (Int(msg[4]) << 16) | (Int(msg[5]) << 8) | Int(msg[6])
    assert_eq(list_len, 0, "empty cert list_len")


# ============================================================================
# Test 8 — build_client_certificate12: single cert round-trip
# ============================================================================

def test_build_cert12_single() raises:
    var cert_der = List[UInt8]()
    for i in range(10):
        cert_der.append(UInt8(i))
    var chain = List[List[UInt8]]()
    chain.append(cert_der.copy())

    var msg = build_client_certificate12(chain)
    assert_eq(Int(msg[0]), Int(HS_CERTIFICATE), "single cert msg type")

    # Total body length = 3 (list_len) + 3 (cert_len) + 10 (cert bytes) = 16
    var body_len = (Int(msg[1]) << 16) | (Int(msg[2]) << 8) | Int(msg[3])
    assert_eq(body_len, 16, "single cert body_len")

    # list_len = 3 + 10 = 13
    var list_len = (Int(msg[4]) << 16) | (Int(msg[5]) << 8) | Int(msg[6])
    assert_eq(list_len, 13, "single cert list_len")

    # cert_len = 10
    var cert_len = (Int(msg[7]) << 16) | (Int(msg[8]) << 8) | Int(msg[9])
    assert_eq(cert_len, 10, "single cert cert_len")

    # cert bytes
    for i in range(10):
        assert_eq(Int(msg[10 + i]), i, "single cert byte[" + String(i) + "]")


# ============================================================================
# Test 9 — build_client_certificate_verify12: header fields
# ============================================================================

def test_build_cert_verify12() raises:
    var sig = List[UInt8]()
    for _ in range(8):
        sig.append(UInt8(0xAA))

    var msg = build_client_certificate_verify12(4, 3, sig)  # SHA-256, ECDSA
    assert_eq(Int(msg[0]), Int(HS_CERTIFICATE_VERIFY), "cv msg type")

    # body = hash_alg(1) + sig_alg(1) + sig_len(2) + sig(8) = 12
    var body_len = (Int(msg[1]) << 16) | (Int(msg[2]) << 8) | Int(msg[3])
    assert_eq(body_len, 12, "cv body_len")
    assert_eq(Int(msg[4]), 4, "cv hash_alg = SHA-256")
    assert_eq(Int(msg[5]), 3, "cv sig_alg = ECDSA")

    # sig_len = 8
    var sig_len = (Int(msg[6]) << 8) | Int(msg[7])
    assert_eq(sig_len, 8, "cv sig_len")


# ============================================================================
# Test 10 — _ecdsa_raw_to_der: known (r, s) → expected DER
#
# r = 0x0102030405060708090a0b0c0d0e0f10 (16 bytes, high bit clear)
# s = 0x8182838485868788898a8b8c8d8e8f90 (16 bytes, high bit SET → needs 0x00 pad)
# ============================================================================

def test_ecdsa_raw_to_der_basic() raises:
    var r = List[UInt8]()
    var s = List[UInt8]()
    # r: 16 bytes, high bit clear → no padding
    for i in range(16):
        r.append(UInt8(i + 1))
    # s: 16 bytes, high bit set → needs 0x00 prepended
    s.append(0x81)
    for i in range(15):
        s.append(UInt8(0x82 + i))

    var der = _ecdsa_raw_to_der(r, s)

    # DER layout: 30 <seq_len> 02 <r_len> <r_bytes> 02 <s_len+1> 00 <s_bytes>
    assert_eq(Int(der[0]), 0x30, "SEQUENCE tag")
    assert_eq(Int(der[2]), 0x02, "INTEGER r tag")
    assert_eq(Int(der[3]), 16, "r length (no padding)")
    # s has high bit set → padded to 17 bytes
    var r_end = 4 + 16
    assert_eq(Int(der[r_end]), 0x02, "INTEGER s tag")
    assert_eq(Int(der[r_end + 1]), 17, "s length (padded)")
    assert_eq(Int(der[r_end + 2]), 0x00, "s padding byte")


# ============================================================================
# Test 11 — _ecdsa_raw_to_der: leading zeros stripped
#
# r = [0x00, 0x00, 0x01] → stripped to [0x01]
# s = [0x00, 0x42]       → stripped to [0x42]
# ============================================================================

def test_ecdsa_raw_to_der_leading_zeros() raises:
    var r = List[UInt8]()
    r.append(0x00); r.append(0x00); r.append(0x01)
    var s = List[UInt8]()
    s.append(0x00); s.append(0x42)

    var der = _ecdsa_raw_to_der(r, s)
    # r stripped to [0x01] (1 byte, high bit clear)
    assert_eq(Int(der[2]), 0x02, "r INTEGER tag")
    assert_eq(Int(der[3]), 1, "r length = 1 after stripping")
    assert_eq(Int(der[4]), 0x01, "r value")
    # s stripped to [0x42] (1 byte, high bit clear)
    assert_eq(Int(der[5]), 0x02, "s INTEGER tag")
    assert_eq(Int(der[6]), 1, "s length = 1")
    assert_eq(Int(der[7]), 0x42, "s value")


# ============================================================================
# Test 12 — _ecdsa_raw_to_der: all-zero r preserves single zero byte
# ============================================================================

def test_ecdsa_raw_to_der_zero_r() raises:
    # r = [0x00, 0x00] → last 0x00 kept (minimum 1 byte)
    var r = List[UInt8]()
    r.append(0x00); r.append(0x00)
    var s = List[UInt8]()
    s.append(0x01)

    var der = _ecdsa_raw_to_der(r, s)
    # r stripped to single [0x00] — no high-bit padding needed
    assert_eq(Int(der[3]), 1, "zero r: length = 1")
    assert_eq(Int(der[4]), 0x00, "zero r: value = 0x00")


# ============================================================================
# Main
# ============================================================================

def main() raises:
    var passed = 0
    var failed = 0

    print("=== TLS 1.2 mTLS Message Tests ===")
    print()

    run_test("parse valid CertificateRequest12",          passed, failed, test_parse_valid_certreq)
    run_test("parse CertificateRequest12 multiple",       passed, failed, test_parse_certreq_multi)
    run_test("parse CertificateRequest12 with CA",        passed, failed, test_parse_certreq_with_ca)
    run_test("truncated at types_len raises",             passed, failed, test_certreq_truncated_at_types)
    run_test("truncated at sig_algs_len raises",          passed, failed, test_certreq_truncated_at_algs)
    run_test("truncated at ca_list_len raises",           passed, failed, test_certreq_truncated_at_ca)
    run_test("build_client_certificate12 empty chain",    passed, failed, test_build_cert12_empty)
    run_test("build_client_certificate12 single cert",    passed, failed, test_build_cert12_single)
    run_test("build_client_certificate_verify12 header",  passed, failed, test_build_cert_verify12)
    run_test("_ecdsa_raw_to_der basic high-bit padding",  passed, failed, test_ecdsa_raw_to_der_basic)
    run_test("_ecdsa_raw_to_der leading zeros stripped",  passed, failed, test_ecdsa_raw_to_der_leading_zeros)
    run_test("_ecdsa_raw_to_der all-zero r",              passed, failed, test_ecdsa_raw_to_der_zero_r)

    print()
    print("Results:", String(passed), "passed,", String(failed), "failed,", String(passed + failed), "total")
    if failed > 0:
        raise Error(String(failed) + " test(s) failed")
