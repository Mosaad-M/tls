# ============================================================================
# test_asn1.mojo — ASN.1 DER parser tests
# ============================================================================
# Test vectors generated with Python cryptography library.
# ============================================================================

from crypto.asn1 import (
    der_parse, der_raw_bytes, der_children, der_int_bytes, der_bit_str,
    der_oid_eq, asn1_parse_rsa_spki, asn1_parse_ec_spki, asn1_parse_ecdsa_sig,
    TAG_SEQUENCE, TAG_INTEGER, TAG_OID, TAG_BIT_STRING,
    OID_RSA_ENCRYPTION, OID_EC_PUBLIC_KEY,
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
# Low-level DER parsing
# ============================================================================

def test_parse_integer() raises:
    # DER: 02 03 01 00 01  → INTEGER 65537 = 0x10001 (3 bytes, no leading zero)
    # tag=02, len=03, value=010001
    var d = hex_to_bytes("0203010001")
    var res = der_parse(d, 0)
    if res[0] != 0x02:
        raise Error("parse_integer: wrong tag")
    var val = res[1].copy()
    if len(val) != 3 or val[0] != 0x01 or val[1] != 0x00 or val[2] != 0x01:
        raise Error("parse_integer: wrong value: " + bytes_to_hex(val))
    if res[2] != 5:
        raise Error("parse_integer: wrong next_offset")


def test_parse_sequence() raises:
    # DER: 30 06 02 01 01 02 01 02  → SEQUENCE { 1, 2 }
    var d = hex_to_bytes("3006020101020102")
    var res = der_parse(d, 0)
    if res[0] != 0x30:
        raise Error("parse_sequence: wrong tag")
    var children = der_children(res[1])
    if len(children) != 2:
        raise Error("parse_sequence: expected 2 children, got " + String(len(children)))
    if children[0].tag != 0x02 or children[1].tag != 0x02:
        raise Error("parse_sequence: children not INTEGERs")
    var v0 = der_int_bytes(children[0].content)
    var v1 = der_int_bytes(children[1].content)
    if v0[0] != 1 or v1[0] != 2:
        raise Error("parse_sequence: wrong integer values")


def test_long_form_length() raises:
    # DER with long-form length: 02 81 80 <128 bytes of 0xAB...>
    var d = List[UInt8](capacity=131)
    d.append(0x02)   # INTEGER tag
    d.append(0x81)   # long form: 1 length byte follows
    d.append(0x80)   # length = 128
    for _ in range(128):
        d.append(0xAB)
    var res = der_parse(d, 0)
    if res[0] != 0x02:
        raise Error("long_form: wrong tag")
    if len(res[1]) != 128:
        raise Error("long_form: wrong content length: " + String(len(res[1])))
    if res[2] != 131:
        raise Error("long_form: wrong next_offset")


def test_der_raw_bytes() raises:
    # 30 06 02 01 01 02 01 02 → raw bytes of whole element
    var d = hex_to_bytes("3006020101020102")
    var raw = der_raw_bytes(d, 0)
    assert_hex_eq(raw, "3006020101020102", "raw_bytes")


def test_bit_str() raises:
    # 03 05 00 04 03 02 01  → BIT STRING { 04 03 02 01 } (0 unused bits)
    var content = hex_to_bytes("000403020115")  # 0x00 = unused bits, then payload
    var content2 = List[UInt8]()
    content2.append(0x00)  # unused bits
    content2.append(0x04); content2.append(0x03); content2.append(0x02); content2.append(0x01)
    var payload = der_bit_str(content2)
    if len(payload) != 4 or payload[0] != 0x04:
        raise Error("bit_str: wrong payload")


def test_oid_eq() raises:
    # RSA OID: 2a864886f70d010101
    var oid_content = hex_to_bytes("2a864886f70d010101")
    if not der_oid_eq(oid_content, OID_RSA_ENCRYPTION):
        raise Error("oid_eq: RSA OID mismatch")
    # EC OID: 2a8648ce3d0201
    var ec_oid = hex_to_bytes("2a8648ce3d0201")
    if not der_oid_eq(ec_oid, OID_EC_PUBLIC_KEY):
        raise Error("oid_eq: EC OID mismatch")
    # Wrong OID should fail
    if der_oid_eq(oid_content, OID_EC_PUBLIC_KEY):
        raise Error("oid_eq: RSA OID should not match EC OID")


# ============================================================================
# RSA SubjectPublicKeyInfo parsing
# RSA-512 SPKI generated by Python cryptography library
# ============================================================================

def test_parse_rsa_spki() raises:
    # RSA-512 SubjectPublicKeyInfo DER (94 bytes)
    var der = hex_to_bytes(
        "305c300d06092a864886f70d010101050003"
        "4b003048024100ae15fd2917d0d3e1456843"
        "92d46ddec7637c1c306799672fa10e0ca5d3"
        "ca7a0d8d7d608b7d4b1b70f821a83a07f9da"
        "1393963f6237a88358211ac2875b1fd7d502"
        "03010001"
    )
    var res = asn1_parse_rsa_spki(der)
    var n_bytes = res[0].copy()
    var e_bytes = res[1].copy()
    # Expected n and e
    assert_hex_eq(
        n_bytes,
        "ae15fd2917d0d3e145684392d46ddec7637c1c306799672fa10e0ca5d3ca7a0d8d7d608b7d4b1b70f821a83a07f9da1393963f6237a88358211ac2875b1fd7d5",
        "rsa_n",
    )
    # e = 65537 = 010001 (3 bytes, leading zero stripped)
    assert_hex_eq(e_bytes, "010001", "rsa_e")


# ============================================================================
# EC SubjectPublicKeyInfo parsing
# EC P-256 SPKI generated by Python cryptography library
# ============================================================================

def test_parse_ec_spki() raises:
    # EC P-256 SubjectPublicKeyInfo DER (91 bytes)
    var der = hex_to_bytes(
        "3059301306072a8648ce3d020106082a8648"
        "ce3d03010703420004a8409a5d47d767f80d"
        "551678ebe254c3f62c4902de2348a8357b15"
        "e3c25dbf207cce98f3872876a8fdfddb2277"
        "986297318e439123ffda71af50f4240404d0bb"
    )
    var point = asn1_parse_ec_spki(der)
    if len(point) != 65 or point[0] != 0x04:
        raise Error("ec_spki: wrong point format")
    # Check Qx and Qy
    var qx = List[UInt8](capacity=32)
    var qy = List[UInt8](capacity=32)
    for i in range(32): qx.append(point[1 + i])
    for i in range(32): qy.append(point[33 + i])
    assert_hex_eq(
        qx,
        "a8409a5d47d767f80d551678ebe254c3f62c4902de2348a8357b15e3c25dbf20",
        "ec_qx",
    )
    assert_hex_eq(
        qy,
        "7cce98f3872876a8fdfddb2277986297318e439123ffda71af50f4240404d0bb",
        "ec_qy",
    )


# ============================================================================
# ECDSA DER signature parsing
# ============================================================================

def test_parse_ecdsa_sig() raises:
    # ECDSA DER sig (70 bytes)
    var der = hex_to_bytes(
        "304402207cf871d679ccc3812646d6f1bde88b"
        "c166bdb8f205d6e3f50a9c0db04996d4eb022"
        "0524de8b4f578aff345ffe8761472b63256edd"
        "c1c4d9999fa3da4f6bcf9b5741b"
    )
    var res = asn1_parse_ecdsa_sig(der)
    var r = res[0].copy()
    var s = res[1].copy()
    assert_hex_eq(
        r,
        "7cf871d679ccc3812646d6f1bde88bc166bdb8f205d6e3f50a9c0db04996d4eb",
        "ecdsa_r",
    )
    assert_hex_eq(
        s,
        "524de8b4f578aff345ffe8761472b63256eddc1c4d9999fa3da4f6bcf9b5741b",
        "ecdsa_s",
    )


def main() raises:
    var passed = 0
    var failed = 0
    print("=== ASN.1 DER Parser Tests ===")
    print()
    run_test("parse INTEGER TLV",         passed, failed, test_parse_integer)
    run_test("parse SEQUENCE with children", passed, failed, test_parse_sequence)
    run_test("long-form length encoding", passed, failed, test_long_form_length)
    run_test("der_raw_bytes",             passed, failed, test_der_raw_bytes)
    run_test("BIT STRING payload",        passed, failed, test_bit_str)
    run_test("OID comparison",            passed, failed, test_oid_eq)
    run_test("RSA SubjectPublicKeyInfo",  passed, failed, test_parse_rsa_spki)
    run_test("EC SubjectPublicKeyInfo",   passed, failed, test_parse_ec_spki)
    run_test("ECDSA DER signature",       passed, failed, test_parse_ecdsa_sig)
    print()
    print("Results:", passed, "passed,", failed, "failed")
    if failed > 0:
        raise Error(String(failed) + " test(s) failed")
