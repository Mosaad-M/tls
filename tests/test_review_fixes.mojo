# ============================================================================
# test_review_fixes.mojo — regressions for the October 2026 security review
# ============================================================================
# Each test reproduces a finding against tls 1.5.0 (crafted input that was
# accepted, crashed the process, or was mis-handled) and checks the fix.
# Vectors are built independently (Python, OpenSSL); see the comments.
# ============================================================================

from crypto.cert import cert_parse, _parse_asn1_time
from crypto.asn1 import asn1_parse_ecdsa_sig, asn1_parse_ecdsa_sig_48, asn1_parse_ec_spki
from crypto.rsa import rsa_pkcs1_verify, rsa_pss_verify
from path_fixtures import LEAF_OK
from tls.message import (
    parse_server_hello, build_client_hello, validate_encrypted_extensions,
    parse_certificate_chain, parse_hello_retry_request, GROUP_X25519,
)
from tls.message12 import parse_server_hello_version
from tls.connection import tls_handle_incoming_alert
from crypto.record import record_seal, record_open, CIPHER_AES_128_GCM, CTYPE_APPLICATION_DATA


def run_test[test_fn: def() thin raises -> None](
    name: String,
    mut passed: Int,
    mut failed: Int,
):
    try:
        test_fn()
        print("  PASS:", name)
        passed += 1
    except e:
        print("  FAIL:", name, "-", String(e))
        failed += 1


def _unhex(h: String) -> List[UInt8]:
    var raw = h.as_bytes()
    var out = List[UInt8](capacity=len(raw) // 2)
    for i in range(0, len(raw) - 1, 2):
        var hi = raw[i]
        var lo = raw[i + 1]
        var a: UInt8 = (hi - 48) if hi <= 57 else (hi - 87)
        var b: UInt8 = (lo - 48) if lo <= 57 else (lo - 87)
        out.append((a << 4) | b)
    return out^


def _bytes(s: String) -> List[UInt8]:
    var out = List[UInt8]()
    for b in s.as_bytes():
        out.append(b)
    return out^


def _cert_rejected(der: List[UInt8], why: String) raises:
    var message = String()
    try:
        _ = cert_parse(der)
    except e:
        message = String(e)
    if message.byte_length() == 0:
        raise Error("certificate accepted, expected rejection (" + why + ")")
    if message.find(why) < 0:
        raise Error("rejected for the wrong reason: '" + message + "' (expected '" + why + "')")


# ── X.509 / DER parsing ─────────────────────────────────────────────────────

comptime CRASH_CERT = "3081633052a003020102020101300a06082a8648ce3d0403023000301e170d3235303130313030303030305a170d3335303130313030303030305a30003018301306072a8648ce3d020106082a8648ce3d030107030100300a06082a8648ce3d040302030100"


def test_empty_ec_point_rejected() raises:
    # Reviewer's 105-byte certificate: EC SPKI BIT STRING 03 01 00 (no
    # point). tls 1.5.0 aborted the process here, before any trust check.
    # (It also uses non-minimal lengths, which are now rejected first.)
    var raised = False
    try:
        _ = cert_parse(_unhex(CRASH_CERT))
    except:
        raised = True
    if not raised:
        raise Error("crash certificate accepted")
    # The same empty point in a minimally encoded SubjectPublicKeyInfo
    var message = String()
    try:
        _ = asn1_parse_ec_spki(_unhex("3018301306072a8648ce3d020106082a8648ce3d030107030100"))
    except e:
        message = String(e)
    if message.find("empty public point") < 0:
        raise Error("empty EC point: '" + message + "'")


def test_trailing_bytes_rejected() raises:
    var der = _unhex(LEAF_OK)
    der.append(0)
    _cert_rejected(der, "trailing")


def test_non_minimal_length_rejected() raises:
    # 30 82 01 c9 ... re-encoded as 30 83 00 01 c9 (same length, 3 bytes)
    var der = _unhex(LEAF_OK)
    if der[1] != 0x82:
        raise Error("fixture layout changed")
    var out = List[UInt8]()
    out.append(0x30)
    out.append(0x83)
    out.append(0x00)
    for i in range(2, len(der)):
        out.append(der[i])
    _cert_rejected(out, "non-minimal")


def test_tbs_signature_algorithm_mismatch_rejected() raises:
    # Change the TBS copy of ecdsa-with-SHA256 (…040302) to …040303; the
    # outer signatureAlgorithm still says SHA-256.
    var der = _unhex(LEAF_OK)
    var oid = _unhex("2a8648ce3d040302")
    var done = False
    for i in range(len(der) - len(oid)):
        var hit = True
        for j in range(len(oid)):
            if der[i + j] != oid[j]:
                hit = False
                break
        if hit:
            der[i + len(oid) - 1] = 0x03
            done = True
            break
    if not done:
        raise Error("OID not found")
    _cert_rejected(der, "signatureAlgorithm")


comptime P521_CERT = "3082020b3082016ca0030201020214322ff21b027f8d607a55d64d393604c50f60e5ce300a06082a8648ce3d04030230173115301306035504030c0c703532312e6578616d706c65301e170d3236313030353233313231355a170d3336313030323233313231355a30173115301306035504030c0c703532312e6578616d706c6530819b301006072a8648ce3d020106052b81040023038186000401c8c9edd52a7582ef0da8a094e844a710e3a0e82781174ccf319d28133cb5bb45f126e53cd8ee59fec93782e86b1e56dbb5bc5d6db0f070646e2e3e6219a1bfc5960022e29b6c2629d467c34d754322a1b5eef24e2757c355a26fde4636bd937bfe1c33bc1b88dc0965ac66e9b07f2d2b17eb079c8cbe4ad0d4b0e9d0008a70fc0610afa3533051301d0603551d0e04160414664ccbaf884e3d4b642cc041fe2dd5c840c7ae48301f0603551d23041830168014664ccbaf884e3d4b642cc041fe2dd5c840c7ae48300f0603551d130101ff040530030101ff300a06082a8648ce3d04030203818c00308188024200b3ba2c39b34a27324fc3fb1d601cff7589fb373a5946103eb9cb59817bdbb45a075caca9e8048c1dd35babf88d1d431aed5ba2195d4223631bd5c67d378476b686024200d70c32328f7e0e0eeb36ac468b5f0d5818b26d447822981459fa1bf0a91d187bf172095fadd3490361d94267db498885f5358b3071e7dc3e544c5574f5a7e4b875"


def test_unknown_curve_rejected() raises:
    # secp521r1 key (openssl ecparam -name secp521r1): 1.5.0 labelled any
    # unknown curve "p256".
    _cert_rejected(_unhex(P521_CERT), "curve")


def _time_rejected(s: String) raises:
    var raised = False
    try:
        _ = _parse_asn1_time(_bytes(s), False)
    except:
        raised = True
    if not raised:
        raise Error("accepted invalid date " + s)


def test_impossible_dates_rejected() raises:
    _time_rejected("250231000000Z")   # 31 February
    _time_rejected("250229000000Z")   # 29 February 2025 (not a leap year)
    _time_rejected("250431000000Z")   # 31 April
    _ = _parse_asn1_time(_bytes("240229000000Z"), False)  # leap day is fine


# ── ECDSA signature encoding ────────────────────────────────────────────────

def _ecdsa_der(r: List[UInt8], s: List[UInt8]) -> List[UInt8]:
    var out = List[UInt8]()
    out.append(0x30)
    out.append(UInt8(4 + len(r) + len(s)))
    out.append(0x02)
    out.append(UInt8(len(r)))
    for i in range(len(r)):
        out.append(r[i])
    out.append(0x02)
    out.append(UInt8(len(s)))
    for i in range(len(s)):
        out.append(s[i])
    return out^


def _filled(n: Int, v: UInt8) -> List[UInt8]:
    var out = List[UInt8]()
    for _ in range(n):
        out.append(v)
    return out^


def _sig_rejected(r: List[UInt8], s: List[UInt8], what: String) raises:
    var raised = False
    try:
        _ = asn1_parse_ecdsa_sig(_ecdsa_der(r, s))
    except:
        raised = True
    if not raised:
        raise Error("accepted " + what)


def test_ecdsa_integer_encoding_strict() raises:
    var good = _filled(32, 0x11)
    _ = asn1_parse_ecdsa_sig(_ecdsa_der(good, good))
    var long_r = _filled(33, 0x11)          # 1.5.0 kept the last 32 bytes
    _sig_rejected(long_r, good, "a 33-byte r")
    var neg: List[UInt8] = [0x80, 0x01]     # negative INTEGER
    _sig_rejected(neg, good, "a negative r")
    var padded: List[UInt8] = [0x00, 0x01]  # non-minimal: 00 before < 0x80
    _sig_rejected(padded, good, "a non-minimal r")
    _sig_rejected(List[UInt8](), good, "an empty r")


# ── RSA strictness (e = 1 keys: the signature equals the encoded message;
#    vectors computed in Python) ─────────────────────────────────────────────

comptime HASH = "c97ace4c8fef2cee8fa0f3c9f52aab18dbd4f42438afe362ffb8f75ce4c04b84"
comptime PKCS1_N = "80000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000001"
comptime PKCS1_EM = "0001ffffffffffffffffffff003031300d060960864801650304020105000420c97ace4c8fef2cee8fa0f3c9f52aab18dbd4f42438afe362ffb8f75ce4c04b84"
comptime PKCS1_EM_PLUS_N = "8001ffffffffffffffffffff003031300d060960864801650304120105000420c97ace4c8fef2cee8fa0f3c9f52aab18dbd4f42438afe362ffb8f75ce4c04b85"
comptime PSS_N = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff97"
comptime PSS_GOOD = "57c8cac199938cc6c0067dc8dbe6b2450715b36f20cac6272d3f8f6ee39d8986494a10d4622629cc459530d76f9e14f80bf212eace22873ab02cdc70446808a4f76b87eb8b83c388447233112e687f3a5d9915ded52d2c4c98e199cfeb3b7d5871cb0b59e243f592ff72a4b23b53617252382a1215e10249ffd5756264103fbc"
comptime PSS_TOPBIT = "d7c8cac199938cc6c0067dc8dbe6b2450715b36f20cac6272d3f8f6ee39d8986494a10d4622629cc459530d76f9e14f80bf212eace22873ab02cdc70446808a4f76b87eb8b83c388447233112e687f3a5d9915ded52d2c4c98e199cfeb3b7d5871cb0b59e243f592ff72a4b23b53617252382a1215e10249ffd5756264103fbc"


def test_rsa_signature_not_below_modulus() raises:
    var one: List[UInt8] = [1]
    rsa_pkcs1_verify(_unhex(PKCS1_N), one, _unhex(HASH), _unhex(PKCS1_EM))
    var raised = False
    try:
        # s + n: same value mod n, a second encoding of one signature
        rsa_pkcs1_verify(_unhex(PKCS1_N), one, _unhex(HASH), _unhex(PKCS1_EM_PLUS_N))
    except:
        raised = True
    if not raised:
        raise Error("PKCS#1 signature s >= n accepted")


def test_rsa_pss_top_bits_checked() raises:
    var one: List[UInt8] = [1]
    rsa_pss_verify(_unhex(PSS_N), one, _unhex(HASH), _unhex(PSS_GOOD), 32)
    var raised = False
    try:
        # the leftmost 8*emLen - emBits bits of maskedDB must be zero
        rsa_pss_verify(_unhex(PSS_N), one, _unhex(HASH), _unhex(PSS_TOPBIT), 32)
    except:
        raised = True
    if not raised:
        raise Error("PSS encoding with the top bit set accepted")


# ── ServerHello / HRR / EncryptedExtensions / Certificate strictness ──────

def _sh(version: UInt16, cipher: UInt16, compression: UInt8, exts: List[UInt8], trailing: Bool = False) -> List[UInt8]:
    var b = List[UInt8]()
    b.append(UInt8(version >> 8))
    b.append(UInt8(version & 0xFF))
    for i in range(32):
        b.append(UInt8(i + 1))
    b.append(0)  # session_id
    b.append(UInt8(cipher >> 8))
    b.append(UInt8(cipher & 0xFF))
    b.append(compression)
    b.append(UInt8(len(exts) >> 8))
    b.append(UInt8(len(exts) & 0xFF))
    for i in range(len(exts)):
        b.append(exts[i])
    if trailing:
        b.append(0)
    return b^


def _rejected[f: def() thin raises -> None](what: String) raises:
    var raised = False
    try:
        f()
    except:
        raised = True
    if not raised:
        raise Error(what + " accepted")


def _v13() -> List[UInt8]:
    return [0x00, 0x2B, 0x00, 0x02, 0x03, 0x04]


def _sh_compression() raises:
    _ = parse_server_hello_version(_sh(0x0303, 0xC02B, 1, List[UInt8]()))

def _sh_legacy_version() raises:
    _ = parse_server_hello_version(_sh(0x0302, 0xC02B, 0, List[UInt8]()))

def _sh_versions_not_13() raises:
    var e: List[UInt8] = [0x00, 0x2B, 0x00, 0x02, 0x03, 0x03]
    _ = parse_server_hello_version(_sh(0x0303, 0x1301, 0, e))

def _sh_unsolicited_13() raises:
    var e = _v13()
    for b in [0x00, 0x10, 0x00, 0x00]:
        e.append(UInt8(b))
    _ = parse_server_hello_version(_sh(0x0303, 0x1301, 0, e))

def _sh_cipher_not_offered() raises:
    _ = parse_server_hello_version(_sh(0x0303, 0x0000, 0, List[UInt8]()))

def _sh_trailing() raises:
    _ = parse_server_hello_version(_sh(0x0303, 0xC02B, 0, List[UInt8](), True))


def test_server_hello_strict() raises:
    # tls 1.5.0 accepted every one of these
    _rejected[_sh_compression]("compression method 1")
    _rejected[_sh_legacy_version]("legacy_version 0x0302")
    _rejected[_sh_versions_not_13]("supported_versions = TLS 1.2 (silent fallback)")
    _rejected[_sh_unsolicited_13]("unsolicited ALPN in a TLS 1.3 ServerHello")
    _rejected[_sh_cipher_not_offered]("a cipher suite never offered")
    _rejected[_sh_trailing]("bytes after the extensions")
    # still fine: TLS 1.2 with an empty server_name acknowledgement and EMS
    var ok: List[UInt8] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x17, 0x00, 0x00]
    _ = parse_server_hello_version(_sh(0x0303, 0xC02B, 0, ok))


def test_cookie_only_hrr_accepted() raises:
    # stateless servers may send only a cookie (1.5.0 rejected this)
    var r: List[UInt8] = [0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
                          0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C]
    var e: List[UInt8] = [0x00, 0x2B, 0x00, 0x02, 0x03, 0x04, 0x00, 0x2C, 0x00, 0x05, 0x00, 0x03, 0x61, 0x62, 0x63]
    var b: List[UInt8] = [0x03, 0x03]
    for i in range(32):
        b.append(r[i])
    for x in [0x00, 0x13, 0x01, 0x00]:
        b.append(UInt8(x))
    b.append(0)
    b.append(UInt8(len(e)))
    for i in range(len(e)):
        b.append(e[i])
    var hrr = parse_hello_retry_request(b)
    if hrr.selected_group != GROUP_X25519 or len(hrr.cookie) != 3:
        raise Error("cookie-only HRR fields wrong")


def _ee(exts: List[UInt8]) -> List[UInt8]:
    var b = List[UInt8]()
    b.append(UInt8(len(exts) >> 8))
    b.append(UInt8(len(exts) & 0xFF))
    for i in range(len(exts)):
        b.append(exts[i])
    return b^


def _alpn_h2() -> List[UInt8]:
    return [0x00, 0x10, 0x00, 0x05, 0x00, 0x03, 0x02, 0x68, 0x32]  # ALPN "h2"


def _ee_alpn_not_offered() raises:
    _ = validate_encrypted_extensions(_ee(_alpn_h2()), List[String]())

def _ee_forbidden_key_share() raises:
    var e: List[UInt8] = [0x00, 0x33, 0x00, 0x00]
    _ = validate_encrypted_extensions(_ee(e), List[String]())

def _ee_alpn_other() raises:
    var offered = List[String]()
    offered.append("http/1.1")
    _ = validate_encrypted_extensions(_ee(_alpn_h2()), offered)


def test_encrypted_extensions_strict() raises:
    var offered = List[String]()
    offered.append("h2")
    offered.append("http/1.1")
    if validate_encrypted_extensions(_ee(_alpn_h2()), offered) != "h2":
        raise Error("offered ALPN not returned")
    _rejected[_ee_alpn_not_offered]("ALPN when none was offered")
    _rejected[_ee_forbidden_key_share]("key_share in EncryptedExtensions")
    _rejected[_ee_alpn_other]("an ALPN protocol not in the offer")


def _cert_ctx() raises:
    var b: List[UInt8] = [0x01, 0x07, 0x00, 0x00, 0x06, 0x00, 0x00, 0x01, 0xAA, 0x00, 0x00]
    _ = parse_certificate_chain(b)

def _cert_trailing() raises:
    var b: List[UInt8] = [0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x01, 0xAA, 0x00, 0x00, 0xFF]
    _ = parse_certificate_chain(b)


def test_certificate_message_strict() raises:
    var ok: List[UInt8] = [0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x01, 0xAA, 0x00, 0x00]
    if len(parse_certificate_chain(ok)) != 1:
        raise Error("valid Certificate message rejected")
    _rejected[_cert_ctx]("a non-empty certificate_request_context")
    _rejected[_cert_trailing]("bytes after the certificate list")


def _long_inner() raises:
    var key = List[UInt8]()
    for _ in range(16):
        key.append(1)
    var iv = List[UInt8]()
    for _ in range(12):
        iv.append(2)
    var big = List[UInt8]()
    for _ in range(16385):  # + content type = 16386 > 2^14 + 1
        big.append(0x41)
    _ = record_open(CIPHER_AES_128_GCM, key, iv, 0, record_seal(CIPHER_AES_128_GCM, key, iv, 0, CTYPE_APPLICATION_DATA, big))

def _long_alert() raises:
    var a: List[UInt8] = [2, 40, 0]
    tls_handle_incoming_alert(a)


def test_record_and_alert_limits() raises:
    _rejected[_long_inner]("a TLS 1.3 record with 2^14 + 2 inner bytes")
    var message = String()
    try:
        _long_alert()
    except e:
        message = String(e)
    if message.find("decode_error") < 0:
        raise Error("a 3-byte alert gave '" + message + "'")


def test_no_sni_for_ip_literals() raises:
    var key = List[UInt8]()
    for _ in range(32):
        key.append(9)
    var rnd = List[UInt8]()
    for _ in range(32):
        rnd.append(3)
    var with_sni = build_client_hello(rnd, List[UInt8](), key, "example.com")
    var no_sni = build_client_hello(rnd, List[UInt8](), key, "192.0.2.1")
    var no_sni6 = build_client_hello(rnd, List[UInt8](), key, "2001:db8::1")
    if len(no_sni) >= len(with_sni) or len(no_sni6) >= len(with_sni):
        raise Error("server_name sent for an IP literal")


def main() raises:
    var passed = 0
    var failed = 0
    print("=== Security review regressions ===")
    print()
    run_test[test_empty_ec_point_rejected]("EC key with an empty point: clean error, no crash", passed, failed)
    run_test[test_trailing_bytes_rejected]("certificate with trailing bytes rejected", passed, failed)
    run_test[test_non_minimal_length_rejected]("non-minimal DER length rejected", passed, failed)
    run_test[test_tbs_signature_algorithm_mismatch_rejected]("TBS/outer signatureAlgorithm mismatch rejected", passed, failed)
    run_test[test_unknown_curve_rejected]("unsupported curve (P-521) rejected", passed, failed)
    run_test[test_impossible_dates_rejected]("impossible validity dates rejected", passed, failed)
    run_test[test_ecdsa_integer_encoding_strict]("ECDSA r/s must be minimal positive INTEGERs", passed, failed)
    run_test[test_rsa_signature_not_below_modulus]("RSA signature s >= n rejected", passed, failed)
    run_test[test_rsa_pss_top_bits_checked]("RSA-PSS top bits of maskedDB checked", passed, failed)
    run_test[test_server_hello_strict]("ServerHello validated strictly", passed, failed)
    run_test[test_cookie_only_hrr_accepted]("cookie-only HelloRetryRequest accepted", passed, failed)
    run_test[test_encrypted_extensions_strict]("EncryptedExtensions / ALPN validated", passed, failed)
    run_test[test_certificate_message_strict]("Certificate message parsed strictly", passed, failed)
    run_test[test_record_and_alert_limits]("record_overflow and alert length", passed, failed)
    run_test[test_no_sni_for_ip_literals]("no SNI for IP literals", passed, failed)
    print()
    print("Results:", passed, "passed,", failed, "failed")
    if failed > 0:
        raise Error(String(failed) + " test(s) failed")
