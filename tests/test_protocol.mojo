# ============================================================================
# test_protocol.mojo — TLS 1.2 PRF/EMS/RI, ServerKeyExchange ECDSA, HRR
# ============================================================================
# Known answers computed independently with Python hmac/hashlib; ECDSA
# fixtures signed with OpenSSL (`openssl dgst -sha256|-sha384 -sign`).
# End-to-end coverage of the same features: tests/interop.sh.
# ============================================================================

from crypto.prf import tls12_master_secret, tls12_extended_master_secret
from crypto.hash import sha256, sha384
from crypto.cert import cert_parse
from tls.connection12 import _verify_ske_signature
from tls.message12 import parse_server_hello_tls12_exts
from tls.message import (
    build_client_hello, is_hello_retry_request, parse_hello_retry_request,
    hrr_message_hash, GROUP_SECP256R1, GROUP_SECP384R1,
)


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


def _expect(got: List[UInt8], want_hex: String, what: String) raises:
    var want = _unhex(want_hex)
    if len(got) != len(want):
        raise Error(what + ": length " + String(len(got)))
    for i in range(len(want)):
        if got[i] != want[i]:
            raise Error(what + ": mismatch at byte " + String(i))


def _has(data: List[UInt8], pattern: List[UInt8]) -> Bool:
    for i in range(len(data) - len(pattern) + 1):
        var ok = True
        for j in range(len(pattern)):
            if data[i + j] != pattern[j]:
                ok = False
                break
        if ok:
            return True
    return False


# ── TLS 1.2 master secret ───────────────────────────────────────────────────

def _pms() -> List[UInt8]:
    var out = List[UInt8]()
    for i in range(48):
        out.append(UInt8(i))
    return out^


def _randoms() -> Tuple[List[UInt8], List[UInt8]]:
    var cr = List[UInt8]()
    var sr = List[UInt8]()
    for i in range(32):
        cr.append(UInt8(0xA0 + i % 16))
        sr.append(UInt8(0x50 + i % 16))
    return (cr^, sr^)


def test_master_secret_prf_hash() raises:
    # RFC 5246 §5: the PRF hash is the suite's, SHA-384 for *_SHA384 suites
    var r = _randoms()
    _expect(tls12_master_secret(_pms(), r[0], r[1], False),
        "2c5fb3eb4ff8d958aaf74451d9ad1ad5853512c014b0bbc37382ad89cd79a36bb025118144fe4233bb68cd955250836f", "SHA-256 master secret")
    _expect(tls12_master_secret(_pms(), r[0], r[1], True),
        "877eacf9ef5659304d3452bfb9587b210b12c47f089bfc1035b9ac9e61d8d42062cd659a13825c6fa7ffc0f48e5c351f", "SHA-384 master secret")


def test_extended_master_secret() raises:
    # RFC 7627 §4: PRF(pms, "extended master secret", session_hash)
    _expect(tls12_extended_master_secret(_pms(), sha256(_bytes("session")), False),
        "eea7b66e5e5f150058446032d53e77cccec702ed4b60d8819d14fba01fad489ea6d77974be08ee8f08601609696ef529", "SHA-256 extended master secret")
    _expect(tls12_extended_master_secret(_pms(), sha384(_bytes("session")), True),
        "69811dc3271b811a6995c5558f569b3d5ec206b18b583222a254eacbe69110eed1727c295e3eb4c21365b9b907dbf3fe", "SHA-384 extended master secret")


# ── TLS 1.2 ServerHello extensions ──────────────────────────────────────────

def _server_hello12(exts: List[UInt8]) -> List[UInt8]:
    var b = List[UInt8]()
    b.append(0x03)
    b.append(0x03)
    for i in range(32):
        b.append(UInt8(i))
    b.append(0)        # session_id length
    b.append(0xC0)
    b.append(0x2B)     # ECDHE-ECDSA-AES128-GCM-SHA256
    b.append(0)        # compression
    b.append(UInt8(len(exts) >> 8))
    b.append(UInt8(len(exts) & 0xFF))
    for i in range(len(exts)):
        b.append(exts[i])
    return b^


def test_ems_and_ri_parsing() raises:
    var ems_ri: List[UInt8] = [0x00, 0x17, 0x00, 0x00, 0xFF, 0x01, 0x00, 0x01, 0x00]
    if not parse_server_hello_tls12_exts(_server_hello12(ems_ri)):
        raise Error("EMS not detected")
    var ri_only: List[UInt8] = [0xFF, 0x01, 0x00, 0x01, 0x00]
    if parse_server_hello_tls12_exts(_server_hello12(ri_only)):
        raise Error("EMS detected without the extension")
    if parse_server_hello_tls12_exts(_server_hello12(List[UInt8]())):
        raise Error("EMS detected with no extensions")


def test_nonempty_ri_rejected() raises:
    var raised = False
    try:
        var ext: List[UInt8] = [0xFF, 0x01, 0x00, 0x0D, 0x0C]
        for i in range(12):
            ext.append(UInt8(i))
        _ = parse_server_hello_tls12_exts(_server_hello12(ext))
    except:
        raised = True
    if not raised:
        raise Error("non-empty renegotiation_info accepted")


# ── ServerKeyExchange ECDSA: curve from the certificate, hash from the scheme

comptime P256_CERT = "308201873082012da003020102021478dc3ffbdfe611d2c00b4c1c4479f5e8266e5abf300a06082a8648ce3d04030230193117301506035504030c0e736b652d7072696d653235367631301e170d3236313030353132333735315a170d3336313030323132333735315a30193117301506035504030c0e736b652d7072696d6532353676313059301306072a8648ce3d020106082a8648ce3d030107034200044fc7187766c0f2507eb6c6ac49d36093eaa7f0e3472ab8bc3da4836845e21d4ca043278caa53a77ebc0a189d6e2f7aae3b734b7b348617ed7358c6375bd9e090a3533051301d0603551d0e041604146ced992d281d710b0b79ba725fc0c760a0781ac9301f0603551d230418301680146ced992d281d710b0b79ba725fc0c760a0781ac9300f0603551d130101ff040530030101ff300a06082a8648ce3d0403020348003045022016cfdc291b48de29ea22cc2e6ea4010ef2cc04574368fead5cd0e073535773c8022100a4cba0f396537e0b4994b0a1e779eb07c4412ae41de6814169b1c7edfed73004"
comptime P384_CERT = "308201c230820148a00302010202143a7632665e56c47c3f6b6243ddb356a63af170a0300a06082a8648ce3d04030230183116301406035504030c0d736b652d736563703338347231301e170d3236313030353132333735315a170d3336313030323132333735315a30183116301406035504030c0d736b652d7365637033383472313076301006072a8648ce3d020106052b81040022036200041026c592151267b893aae4cde9c9c161f1fddce2fd76f97121e7e8e46f42f44b71055c858e2a060846723e13934895879f72f0499a8eac0aa58b4ff7a588825c56e63d04d85b83880524c94957458b5ba8b34c4a5bd2e18d5238c1f905eab8eca3533051301d0603551d0e041604147131030008542e2d3ccc90be21ca81ad5d84cf17301f0603551d230418301680147131030008542e2d3ccc90be21ca81ad5d84cf17300f0603551d130101ff040530030101ff300a06082a8648ce3d0403020368003065023100d06b01f5356077dc257541f1fc198015281fce159354f6d0a783e048ce296c974ffbb060198509ee9bada4990b6c40ba02301902656013d7d551333f2c2456a54d42de63edd1518a2e057e8284e9a3afa045822850b56c6faaf21a72f69d9ca533a7"
comptime SIG_P384_SHA256 = "3065023100aa7a2502ff6d9d45dd3d3ba6fe858d2aa32f9c13d09cd1a53168309a9cd96d22e39212fff441e27b0b902f950552c28002303c76e6296a81cc037ec48636d2f9eb4923e0c0b3ad9e3b1c83937e7b0545b04ab8f58f6a0fab2fdc5da75a096b36b8a0"
comptime SIG_P256_SHA384 = "3045022100cb3b8c2c179bff861b8841a772c547339e5ffbfe671873189744d25ca6d28ec2022008ec9b0b89b3ff452a7059b9c1ac5eb0b2b68872c2553ecaa48089a27b885318"


def test_ske_p384_key_sha256() raises:
    # TLS 1.2 scheme (sha256, ecdsa) signed with a P-384 key
    _verify_ske_signature(cert_parse(_unhex(P384_CERT)), 4, 3, _unhex(SIG_P384_SHA256),
                          _bytes("server key exchange params"))


def test_ske_p256_key_sha384() raises:
    # (sha384, ecdsa) with a P-256 key: the hash is truncated to 256 bits
    _verify_ske_signature(cert_parse(_unhex(P256_CERT)), 5, 3, _unhex(SIG_P256_SHA384),
                          _bytes("server key exchange params"))


def test_ske_tampered_rejected() raises:
    var raised = False
    try:
        _verify_ske_signature(cert_parse(_unhex(P384_CERT)), 4, 3, _unhex(SIG_P384_SHA256),
                              _bytes("server key exchange paramz"))
    except:
        raised = True
    if not raised:
        raise Error("signature over different data accepted")


# ── HelloRetryRequest ───────────────────────────────────────────────────────

def _hrr_random() -> List[UInt8]:
    return _unhex("cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c")


def _hrr(exts: List[UInt8], cipher: UInt16 = 0x1301) -> List[UInt8]:
    var b = List[UInt8]()
    b.append(0x03)
    b.append(0x03)
    var r = _hrr_random()
    for i in range(32):
        b.append(r[i])
    b.append(0)
    b.append(UInt8(cipher >> 8))
    b.append(UInt8(cipher & 0xFF))
    b.append(0)
    b.append(UInt8(len(exts) >> 8))
    b.append(UInt8(len(exts) & 0xFF))
    for i in range(len(exts)):
        b.append(exts[i])
    return b^


def test_hrr_detection_and_parsing() raises:
    if not is_hello_retry_request(_hrr_random()):
        raise Error("HRR random not recognised")
    var other = _hrr_random()
    other[31] ^= 1
    if is_hello_retry_request(other):
        raise Error("ordinary random taken for an HRR")
    # supported_versions 0304, key_share secp256r1, cookie "abc"
    var exts: List[UInt8] = [0x00, 0x2B, 0x00, 0x02, 0x03, 0x04,
                             0x00, 0x33, 0x00, 0x02, 0x00, 0x17,
                             0x00, 0x2C, 0x00, 0x05, 0x00, 0x03, 0x61, 0x62, 0x63]
    var hrr = parse_hello_retry_request(_hrr(exts))
    if hrr.selected_group != GROUP_SECP256R1 or hrr.cipher_suite != 0x1301 or len(hrr.cookie) != 3:
        raise Error("HRR fields wrong")
    var exts384: List[UInt8] = [0x00, 0x2B, 0x00, 0x02, 0x03, 0x04, 0x00, 0x33, 0x00, 0x02, 0x00, 0x18]
    if parse_hello_retry_request(_hrr(exts384)).selected_group != GROUP_SECP384R1:
        raise Error("HRR to secp384r1 not parsed")


def _reject_hrr(exts: List[UInt8], cipher: UInt16, what: String) raises:
    var raised = False
    try:
        _ = parse_hello_retry_request(_hrr(exts, cipher))
    except:
        raised = True
    if not raised:
        raise Error(what + " accepted")


def test_hrr_validation() raises:
    # asks for X25519, the group we already sent
    _reject_hrr([0x00, 0x2B, 0x00, 0x02, 0x03, 0x04, 0x00, 0x33, 0x00, 0x02, 0x00, 0x1D], 0x1301, "HRR selecting X25519")
    # no supported_versions
    _reject_hrr([0x00, 0x33, 0x00, 0x02, 0x00, 0x17], 0x1301, "HRR without supported_versions")
    # TLS 1.2 cipher suite
    _reject_hrr([0x00, 0x2B, 0x00, 0x02, 0x03, 0x04, 0x00, 0x33, 0x00, 0x02, 0x00, 0x17], 0xC02B, "HRR with a TLS 1.2 suite")
    # an extension the client never offered
    _reject_hrr([0x00, 0x2B, 0x00, 0x02, 0x03, 0x04, 0x00, 0x33, 0x00, 0x02, 0x00, 0x17, 0x00, 0x10, 0x00, 0x00], 0x1301, "HRR with ALPN")


def test_hrr_message_hash() raises:
    var ch: List[UInt8] = [1, 0, 0, 5, 1, 2, 3, 4, 5]
    _expect(hrr_message_hash(ch, False), "fe000020ff87bca65cc32b44b8ee1b74e0db7ed92e0e6ed09ba0074729ca1012bc8f521a", "message_hash SHA-256")
    _expect(hrr_message_hash(ch, True), "fe00003059ed22df1273cf56d12d71cea6320393ccb0fddee6e411427b412a33ca153dd61fe3f0ee5d6115800a71ee7a2daf759b", "message_hash SHA-384")


# ── ClientHello contents ────────────────────────────────────────────────────

def test_client_hello_extensions() raises:
    var key = List[UInt8]()
    for _ in range(32):
        key.append(9)
    var ch = build_client_hello(_randoms()[0], List[UInt8](), key, "example.com")
    var ems: List[UInt8] = [0x00, 0x17, 0x00, 0x00]
    var ri: List[UInt8] = [0xFF, 0x01, 0x00, 0x01, 0x00]
    var p384_sig: List[UInt8] = [0x05, 0x03]
    var dsa_sig: List[UInt8] = [0x05, 0x02]
    var groups: List[UInt8] = [0x00, 0x0A, 0x00, 0x08, 0x00, 0x06, 0x00, 0x1D, 0x00, 0x17, 0x00, 0x18]
    if not _has(ch, ems):
        raise Error("no extended_master_secret extension")
    if not _has(ch, ri):
        raise Error("no empty renegotiation_info extension")
    if not _has(ch, p384_sig):
        raise Error("ecdsa_secp384r1_sha384 (0x0503) not offered")
    if _has(ch, dsa_sig):
        raise Error("0x0502 (DSA) still offered")
    if not _has(ch, groups):
        raise Error("supported_groups is not x25519, secp256r1, secp384r1")
    # second ClientHello after HRR: P-256 key share and the cookie
    var p256_key = List[UInt8]()
    p256_key.append(4)
    for _ in range(64):
        p256_key.append(7)
    var cookie: List[UInt8] = [0x61, 0x62, 0x63]
    var ch2 = build_client_hello(_randoms()[0], List[UInt8](), p256_key, "example.com",
                                 List[String](), GROUP_SECP256R1, cookie)
    var ks_head: List[UInt8] = [0x00, 0x33, 0x00, 0x47, 0x00, 0x45, 0x00, 0x17, 0x00, 0x41, 0x04]
    var cookie_ext: List[UInt8] = [0x00, 0x2C, 0x00, 0x05, 0x00, 0x03, 0x61, 0x62, 0x63]
    if not _has(ch2, ks_head):
        raise Error("ClientHello2 lacks the secp256r1 key share")
    if not _has(ch2, cookie_ext):
        raise Error("ClientHello2 lacks the cookie")


def main() raises:
    var passed = 0
    var failed = 0
    print("=== Protocol tests (EMS, RI, PRF, ECDSA SKE, HRR) ===")
    print()
    run_test[test_master_secret_prf_hash]("TLS 1.2 master secret uses the suite's PRF hash", passed, failed)
    run_test[test_extended_master_secret]("extended master secret (SHA-256/384)", passed, failed)
    run_test[test_ems_and_ri_parsing]("ServerHello EMS / renegotiation_info parsing", passed, failed)
    run_test[test_nonempty_ri_rejected]("non-empty renegotiation_info rejected", passed, failed)
    run_test[test_ske_p384_key_sha256]("SKE: P-384 key, SHA-256 signature", passed, failed)
    run_test[test_ske_p256_key_sha384]("SKE: P-256 key, SHA-384 signature", passed, failed)
    run_test[test_ske_tampered_rejected]("SKE: signature over other data rejected", passed, failed)
    run_test[test_hrr_detection_and_parsing]("HRR detection and parsing", passed, failed)
    run_test[test_hrr_validation]("HRR validation rejects bad retries", passed, failed)
    run_test[test_hrr_message_hash]("HRR message_hash transcript entry", passed, failed)
    run_test[test_client_hello_extensions]("ClientHello: EMS, RI, 0x0503, groups, HRR key share + cookie", passed, failed)
    print()
    print("Results:", passed, "passed,", failed, "failed")
    if failed > 0:
        raise Error(String(failed) + " test(s) failed")
