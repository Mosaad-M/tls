# ============================================================================
# test_cert.mojo — X.509 certificate parsing and verification tests
# ============================================================================
# Test vectors: self-signed RSA-2048 and EC P-256 certificates generated with
# the Python cryptography library.
# ============================================================================

from crypto.cert import X509Cert, cert_parse, cert_verify_sig


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
# RSA-2048 self-signed certificate  (sha256WithRSAEncryption)
# 675 bytes, generated with Python cryptography library
# ============================================================================

def _rsa_cert_der() raises -> List[UInt8]:
    return hex_to_bytes(
        "3082029f30820187a003020102020101300d06092a864886f70d01010b050030"
        "133111300f06035504030c085465737420525341301e170d3230303130313030"
        "303030305a170d3330303130313030303030305a30133111300f06035504030c"
        "08546573742052534130820122300d06092a864886f70d01010105000382010f"
        "003082010a0282010100afb9534ceda05e85566e1058cfa098995f9dd0de9583"
        "f4857cb6f2c2445cd3fc5785635f33070e3734703580e3fa05c16e994949a188"
        "678b1278e84497891cbda37bf8d12eaac2142a1808f890d99f2c70648e98f053"
        "7c10dc525fe728f1fc11690aef26d4bfb6c66907e03269e03cf87d861d02635b"
        "fe1b05036f2e888b3c6c35a3332a730da816a2bd46155e3afa9ca83bccbe8817"
        "9db697c484336be0e0286aab667b3f6c1bb58d70e107df37cc0f827391d90507"
        "229b288847f939478e7f9297f5d0bffc6a2c88600bf8066d55323d9c2b9aaf03"
        "e4894b6ad5ae9811368f40375343ee6897f84009ca2be0c7e88ed5f063d82193"
        "3ddf16a2b0fb2f5ced870203010001300d06092a864886f70d01010b05000382"
        "0101009f0b3af05e8ec94aa31482a0ab459e808c24c709b4f9c214c34d06f92a"
        "4fa7984d8e09e15a06f453992f06a6a2e5df43cf67445a00644a68a73de871a5"
        "77142882bee76111e32e6b5bc158d283911c98165e7795dee02343054a121357e"
        "eaffad0e051bbc1779b47c61d22b889fd16238f405c870148bc49bc99de1736ac"
        "5d18a8cc446ae5519d2304dc63338fbb00cc975a1f4cf5ceb837a79ad55dbde6"
        "41428ef2873101627671f96b9af45487dbd81e69e02f47aa9db7ce433a9915a9"
        "c91413d295961be8833a01433ee23822570c4052ae1859a589378e5b709b51002"
        "064ec3fb0d2f6520d65dcc9295e4130a859fac72ee977e32a9344d884e75c16f"
        "f5a"
    )


def _rsa_tampered_der() raises -> List[UInt8]:
    # Same cert but byte [-10] flipped: ...e32a... → ...e32b...
    return hex_to_bytes(
        "3082029f30820187a003020102020101300d06092a864886f70d01010b050030"
        "133111300f06035504030c085465737420525341301e170d3230303130313030"
        "303030305a170d3330303130313030303030305a30133111300f06035504030c"
        "08546573742052534130820122300d06092a864886f70d01010105000382010f"
        "003082010a0282010100afb9534ceda05e85566e1058cfa098995f9dd0de9583"
        "f4857cb6f2c2445cd3fc5785635f33070e3734703580e3fa05c16e994949a188"
        "678b1278e84497891cbda37bf8d12eaac2142a1808f890d99f2c70648e98f053"
        "7c10dc525fe728f1fc11690aef26d4bfb6c66907e03269e03cf87d861d02635b"
        "fe1b05036f2e888b3c6c35a3332a730da816a2bd46155e3afa9ca83bccbe8817"
        "9db697c484336be0e0286aab667b3f6c1bb58d70e107df37cc0f827391d90507"
        "229b288847f939478e7f9297f5d0bffc6a2c88600bf8066d55323d9c2b9aaf03"
        "e4894b6ad5ae9811368f40375343ee6897f84009ca2be0c7e88ed5f063d82193"
        "3ddf16a2b0fb2f5ced870203010001300d06092a864886f70d01010b05000382"
        "0101009f0b3af05e8ec94aa31482a0ab459e808c24c709b4f9c214c34d06f92a"
        "4fa7984d8e09e15a06f453992f06a6a2e5df43cf67445a00644a68a73de871a5"
        "77142882bee76111e32e6b5bc158d283911c98165e7795dee02343054a121357e"
        "eaffad0e051bbc1779b47c61d22b889fd16238f405c870148bc49bc99de1736ac"
        "5d18a8cc446ae5519d2304dc63338fbb00cc975a1f4cf5ceb837a79ad55dbde6"
        "41428ef2873101627671f96b9af45487dbd81e69e02f47aa9db7ce433a9915a9"
        "c91413d295961be8833a01433ee23822570c4052ae1859a589378e5b709b51002"
        "064ec3fb0d2f6520d65dcc9295e4130a859fac72ee977e32b9344d884e75c16f"
        "f5a"
    )


# ============================================================================
# EC P-256 self-signed certificate  (ecdsa-with-SHA256)
# 277 bytes, generated with Python cryptography library
# ============================================================================

def _ec_cert_der() raises -> List[UInt8]:
    return hex_to_bytes(
        "308201113081b7a003020102020101300a06082a8648ce3d04030230123110300e"
        "06035504030c0754657374204543301e170d3230303130313030303030305a170d"
        "3330303130313030303030305a30123110300e06035504030c075465737420454330"
        "59301306072a8648ce3d020106082a8648ce3d03010703420004a6eb197e543177a6"
        "c8947d0f6a29533d9203591fa6ebd740db5fcf5c7a685e7a9d0ac6b2bafc3c649c2"
        "b8d663ad11a20cc3a39932d8cd6f656e639a1433b762a300a06082a8648ce3d0403"
        "02034900304602210096affc03adb5350e1684328bba60c30130f906684b6df723aa"
        "b573247470a9ab022100fe77acaf96813a475833c64dce9f2c9261ec85fe14034f28"
        "5a9caa2c27bbb93f"
    )


def _ec_tampered_der() raises -> List[UInt8]:
    # Same cert but last r-byte flipped: ...caa2c... → ...caa2d...
    return hex_to_bytes(
        "308201113081b7a003020102020101300a06082a8648ce3d04030230123110300e"
        "06035504030c0754657374204543301e170d3230303130313030303030305a170d"
        "3330303130313030303030305a30123110300e06035504030c075465737420454330"
        "59301306072a8648ce3d020106082a8648ce3d03010703420004a6eb197e543177a6"
        "c8947d0f6a29533d9203591fa6ebd740db5fcf5c7a685e7a9d0ac6b2bafc3c649c2"
        "b8d663ad11a20cc3a39932d8cd6f656e639a1433b762a300a06082a8648ce3d0403"
        "02034900304602210096affc03adb5350e1684328bba60c30130f906684b6df723aa"
        "b573247470a9ab022100fe77acaf96813a475833c64dce9f2c9261ec85fe14034f28"
        "5a9caa2d27bbb93f"
    )


# ============================================================================
# Tests
# ============================================================================

def test_parse_rsa_cert() raises:
    var der = _rsa_cert_der()
    var cert = cert_parse(der)
    if cert.pub_key_alg != "rsa":
        raise Error("rsa_cert: expected pub_key_alg=rsa, got " + cert.pub_key_alg)
    if cert.sig_alg != "rsa":
        raise Error("rsa_cert: expected sig_alg=rsa, got " + cert.sig_alg)
    if len(cert.rsa_n) != 256:
        raise Error("rsa_cert: expected 256-byte modulus, got " + String(len(cert.rsa_n)))
    if len(cert.ec_point) != 0:
        raise Error("rsa_cert: ec_point should be empty for RSA cert")


def test_parse_ec_cert() raises:
    var der = _ec_cert_der()
    var cert = cert_parse(der)
    if cert.pub_key_alg != "ec":
        raise Error("ec_cert: expected pub_key_alg=ec, got " + cert.pub_key_alg)
    if cert.sig_alg != "ecdsa":
        raise Error("ec_cert: expected sig_alg=ecdsa, got " + cert.sig_alg)
    if len(cert.ec_point) != 65:
        raise Error("ec_cert: expected 65-byte EC point, got " + String(len(cert.ec_point)))
    if cert.ec_point[0] != 0x04:
        raise Error("ec_cert: EC point should start with 0x04")
    if len(cert.rsa_n) != 0:
        raise Error("ec_cert: rsa_n should be empty for EC cert")


def test_verify_rsa_self_signed() raises:
    var der = _rsa_cert_der()
    var cert = cert_parse(der)
    cert_verify_sig(cert, cert)


def test_verify_ec_self_signed() raises:
    var der = _ec_cert_der()
    var cert = cert_parse(der)
    cert_verify_sig(cert, cert)


def test_reject_tampered_rsa() raises:
    var der = _rsa_tampered_der()
    var cert = cert_parse(der)
    var raised = False
    try:
        cert_verify_sig(cert, cert)
    except:
        raised = True
    if not raised:
        raise Error("tampered_rsa: tampered cert should not verify")


def test_reject_tampered_ec() raises:
    var der = _ec_tampered_der()
    var cert = cert_parse(der)
    var raised = False
    try:
        cert_verify_sig(cert, cert)
    except:
        raised = True
    if not raised:
        raise Error("tampered_ec: tampered cert should not verify")


def main() raises:
    var passed = 0
    var failed = 0
    print("=== X.509 Certificate Tests ===")
    print()
    run_test("parse RSA-2048 cert",           passed, failed, test_parse_rsa_cert)
    run_test("parse EC P-256 cert",           passed, failed, test_parse_ec_cert)
    run_test("verify RSA self-signed cert",   passed, failed, test_verify_rsa_self_signed)
    run_test("verify EC self-signed cert",    passed, failed, test_verify_ec_self_signed)
    run_test("reject tampered RSA cert",      passed, failed, test_reject_tampered_rsa)
    run_test("reject tampered EC cert",       passed, failed, test_reject_tampered_ec)
    print()
    print("Results:", passed, "passed,", failed, "failed")
    if failed > 0:
        raise Error(String(failed) + " test(s) failed")
