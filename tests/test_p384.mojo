# ============================================================================
# test_p384.mojo — NIST P-384 ECDSA verification tests
# ============================================================================
# Test vectors generated with Python cryptography library (secp384r1).
#
# Private key: SHA-384("test p384 private key")
# Public key (97 bytes uncompressed):
#   0454f437d8a71a467d5b2a71fca0cbdef31209407690838f3402dd5e49b2e2b4aa
#   c1c10ca67e240ba318a3645eda0cec0e0846083adc6bbe9d0d4aac7efd53c38b4d
#   db45af99e1b3c6bb60446a2cf0a55dd1fd2f3f0663c95213614f81732ec691
#
# msg_hash: SHA-384("test message for p384")
# SIG_DER (from Python sign):
#   3065 0231 00892a7a...a69166 0230 09c1c5df...4128e
#
# CA cert: self-signed P-384, ecdsa-with-SHA384
# Leaf cert: P-384, signed by CA, ecdsa-with-SHA384
# ============================================================================

from crypto.p384 import p384_ecdsa_verify
from crypto.asn1 import asn1_parse_ecdsa_sig_48
from crypto.cert import X509Cert, cert_parse, cert_verify_sig


fn run_test(
    name: String,
    mut passed: Int,
    mut failed: Int,
    test_fn: fn () raises -> None,
):
    try:
        test_fn()
        print("  PASS:", name)
        passed += 1
    except e:
        print("  FAIL:", name, "-", String(e))
        failed += 1


fn hex_to_bytes(h: String) -> List[UInt8]:
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


fn bytes_to_hex(b: List[UInt8]) -> String:
    var digits = "0123456789abcdef".as_bytes()
    var result = List[UInt8](capacity=len(b) * 2)
    for i in range(len(b)):
        var byte = Int(b[i])
        result.append(digits[(byte >> 4) & 0xF])
        result.append(digits[byte & 0xF])
    return String(unsafe_from_utf8=result^)


# Test vectors
fn _pub_key() -> List[UInt8]:
    return hex_to_bytes("0454f437d8a71a467d5b2a71fca0cbdef31209407690838f3402dd5e49b2e2b4aac1c10ca67e240ba318a3645eda0cec0e0846083adc6bbe9d0d4aac7efd53c38b4ddb45af99e1b3c6bb60446a2cf0a55dd1fd2f3f0663c95213614f81732ec691")


fn _msg_hash() -> List[UInt8]:
    return hex_to_bytes("fb8549816cdeeae0e5fdbdd6482582a1fff50c9cb6477ba4664963fde15b5c3bc3a8e6733846c9dbed816fd4e1b813ca")


fn _sig_r() -> List[UInt8]:
    return hex_to_bytes("892a7a89ebf1617e577bc66f04e69f8be9ffea4019dfe52a53eea4765e9d10e9ef797b08072e7dd304ee733b39a69166")


fn _sig_s() -> List[UInt8]:
    return hex_to_bytes("09c1c5df8f650134aaeea41026305fcdfe5bbaa230fc58ff399bcade559aed9185483e3768e3a6099532cfaa3ae4128e")


fn _sig_der() -> List[UInt8]:
    return hex_to_bytes("3065023100892a7a89ebf1617e577bc66f04e69f8be9ffea4019dfe52a53eea4765e9d10e9ef797b08072e7dd304ee733b39a6916602300" + "9c1c5df8f650134aaeea41026305fcdfe5bbaa230fc58ff399bcade559aed9185483e3768e3a6099532cfaa3ae4128e")


fn _ca_der() -> List[UInt8]:
    return hex_to_bytes("308201573081dea003020102020101300a06082a8648ce3d04030330173115301306035504030c0c503338342054657374204341301e170d3234303130313030303030305a170d3330303130313030303030305a30173115301306035504030c0c5033383420546573742043413076301006072a8648ce3d020106052b8104002203620004d834ac99dc76453b53493faeb6dbcea73d62acb7562098224dc4e9f10082580b7202f5abb768ca10963c8cb42095ffc5974ea39b3b830b7de276c5ea193e41215848a553db3b5e1eb03a2328d66a19bcefe287399986d444565c3f013240f96b300a06082a8648ce3d0403030368003065023100845eba5e5515d5f1a61394fc0f9b0179dc032bb3dadfee41999b867238847fc45d9b77f883d601f8dab21ad4c1ec00300230237ca6592d53476e5d15b35f03e0188193cf57c5570effe80734681367f2c9806c101563e63436be19de1e2c0f8af930")


fn _leaf_der() -> List[UInt8]:
    return hex_to_bytes("308201773081ffa003020102020102300a06082a8648ce3d04030330173115301306035504030c0c503338342054657374204341301e170d3234303130313030303030305a170d3330303130313030303030305a30193117301506035504030c0e503338342054657374204c6561663076301006072a8648ce3d020106052b8104002203620004a28da960fae01205cf60f87ab7c94a0861f54187fe3f2d8eef06b9a22eb850257589baec9e980552bd474a65d3b8f30264f6c5911ee77e975637bb26c3ac430120ac161ccad1a7f4c56aaa1e1d8471a79b6defaa85853df919f5fe5fc87dca5aa31d301b30190603551d1104123010820e6c6561662e703338342e74657374300a06082a8648ce3d040303036700306402301c9e0b1c12cec18b40985af7555238000d7a7481ff1fca80465f181a6734471807c91ed755fe25766b2c05d8c7871bf602304be5934e36b7cfe86f1f7f8680af70be0f7c14dca4473d89dc6194f7f2cb392ad15afe6c57038bf37f3864ae017298ef")


# ── Test 1: p384_ecdsa_verify — valid signature ────────────────────────────

fn test_p384_ecdsa_verify_valid() raises:
    p384_ecdsa_verify(_pub_key(), _msg_hash(), _sig_r(), _sig_s())


# ── Test 2: p384_ecdsa_verify — bad signature (flip one byte in r) ─────────

fn test_p384_ecdsa_verify_bad_sig() raises:
    var r = _sig_r()
    r[0] = r[0] ^ 0xFF  # Corrupt first byte
    var raised = False
    try:
        p384_ecdsa_verify(_pub_key(), _msg_hash(), r, _sig_s())
    except:
        raised = True
    if not raised:
        raise Error("expected p384_ecdsa_verify to raise on bad signature, but it did not")


# ── Test 3: p384_ecdsa_verify — bad public key (not on curve) ──────────────

fn test_p384_ecdsa_verify_bad_key() raises:
    var pub = _pub_key()
    # Corrupt the Qx coordinate
    pub[10] = pub[10] ^ 0xFF
    var raised = False
    try:
        p384_ecdsa_verify(pub, _msg_hash(), _sig_r(), _sig_s())
    except:
        raised = True
    if not raised:
        raise Error("expected p384_ecdsa_verify to raise on bad public key, but it did not")


# ── Test 4: asn1_parse_ecdsa_sig_48 — 48-byte r and s from DER ─────────────

fn test_asn1_parse_ecdsa_sig_48() raises:
    var der = _sig_der()
    var res = asn1_parse_ecdsa_sig_48(der)
    var r = res[0].copy()
    var s = res[1].copy()
    if len(r) != 48:
        raise Error("expected 48-byte r, got " + String(len(r)))
    if len(s) != 48:
        raise Error("expected 48-byte s, got " + String(len(s)))
    # Verify r matches expected (without leading 00 sign byte)
    var expected_r = _sig_r()
    for i in range(48):
        if r[i] != expected_r[i]:
            raise Error("r[" + String(i) + "] mismatch: got " + String(Int(r[i])) + ", want " + String(Int(expected_r[i])))
    var expected_s = _sig_s()
    for i in range(48):
        if s[i] != expected_s[i]:
            raise Error("s[" + String(i) + "] mismatch: got " + String(Int(s[i])) + ", want " + String(Int(expected_s[i])))


# ── Test 5: cert_parse on P-384 cert → ec_curve == "p384" ──────────────────

fn test_cert_parse_p384() raises:
    var ca_der = _ca_der()
    var cert = cert_parse(ca_der)
    if cert.pub_key_alg != "ec":
        raise Error("expected pub_key_alg='ec', got '" + cert.pub_key_alg + "'")
    if cert.ec_curve != "p384":
        raise Error("expected ec_curve='p384', got '" + cert.ec_curve + "'")
    if len(cert.ec_point) != 97:
        raise Error("expected 97-byte ec_point, got " + String(len(cert.ec_point)))
    if cert.ec_point[0] != 0x04:
        raise Error("expected ec_point[0] == 0x04")
    if cert.sig_alg != "ecdsa":
        raise Error("expected sig_alg='ecdsa', got '" + cert.sig_alg + "'")
    if cert.sig_hash != "sha384":
        raise Error("expected sig_hash='sha384', got '" + cert.sig_hash + "'")


# ── Test 6: cert_verify_sig with P-384 issuer → passes ─────────────────────

fn test_cert_verify_sig_p384() raises:
    var ca_der   = _ca_der()
    var leaf_der = _leaf_der()
    var ca   = cert_parse(ca_der)
    var leaf = cert_parse(leaf_der)
    # Verify leaf cert signature against CA
    cert_verify_sig(leaf, ca)
    # Verify CA self-signed signature
    cert_verify_sig(ca, ca)


fn main() raises:
    var passed = 0
    var failed = 0

    print("=== P-384 Tests ===")
    print()

    run_test("p384_ecdsa_verify: valid signature",          passed, failed, test_p384_ecdsa_verify_valid)
    run_test("p384_ecdsa_verify: bad signature raises",     passed, failed, test_p384_ecdsa_verify_bad_sig)
    run_test("p384_ecdsa_verify: bad public key raises",    passed, failed, test_p384_ecdsa_verify_bad_key)
    run_test("asn1_parse_ecdsa_sig_48: 48-byte r and s",    passed, failed, test_asn1_parse_ecdsa_sig_48)
    run_test("cert_parse P-384 cert → ec_curve=p384",       passed, failed, test_cert_parse_p384)
    run_test("cert_verify_sig P-384 chain → passes",        passed, failed, test_cert_verify_sig_p384)

    print()
    print("Results:", passed, "passed,", failed, "failed")
    if failed > 0:
        raise Error(String(failed) + " test(s) failed")
