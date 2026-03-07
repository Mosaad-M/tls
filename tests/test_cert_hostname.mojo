# ============================================================================
# test_cert_hostname.mojo — SAN / hostname matching tests
# ============================================================================
# Test certificates generated with Python cryptography library.
#
# SAN cert: SANs = ["example.com", "*.example.com", "other.net"]
#   Subject CN = "example.com"
#
# CN-only cert: no SAN extension, Subject CN = "cn-only.example.com"
# ============================================================================

from crypto.cert import cert_parse, cert_san_names, cert_hostname_match


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


# SAN cert DER (Python-generated; SANs: example.com, *.example.com, other.net)
comptime SAN_CERT_HEX = "3082014e3081f5a003020102020101300a06082a8648ce3d04030230163114301206035504030c0b6578616d706c652e636f6d301e170d3235303130313030303030305a170d3236303130313030303030305a30163114301206035504030c0b6578616d706c652e636f6d3059301306072a8648ce3d020106082a8648ce3d0301070342000485b67cf153d6303cbcc1468b8f6fbd82cb95bf91f3a12eb3f6b2e2cdd063a4dfc94497687d4b7a4578dce03d0c59feda412ee4ef4d4ab2390e3ab9b1a2c644a3a334303230300603551d1104293027820b6578616d706c652e636f6d820d2a2e6578616d706c652e636f6d82096f746865722e6e6574300a06082a8648ce3d0403020348003045022100a5fa4f1c9b9a340606f64bb8c2e3921132cc1ff367b9c372abd3a110efbbe71302203890eff2d6fe71c545f255c9975b9cb2d0291745295c79fe4ae8ffe4a62c5e21"

# CN-only cert DER (Python-generated; CN = "cn-only.example.com", no SAN)
comptime CN_ONLY_CERT_HEX = "308201283081cfa003020102020102300a06082a8648ce3d040302301e311c301a06035504030c13636e2d6f6e6c792e6578616d706c652e636f6d301e170d3235303130313030303030305a170d3236303130313030303030305a301e311c301a06035504030c13636e2d6f6e6c792e6578616d706c652e636f6d3059301306072a8648ce3d020106082a8648ce3d03010703420004a1e27298e2188564a7e2a6d4db545bfc9870219ed9a6c0eb3a486f36c68e1fb073c78adbed42f6b73e8bdf808a911901f487510804200b9bdba3fbbe30a98710300a06082a8648ce3d0403020348003045022100cc7ecf0cdfcf893170c889843cf103c552f588985c30abab7e39f287da40586002205a2a19095826f5820785b00d41192ea5e41be43ad2b12e257fce8c6623bd074d"


# ── Tests ─────────────────────────────────────────────────────────────────────

fn test_san_names() raises:
    var der = hex_to_bytes(SAN_CERT_HEX)
    var cert = cert_parse(der)
    var names = cert_san_names(cert)
    if len(names) != 3:
        raise Error("expected 3 SAN names, got " + String(len(names)))
    if names[0] != "example.com":
        raise Error("SAN[0] wrong: " + names[0])
    if names[1] != "*.example.com":
        raise Error("SAN[1] wrong: " + names[1])
    if names[2] != "other.net":
        raise Error("SAN[2] wrong: " + names[2])


fn test_match_exact() raises:
    var der = hex_to_bytes(SAN_CERT_HEX)
    var cert = cert_parse(der)
    cert_hostname_match(cert, "example.com")  # should not raise


fn test_match_wildcard() raises:
    var der = hex_to_bytes(SAN_CERT_HEX)
    var cert = cert_parse(der)
    cert_hostname_match(cert, "foo.example.com")  # should not raise


fn test_match_other() raises:
    var der = hex_to_bytes(SAN_CERT_HEX)
    var cert = cert_parse(der)
    cert_hostname_match(cert, "other.net")  # should not raise


fn test_no_match_two_subdomains() raises:
    var der = hex_to_bytes(SAN_CERT_HEX)
    var cert = cert_parse(der)
    var raised = False
    try:
        cert_hostname_match(cert, "bar.foo.example.com")
    except:
        raised = True
    if not raised:
        raise Error("expected raise for bar.foo.example.com (two subdomains)")


fn test_no_match_evil() raises:
    var der = hex_to_bytes(SAN_CERT_HEX)
    var cert = cert_parse(der)
    var raised = False
    try:
        cert_hostname_match(cert, "evil.com")
    except:
        raised = True
    if not raised:
        raise Error("expected raise for evil.com")


fn test_cn_only_fallback() raises:
    var der = hex_to_bytes(CN_ONLY_CERT_HEX)
    var cert = cert_parse(der)
    # No SAN → should fall back to CN = "cn-only.example.com"
    var names = cert_san_names(cert)
    if len(names) != 1:
        raise Error("CN-only cert: expected 1 name, got " + String(len(names)))
    if names[0] != "cn-only.example.com":
        raise Error("CN-only cert: expected 'cn-only.example.com', got '" + names[0] + "'")
    cert_hostname_match(cert, "cn-only.example.com")  # should not raise


fn main() raises:
    var passed = 0
    var failed = 0

    print("=== Cert SAN / Hostname Tests ===")
    print()

    run_test("cert_san_names returns 3 entries", passed, failed, test_san_names)
    run_test("hostname_match: exact match", passed, failed, test_match_exact)
    run_test("hostname_match: wildcard match", passed, failed, test_match_wildcard)
    run_test("hostname_match: other.net", passed, failed, test_match_other)
    run_test("hostname_match: 2-subdomain raises", passed, failed, test_no_match_two_subdomains)
    run_test("hostname_match: evil.com raises", passed, failed, test_no_match_evil)
    run_test("CN-only fallback", passed, failed, test_cn_only_fallback)

    print()
    print("Results:", passed, "passed,", failed, "failed")
    if failed > 0:
        raise Error(String(failed) + " test(s) failed")
