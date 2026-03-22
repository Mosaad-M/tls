# ============================================================================
# test_message12.mojo — Tests for TLS 1.2 message parsers/builders
# ============================================================================

from tls.message import build_client_hello, CIPHER_TLS_AES_128_GCM_SHA256
from tls.message12 import (
    parse_server_hello_version,
    parse_server_key_exchange,
    parse_server_hello_done,
    build_client_key_exchange,
    build_change_cipher_spec_body,
    build_finished_body,
    parse_finished_body,
    TLS12_ECDHE_RSA_AES128_GCM_SHA256,
    NAMED_CURVE_X25519,
)


def make_bytes(value: UInt8, count: Int) -> List[UInt8]:
    var out = List[UInt8](capacity=count)
    for i in range(count):
        out.append(value)
    return out^


def contains_u16(data: List[UInt8], value: UInt16) -> Bool:
    """Check if data contains the 2-byte big-endian value anywhere."""
    var hi = UInt8(value >> 8)
    var lo = UInt8(value & 0xFF)
    for i in range(len(data) - 1):
        if data[i] == hi and data[i + 1] == lo:
            return True
    return False


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


# ── build_client_hello tests ───────────────────────────────────────────────

def test_ch_includes_tls12_suite() raises:
    """build_client_hello now includes 0xC02F (TLS_ECDHE_RSA_AES128_GCM_SHA256)."""
    var random   = make_bytes(0x01, 32)
    var key_share = make_bytes(0x02, 32)
    var ch = build_client_hello(random, List[UInt8](), key_share, "example.com")
    if not contains_u16(ch, 0xC02F):
        raise Error("0xC02F not found in ClientHello cipher_suites")


def test_ch_supported_versions_includes_tls12() raises:
    """build_client_hello supported_versions extension includes 0x0303 (TLS 1.2)."""
    var random   = make_bytes(0x01, 32)
    var key_share = make_bytes(0x02, 32)
    var ch = build_client_hello(random, List[UInt8](), key_share, "example.com")
    if not contains_u16(ch, 0x0303):
        raise Error("0x0303 (TLS 1.2) not found in ClientHello")


# ── parse_server_hello_version tests ─────────────────────────────────────

def _build_server_hello_tls13() -> List[UInt8]:
    """Build a TLS 1.3 ServerHello body (has supported_versions = 0x0304)."""
    var body = List[UInt8]()
    # legacy_version = 0x0303
    body.append(0x03)
    body.append(0x03)
    # random = 32 zeros
    for i in range(32):
        body.append(0x00)
    # session_id_len = 0
    body.append(0x00)
    # cipher_suite = 0x1301
    body.append(0x13)
    body.append(0x01)
    # compression = 0x00
    body.append(0x00)

    # Build extensions
    var exts = List[UInt8]()
    # supported_versions: type=0x002b, len=2, value=0x0304
    exts.append(0x00); exts.append(0x2b)  # type
    exts.append(0x00); exts.append(0x02)  # len
    exts.append(0x03); exts.append(0x04)  # TLS 1.3
    # key_share: type=0x0033, len=36, group=x25519, key_len=32, key=0x01*32
    exts.append(0x00); exts.append(0x33)  # type
    exts.append(0x00); exts.append(0x24)  # len = 36
    exts.append(0x00); exts.append(0x1d)  # group = x25519
    exts.append(0x00); exts.append(0x20)  # key_len = 32
    for i in range(32):
        exts.append(0x01)

    # Append extensions length + extensions to body
    body.append(UInt8(len(exts) >> 8))
    body.append(UInt8(len(exts) & 0xFF))
    for i in range(len(exts)):
        body.append(exts[i])
    return body^


def _build_server_hello_tls12() -> List[UInt8]:
    """Build a TLS 1.2 ServerHello body (no supported_versions ext)."""
    var body = List[UInt8]()
    # legacy_version = 0x0303
    body.append(0x03)
    body.append(0x03)
    # random = 32 bytes of 0x01
    for i in range(32):
        body.append(0x01)
    # session_id_len = 0
    body.append(0x00)
    # cipher_suite = 0xC02F
    body.append(0xC0)
    body.append(0x2F)
    # compression = 0x00
    body.append(0x00)
    # extensions_len = 0 (no extensions)
    body.append(0x00)
    body.append(0x00)
    return body^


def test_parse_server_hello_version_tls13() raises:
    """parse_server_hello_version: TLS 1.3 ServerHello → use_tls13=True."""
    var body = _build_server_hello_tls13()
    var result = parse_server_hello_version(body)
    var use_tls13 = result[3]
    var cipher    = result[0]
    if not use_tls13:
        raise Error("expected use_tls13=True for TLS 1.3 ServerHello")
    if cipher != 0x1301:
        raise Error("expected cipher 0x1301, got " + String(Int(cipher)))


def test_parse_server_hello_version_tls12() raises:
    """parse_server_hello_version: TLS 1.2 ServerHello (no sup_ver ext) → use_tls13=False."""
    var body = _build_server_hello_tls12()
    var result = parse_server_hello_version(body)
    var use_tls13 = result[3]
    var cipher    = result[0]
    if use_tls13:
        raise Error("expected use_tls13=False for TLS 1.2 ServerHello")
    if cipher != 0xC02F:
        raise Error("expected cipher 0xC02F, got " + String(Int(cipher)))


# ── parse_server_key_exchange tests ──────────────────────────────────────

def _build_ske() -> List[UInt8]:
    """Build a fake ServerKeyExchange: curve_type=3, x25519, RSA sig."""
    var body = List[UInt8]()
    body.append(0x03)        # curve_type = named_curve
    body.append(0x00)        # named_curve hi
    body.append(0x1d)        # named_curve lo = x25519
    body.append(0x20)        # pubkey_len = 32
    for i in range(32):
        body.append(0x02)    # pubkey bytes = 0x02
    body.append(0x04)        # sig_hash = SHA-256
    body.append(0x01)        # sig_sig = RSA
    body.append(0x00)        # sig_len hi
    body.append(0x10)        # sig_len lo = 16
    for i in range(16):
        body.append(0x03)    # sig bytes = 0x03
    return body^


def test_parse_server_key_exchange_x25519_rsa() raises:
    """parse_server_key_exchange: x25519 pubkey + RSA sig extracted correctly."""
    var body = _build_ske()
    var result = parse_server_key_exchange(body)
    var named_curve = result[0]
    var pubkey      = result[1].copy()
    var sig_hash    = result[2]
    var sig_sig     = result[3]
    var sig_bytes   = result[4].copy()

    if named_curve != NAMED_CURVE_X25519:
        raise Error("expected x25519 group, got " + String(Int(named_curve)))
    if len(pubkey) != 32:
        raise Error("expected 32-byte pubkey, got " + String(len(pubkey)))
    if pubkey[0] != 0x02:
        raise Error("expected pubkey[0]=0x02")
    if sig_hash != 4:
        raise Error("expected sig_hash=4 (SHA-256), got " + String(Int(sig_hash)))
    if sig_sig != 1:
        raise Error("expected sig_sig=1 (RSA), got " + String(Int(sig_sig)))
    if len(sig_bytes) != 16:
        raise Error("expected 16-byte sig, got " + String(len(sig_bytes)))
    if sig_bytes[0] != 0x03:
        raise Error("expected sig_bytes[0]=0x03")


def test_parse_server_key_exchange_truncated() raises:
    """parse_server_key_exchange: truncated body raises."""
    var body = List[UInt8]()
    body.append(0x03)  # curve_type only — too short
    var raised = False
    try:
        _ = parse_server_key_exchange(body)
    except:
        raised = True
    if not raised:
        raise Error("expected raise for truncated body")


# ── build_client_key_exchange test ────────────────────────────────────────

def test_build_client_key_exchange() raises:
    """build_client_key_exchange: 1-byte length prefix + key bytes."""
    var pubkey = make_bytes(0x04, 32)
    var cke = build_client_key_exchange(pubkey)
    if len(cke) != 33:
        raise Error("expected 33 bytes, got " + String(len(cke)))
    if cke[0] != 32:
        raise Error("expected length prefix 32, got " + String(Int(cke[0])))
    for i in range(32):
        if cke[1 + i] != 0x04:
            raise Error("expected 0x04 at key byte " + String(i))


# ── build_finished_body / parse_finished_body roundtrip ──────────────────

def test_finished_body_roundtrip() raises:
    """build_finished_body + parse_finished_body roundtrip."""
    var verify_data = make_bytes(0x05, 12)
    var body = build_finished_body(verify_data)
    # Should be: 0x14 + 3-byte length + 12 bytes = 16 bytes total
    if len(body) != 16:
        raise Error("expected 16-byte Finished body, got " + String(len(body)))
    if body[0] != 0x14:
        raise Error("expected type 0x14, got " + String(Int(body[0])))
    var parsed = parse_finished_body(body)
    if len(parsed) != 12:
        raise Error("expected 12-byte verify_data, got " + String(len(parsed)))
    for i in range(12):
        if parsed[i] != 0x05:
            raise Error("verify_data mismatch at byte " + String(i))


def main() raises:
    var passed = 0
    var failed = 0

    print("=== TLS 1.2 Message Tests ===")
    print()

    run_test("build_client_hello: includes 0xC02F", passed, failed, test_ch_includes_tls12_suite)
    run_test("build_client_hello: supported_versions includes TLS 1.2", passed, failed, test_ch_supported_versions_includes_tls12)
    run_test("parse_server_hello_version: TLS 1.3 → use_tls13=True", passed, failed, test_parse_server_hello_version_tls13)
    run_test("parse_server_hello_version: TLS 1.2 → use_tls13=False", passed, failed, test_parse_server_hello_version_tls12)
    run_test("parse_server_key_exchange: x25519+RSA fields extracted", passed, failed, test_parse_server_key_exchange_x25519_rsa)
    run_test("parse_server_key_exchange: truncated body raises", passed, failed, test_parse_server_key_exchange_truncated)
    run_test("build_client_key_exchange: length prefix + key", passed, failed, test_build_client_key_exchange)
    run_test("build/parse_finished_body roundtrip", passed, failed, test_finished_body_roundtrip)

    print()
    print("Results:", passed, "passed,", failed, "failed")
    if failed > 0:
        raise Error(String(failed) + " test(s) failed")
