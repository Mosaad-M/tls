# ============================================================================
# test_connection.mojo — TLS 1.3 handshake integration tests
# ============================================================================
# Tests the full client handshake against a local Python TLS 1.3 server.
# Certificates generated with Python cryptography library (ECDSA P-256 / SHA-256).
# ============================================================================

from std.ffi import external_call
from std.memory import alloc
from crypto.cert import X509Cert, cert_parse
from crypto.record import CIPHER_AES_128_GCM
from tls.connection import tls13_client_handshake, TlsKeys


# ── Test certificate constants ─────────────────────────────────────────────
# CA (self-signed, TLS Test CA, ECDSA P-256)
comptime CA_DER_HEX = "3082018130820127a003020102021473b219db4dacd566136d712a9fc09cda8f5a50c2300a06082a8648ce3d04030230163114301206035504030c0b544c532054657374204341301e170d3236303931373133343032345a170d3331303931373133343032345a30163114301206035504030c0b544c5320546573742043413059301306072a8648ce3d020106082a8648ce3d03010703420004817e79ec91a4dc46ddbce8c40d9a574d1d6fdc4b14fe09eef893005bf0491cc90a94949a5be09350677082ed75a571c3f2d5925a7b24e83a3056a54eec918ff6a3533051301d0603551d0e041604149e33d94c2566681719b896baeeb843b1a05e8447301f0603551d230418301680149e33d94c2566681719b896baeeb843b1a05e8447300f0603551d130101ff040530030101ff300a06082a8648ce3d040302034800304502202cffda36351d36271e8aca505babcc18bfb636b3ec933bc87305bad0f839154b022100fb148e777f40b849417900b9f9eabef582560e5796ea8c9dfb3237ab4c612f52"


# ── Helpers ────────────────────────────────────────────────────────────────

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


def _tcp_connect(port: Int) raises -> Int32:
    """Open a TCP connection to 127.0.0.1:port."""
    var AF_INET: Int32 = 2
    var SOCK_STREAM: Int32 = 1
    var fd = external_call["socket", Int32](AF_INET, SOCK_STREAM, Int32(0))
    if fd < 0:
        raise Error("socket() failed")
    var addr = alloc[UInt8](16)
    for i in range(16):
        addr[unsafe_offset=i] = 0
    addr[unsafe_offset=0] = 2                              # AF_INET low byte
    addr[unsafe_offset=1] = 0                              # AF_INET high byte
    addr[unsafe_offset=2] = UInt8((port >> 8) & 0xFF)      # sin_port high
    addr[unsafe_offset=3] = UInt8(port & 0xFF)             # sin_port low
    addr[unsafe_offset=4] = 127                            # 127.0.0.1
    addr[unsafe_offset=5] = 0
    addr[unsafe_offset=6] = 0
    addr[unsafe_offset=7] = 1
    var ret = external_call["connect", Int32](fd, addr, Int32(16))
    addr.unsafe_free()
    if ret < 0:
        _ = external_call["close", Int32](fd)
        raise Error("connect() failed to 127.0.0.1:" + String(port))
    return fd


def _run_server(port: Int, certfile: String, keyfile: String):
    """Spawn a background Python TLS test server."""
    var cmd = (
        String("python3 tests/tls_test_server.py ")
        + String(port)
        + String(" ")
        + certfile
        + String(" ")
        + keyfile
        + String(" &")
    )
    _ = external_call["system", Int32]((cmd + String("\0")).unsafe_ptr())


def _kill_server(port: Int):
    """Kill the test server for the given port."""
    var cmd = (
        String("pkill -f 'tls_test_server.py ")
        + String(port)
        + String("'")
    )
    _ = external_call["system", Int32]((cmd + String("\0")).unsafe_ptr())


def _make_trust_anchors() raises -> List[X509Cert]:
    var anchors = List[X509Cert]()
    anchors.append(cert_parse(hex_to_bytes(CA_DER_HEX)))
    return anchors^


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


# ── Tests ──────────────────────────────────────────────────────────────────

def test_handshake_success() raises:
    """Full TLS 1.3 handshake with a valid localhost certificate."""
    _run_server(14443, "tests/server.pem", "tests/server.key")
    _ = external_call["usleep", Int32](UInt32(1000000))  # 1s startup wait
    var fd = _tcp_connect(14443)
    var anchors = _make_trust_anchors()
    var _keys = tls13_client_handshake(fd, "localhost", anchors, CIPHER_AES_128_GCM)
    _ = external_call["close", Int32](fd)
    _kill_server(14443)


def test_hostname_mismatch() raises:
    """Handshake raises when server cert SAN doesn't match requested hostname."""
    _run_server(14444, "tests/wronghost.pem", "tests/wronghost.key")
    _ = external_call["usleep", Int32](UInt32(1000000))  # 1s startup wait
    var fd = _tcp_connect(14444)
    var anchors = _make_trust_anchors()
    var raised = False
    try:
        var _keys = tls13_client_handshake(fd, "localhost", anchors, CIPHER_AES_128_GCM)
    except:
        raised = True
    _ = external_call["close", Int32](fd)
    _kill_server(14444)
    if not raised:
        raise Error("expected raise for hostname mismatch (cert SAN: wronghost.com)")


def main() raises:
    var passed = 0
    var failed = 0

    print("=== TLS Connection Tests ===")
    print()

    run_test[test_handshake_success]("TLS 1.3 handshake with localhost cert", passed, failed)
    run_test[test_hostname_mismatch]("hostname mismatch cert raises", passed, failed)

    print()
    print("Results:", passed, "passed,", failed, "failed")
    if failed > 0:
        raise Error(String(failed) + " test(s) failed")
