# ============================================================================
# test_connection12.mojo — TLS 1.2 + version-negotiation integration tests
# ============================================================================
# Tests the full TLS 1.2 client handshake against a local Python server.
# Reuses the same ECDSA P-256 test certificates as test_connection.mojo.
# ============================================================================

from std.ffi import external_call
from std.memory import alloc
from crypto.cert import X509Cert, cert_parse
from tls.connection12 import tls12_client_handshake, TlsKeys12
from tls.socket import TlsSocket
from crypto.hash import SHA256, SHA384


# ── Test certificate constants ─────────────────────────────────────────────
# Same CA as test_connection.mojo (ECDSA P-256, self-signed)
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
    addr[unsafe_offset=0] = 2
    addr[unsafe_offset=1] = 0
    addr[unsafe_offset=2] = UInt8((port >> 8) & 0xFF)
    addr[unsafe_offset=3] = UInt8(port & 0xFF)
    addr[unsafe_offset=4] = 127
    addr[unsafe_offset=5] = 0
    addr[unsafe_offset=6] = 0
    addr[unsafe_offset=7] = 1
    var ret = external_call["connect", Int32](fd, addr, Int32(16))
    addr.unsafe_free()
    if ret < 0:
        _ = external_call["close", Int32](fd)
        raise Error("connect() failed to 127.0.0.1:" + String(port))
    return fd


def _run_server(port: Int, certfile: String, keyfile: String, max_conns: Int = 1):
    """Spawn a background Python TLS 1.2 test server."""
    var cmd = (
        String("python3 tests/tls12_test_server.py ")
        + String(port)
        + String(" ")
        + certfile
        + String(" ")
        + keyfile
        + String(" ")
        + String(max_conns)
        + String(" &")
    )
    _ = external_call["system", Int32]((cmd + String("\0")).unsafe_ptr())


def _run_tls13_server(port: Int, certfile: String, keyfile: String):
    """Spawn a background Python TLS 1.3 test server."""
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
    var cmd = String("pkill -f 'test.*server.py ") + String(port) + String("'")
    _ = external_call["system", Int32]((cmd + String("\0")).unsafe_ptr())


def _make_trust_anchors() raises -> List[X509Cert]:
    var anchors = List[X509Cert]()
    anchors.append(cert_parse(hex_to_bytes(CA_DER_HEX)))
    return anchors^


def bytes_equal(a: List[UInt8], b: List[UInt8]) -> Bool:
    if len(a) != len(b):
        return False
    for i in range(len(a)):
        if a[i] != b[i]:
            return False
    return True


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

def test_tls12_handshake_success() raises:
    """Full TLS 1.2 handshake with ECDSA P-256 cert → succeeds."""
    _run_server(14445, "tests/server.pem", "tests/server.key")
    _ = external_call["usleep", Int32](UInt32(800000))
    var fd = _tcp_connect(14445)
    var anchors = _make_trust_anchors()
    var tls = TlsSocket(fd)
    tls.connect("localhost", anchors)
    _ = external_call["close", Int32](fd)
    _kill_server(14445)


def test_tls12_send_recv_roundtrip() raises:
    """TLS 1.2: send HTTP request, recv response, verify content."""
    _run_server(14446, "tests/server.pem", "tests/server.key")
    _ = external_call["usleep", Int32](UInt32(800000))
    var fd = _tcp_connect(14446)
    var anchors = _make_trust_anchors()
    var tls = TlsSocket(fd)
    tls.connect("localhost", anchors)

    # Send a simple HTTP request
    var req_str = String("GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")
    var req_raw = req_str.as_bytes()
    var req = List[UInt8](capacity=len(req_raw))
    for i in range(len(req_raw)):
        req.append(req_raw[i])
    _ = tls.send(req)

    # Read response
    var response = tls.recv_all()
    if not tls.close_notify_received():
        raise Error("recv_all returned without an authenticated close_notify")

    try:
        tls.close()
    except:
        pass
    _kill_server(14446)

    if len(response) < 15:
        raise Error("response too short: " + String(len(response)))
    # Should start with "HTTP/1.1 200 OK"
    var expected_prefix = String("HTTP/1.1 200 OK")
    var prefix_raw = expected_prefix.as_bytes()
    for i in range(len(prefix_raw)):
        if i >= len(response) or response[i] != prefix_raw[i]:
            raise Error("response does not start with HTTP/1.1 200 OK")


def test_tls12_wrong_hostname_raises() raises:
    """TLS 1.2: wrong hostname cert raises cert_chain_verify."""
    _run_server(14447, "tests/wronghost.pem", "tests/wronghost.key")
    _ = external_call["usleep", Int32](UInt32(800000))
    var fd = _tcp_connect(14447)
    var anchors = _make_trust_anchors()
    var raised = False
    try:
        var tls = TlsSocket(fd)
        tls.connect("localhost", anchors)
    except:
        raised = True
    _ = external_call["close", Int32](fd)
    _kill_server(14447)
    if not raised:
        raise Error("expected raise for hostname mismatch")


def test_version_negotiation_tls13_preferred() raises:
    """TLS version negotiation: TLS 1.3 server → TLS 1.3 is negotiated."""
    _run_tls13_server(14448, "tests/server.pem", "tests/server.key")
    _ = external_call["usleep", Int32](UInt32(800000))
    var fd = _tcp_connect(14448)
    var anchors = _make_trust_anchors()
    var tls = TlsSocket(fd)
    tls.connect("localhost", anchors)
    # Verify it's TLS 1.3 (not TLS 1.2)
    if tls._is12:
        _ = external_call["close", Int32](fd)
        _kill_server(14448)
        raise Error("expected TLS 1.3 with TLS 1.3-only server, got TLS 1.2")
    _ = external_call["close", Int32](fd)
    _kill_server(14448)


def test_version_negotiation_tls12_fallback() raises:
    """TLS version negotiation: TLS 1.2-only server → TLS 1.2 is negotiated."""
    _run_server(14449, "tests/server.pem", "tests/server.key")
    _ = external_call["usleep", Int32](UInt32(800000))
    var fd = _tcp_connect(14449)
    var anchors = _make_trust_anchors()
    var tls = TlsSocket(fd)
    tls.connect("localhost", anchors)
    # Verify it's TLS 1.2
    if not tls._is12:
        _ = external_call["close", Int32](fd)
        _kill_server(14449)
        raise Error("expected TLS 1.2 with TLS 1.2-only server")
    _ = external_call["close", Int32](fd)
    _kill_server(14449)


def main() raises:
    var passed = 0
    var failed = 0

    print("=== TLS 1.2 Connection Tests ===")
    print()

    run_test[test_tls12_handshake_success]("TLS 1.2 handshake succeeds", passed, failed)
    run_test[test_tls12_send_recv_roundtrip]("TLS 1.2 send+recv roundtrip", passed, failed)
    run_test[test_tls12_wrong_hostname_raises]("TLS 1.2 wrong hostname raises", passed, failed)
    run_test[test_version_negotiation_tls13_preferred]("Version negotiation: TLS 1.3 preferred", passed, failed)
    run_test[test_version_negotiation_tls12_fallback]("Version negotiation: TLS 1.2 fallback", passed, failed)

    print()
    print("Results:", passed, "passed,", failed, "failed")
    if failed > 0:
        raise Error(String(failed) + " test(s) failed")
