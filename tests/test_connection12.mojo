# ============================================================================
# test_connection12.mojo — TLS 1.2 + version-negotiation integration tests
# ============================================================================
# Tests the full TLS 1.2 client handshake against a local Python server.
# Reuses the same ECDSA P-256 test certificates as test_connection.mojo.
# ============================================================================

from std.ffi import external_call
from std.memory.unsafe_pointer import alloc
from crypto.cert import X509Cert, cert_parse
from tls.connection12 import tls12_client_handshake, TlsKeys12
from tls.socket import TlsSocket
from crypto.hash import SHA256, SHA384


# ── Test certificate constants ─────────────────────────────────────────────
# Same CA as test_connection.mojo (ECDSA P-256, self-signed)
comptime CA_DER_HEX = "3082019230820138a0030201020214573f65a34f1eda3f679a037a6e62e8bfbeb09603300a06082a8648ce3d04030230163114301206035504030c0b544c532054657374204341301e170d3236303330373137333935345a170d3331303330373137333935345a30163114301206035504030c0b544c5320546573742043413059301306072a8648ce3d020106082a8648ce3d0301070342000471185cd463948dea0ac90046f6fc4f385638b7715824723a10d4fa25b69895532047ab52ca3e74261d5b175d27cfb0921f47c26c618c798bf33c48c7b3bb7941a3643062301d0603551d0e04160414896a744421f5317a4cc07a5b7dbef8192c8f4d2b301f0603551d23041830168014896a744421f5317a4cc07a5b7dbef8192c8f4d2b300f0603551d130101ff040530030101ff300f0603551d130101ff040530030101ff300a06082a8648ce3d040302034800304502207d6bca651f67a2edff1bd713578bf452ab4eaacc270e4d94f2ad2984cffb45d5022100a3d7699dccebc90383b97b220b95a85d860476ad98fe7c87bd19df7a9ff4f520"


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
        (addr + i)[] = 0
    (addr + 0)[] = 2
    (addr + 1)[] = 0
    (addr + 2)[] = UInt8((port >> 8) & 0xFF)
    (addr + 3)[] = UInt8(port & 0xFF)
    (addr + 4)[] = 127
    (addr + 5)[] = 0
    (addr + 6)[] = 0
    (addr + 7)[] = 1
    var ret = external_call["connect", Int32](fd, addr, Int32(16))
    addr.free()
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
    _ = external_call["system", Int32](cmd.unsafe_ptr())


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
    _ = external_call["system", Int32](cmd.unsafe_ptr())


def _kill_server(port: Int):
    """Kill the test server for the given port."""
    var cmd = String("pkill -f 'test.*server.py ") + String(port) + String("'")
    _ = external_call["system", Int32](cmd.unsafe_ptr())


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

    run_test("TLS 1.2 handshake succeeds", passed, failed, test_tls12_handshake_success)
    run_test("TLS 1.2 send+recv roundtrip", passed, failed, test_tls12_send_recv_roundtrip)
    run_test("TLS 1.2 wrong hostname raises", passed, failed, test_tls12_wrong_hostname_raises)
    run_test("Version negotiation: TLS 1.3 preferred", passed, failed, test_version_negotiation_tls13_preferred)
    run_test("Version negotiation: TLS 1.2 fallback", passed, failed, test_version_negotiation_tls12_fallback)

    print()
    print("Results:", passed, "passed,", failed, "failed")
    if failed > 0:
        raise Error(String(failed) + " test(s) failed")
