# ============================================================================
# test_socket.mojo — TlsSocket integration tests
# ============================================================================
# Tests load_system_ca_bundle() and TlsSocket connect/send/recv/close.
# Uses the same local Python TLS 1.3 server infrastructure as test_connection.
# ============================================================================

from std.ffi import external_call
from std.memory import alloc
from crypto.cert import X509Cert, cert_parse
from crypto.record import CIPHER_AES_128_GCM
from tls.socket import TlsSocket, load_system_ca_bundle


# ── Test certificate constants ─────────────────────────────────────────────
# CA (self-signed, TLS Test CA, ECDSA P-256) — same as test_connection.mojo
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


def _run_server(port: Int, certfile: String, keyfile: String):
    var cmd = (
        String("python3 tests/tls_test_server.py ")
        + String(port)
        + String(" ")
        + certfile
        + String(" ")
        + keyfile
        + String(" 2 &")   # max_conns=2 for send+recv test
    )
    _ = external_call["system", Int32]((cmd + String("\0")).unsafe_ptr())


def _run_server_alpn(port: Int, certfile: String, keyfile: String, alpn: String):
    # alpn arg: comma-separated protocol list e.g. "h2,http/1.1"
    var cmd = (
        String("python3 tests/tls_test_server.py ")
        + String(port)
        + String(" ")
        + certfile
        + String(" ")
        + keyfile
        + String(" 1 ")
        + alpn
        + String(" &")
    )
    _ = external_call["system", Int32]((cmd + String("\0")).unsafe_ptr())


def _kill_server(port: Int):
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

def test_load_system_ca_bundle() raises:
    """Load_system_ca_bundle() returns at least 40 trusted CA certs.

    Note: only SHA-256-compatible certs (P-256 ECDSA or RSA) are parsed;
    others (P-384, SHA-384 etc.) are silently skipped.
    """
    var certs = load_system_ca_bundle()
    if len(certs) < 40:
        raise Error(
            "expected >= 40 CA certs, got " + String(len(certs))
        )


def test_socket_connect() raises:
    """TlsSocket.connect() succeeds with valid server cert."""
    _run_server(14446, "tests/server.pem", "tests/server.key")
    _ = external_call["usleep", Int32](UInt32(1000000))  # 1s startup wait
    var fd = _tcp_connect(14446)
    var anchors = _make_trust_anchors()
    var sock = TlsSocket(fd)
    sock.connect("localhost", anchors)
    sock.close()
    _kill_server(14446)


def test_socket_send_recv() raises:
    """TlsSocket send+recv: HTTP GET returns 200 OK response."""
    _run_server(14447, "tests/server.pem", "tests/server.key")
    _ = external_call["usleep", Int32](UInt32(1000000))
    var fd = _tcp_connect(14447)
    var anchors = _make_trust_anchors()
    var sock = TlsSocket(fd)
    sock.connect("localhost", anchors)

    # Send HTTP/1.0 GET (Connection: close so server responds quickly)
    var req_str = String(
        "GET / HTTP/1.0\r\nHost: localhost\r\n\r\n"
    )
    var req_bytes = req_str.as_bytes()
    var req = List[UInt8](capacity=len(req_bytes))
    for i in range(len(req_bytes)):
        req.append(req_bytes[i])
    _ = sock.send(req)

    # Receive response
    var resp = sock.recv(4096)
    sock.close()
    _kill_server(14447)

    # Verify HTTP 200 — "HTTP/1.1 200"
    # Offsets: H=0,T=1,T=2,P=3,/=4,1=5,.=6,1=7,' '=8,2=9,0=10,0=11
    if len(resp) < 12:
        raise Error("response too short: " + String(len(resp)))
    var ok = (
        resp[0] == UInt8(72) and   # 'H'
        resp[1] == UInt8(84) and   # 'T'
        resp[2] == UInt8(84) and   # 'T'
        resp[3] == UInt8(80) and   # 'P'
        resp[9] == UInt8(50) and   # '2'
        resp[10] == UInt8(48) and  # '0'
        resp[11] == UInt8(48)      # '0'
    )
    if not ok:
        raise Error("expected HTTP/1.1 200 response")


def test_socket_wrong_cert_raises() raises:
    """TlsSocket.connect() raises when server cert has wrong hostname."""
    _run_server(14448, "tests/wronghost.pem", "tests/wronghost.key")
    _ = external_call["usleep", Int32](UInt32(1000000))
    var fd = _tcp_connect(14448)
    var anchors = _make_trust_anchors()
    var sock = TlsSocket(fd)
    var raised = False
    try:
        sock.connect("localhost", anchors)
    except:
        raised = True
    _ = external_call["close", Int32](fd)
    _kill_server(14448)
    if not raised:
        raise Error("expected raise for hostname mismatch")


def test_alpn_negotiated() raises:
    """ALPN: negotiated_protocol() returns server-selected protocol 'h2'."""
    # Server advertises only "h2"; client requests "h2".
    _run_server_alpn(14449, "tests/server.pem", "tests/server.key", "h2")
    _ = external_call["usleep", Int32](UInt32(1000000))
    var fd = _tcp_connect(14449)
    var anchors = _make_trust_anchors()
    var sock = TlsSocket(fd)
    var protocols = List[String]()
    protocols.append("h2")
    sock.connect("localhost", anchors, protocols)
    var proto = sock.negotiated_protocol()
    sock.close()
    _kill_server(14449)
    if proto != "h2":
        raise Error("expected negotiated protocol 'h2', got '" + proto + "'")


def test_alpn_no_protocols_empty() raises:
    """ALPN: negotiated_protocol() returns '' when no ALPN in ClientHello."""
    _run_server_alpn(14450, "tests/server.pem", "tests/server.key", "h2")
    _ = external_call["usleep", Int32](UInt32(1000000))
    var fd = _tcp_connect(14450)
    var anchors = _make_trust_anchors()
    var sock = TlsSocket(fd)
    sock.connect("localhost", anchors)   # no alpn_protocols argument
    var proto = sock.negotiated_protocol()
    sock.close()
    _kill_server(14450)
    if proto != "":
        raise Error("expected empty negotiated protocol, got '" + proto + "'")


def main() raises:
    var passed = 0
    var failed = 0

    print("=== TLS Socket Tests ===")
    print()

    run_test[test_load_system_ca_bundle]("load_system_ca_bundle: >= 40 parseable certs", passed, failed)
    run_test[test_socket_connect]("TlsSocket.connect: valid cert succeeds", passed, failed)
    run_test[test_socket_send_recv]("TlsSocket.send+recv: HTTP GET returns 200", passed, failed)
    run_test[test_socket_wrong_cert_raises]("TlsSocket.connect: wrong cert raises", passed, failed)
    run_test[test_alpn_negotiated]("TlsSocket.negotiated_protocol: 'h2' when server supports h2", passed, failed)
    run_test[test_alpn_no_protocols_empty]("TlsSocket.negotiated_protocol: '' when no ALPN advertised", passed, failed)

    print()
    print("Results:", passed, "passed,", failed, "failed")
    if failed > 0:
        raise Error(String(failed) + " test(s) failed")
