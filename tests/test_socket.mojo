# ============================================================================
# test_socket.mojo — TlsSocket integration tests
# ============================================================================
# Tests load_system_ca_bundle() and TlsSocket connect/send/recv/close.
# Uses the same local Python TLS 1.3 server infrastructure as test_connection.
# ============================================================================

from ffi import external_call
from memory.unsafe_pointer import alloc
from crypto.cert import X509Cert, cert_parse
from crypto.record import CIPHER_AES_128_GCM
from tls.socket import TlsSocket, load_system_ca_bundle


# ── Test certificate constants ─────────────────────────────────────────────
# CA (self-signed, TLS Test CA, ECDSA P-256) — same as test_connection.mojo
comptime CA_DER_HEX = "3082012e3081d4a003020102020101300a06082a8648ce3d04030230163114301206035504030c0b544c532054657374204341301e170d3235303130313030303030305a170d3330303130313030303030305a30163114301206035504030c0b544c5320546573742043413059301306072a8648ce3d020106082a8648ce3d03010703420004953ebf76c51d88521b84dde00fd5e5887a1f0da45fff9d8ef5f0f8ea06d31f7ac90d2e76db328b6856751526797a83f5f0ec8a59ee46ebcc2097225c7e78131ca3133011300f0603551d130101ff040530030101ff300a06082a8648ce3d0403020349003046022100eabac6ddd8056900b0f44b8df1120ae57f4bf830f14e8c5054c8eacc1df10031022100db664722cd556ffa16438a3b858565ddbe13929c1c688a94b032a4d14fa03cd4"


# ── Helpers ────────────────────────────────────────────────────────────────

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


fn _tcp_connect(port: Int) raises -> Int32:
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


fn _run_server(port: Int, certfile: String, keyfile: String):
    var cmd = (
        String("python3 tests/tls_test_server.py ")
        + String(port)
        + String(" ")
        + certfile
        + String(" ")
        + keyfile
        + String(" 2 &")   # max_conns=2 for send+recv test
    )
    _ = external_call["system", Int32](cmd.unsafe_ptr())


fn _kill_server(port: Int):
    var cmd = (
        String("pkill -f 'tls_test_server.py ")
        + String(port)
        + String("'")
    )
    _ = external_call["system", Int32](cmd.unsafe_ptr())


fn _make_trust_anchors() raises -> List[X509Cert]:
    var anchors = List[X509Cert]()
    anchors.append(cert_parse(hex_to_bytes(CA_DER_HEX)))
    return anchors^


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


# ── Tests ──────────────────────────────────────────────────────────────────

fn test_load_system_ca_bundle() raises:
    """load_system_ca_bundle() returns at least 40 trusted CA certs.

    Note: only SHA-256-compatible certs (P-256 ECDSA or RSA) are parsed;
    others (P-384, SHA-384 etc.) are silently skipped.
    """
    var certs = load_system_ca_bundle()
    if len(certs) < 40:
        raise Error(
            "expected >= 40 CA certs, got " + String(len(certs))
        )


fn test_socket_connect() raises:
    """TlsSocket.connect() succeeds with valid server cert."""
    _run_server(14446, "tests/server.pem", "tests/server.key")
    _ = external_call["usleep", Int32](UInt32(1000000))  # 1s startup wait
    var fd = _tcp_connect(14446)
    var anchors = _make_trust_anchors()
    var sock = TlsSocket(fd)
    sock.connect("localhost", anchors)
    sock.close()
    _kill_server(14446)


fn test_socket_send_recv() raises:
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


fn test_socket_wrong_cert_raises() raises:
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


fn main() raises:
    var passed = 0
    var failed = 0

    print("=== TLS Socket Tests ===")
    print()

    run_test("load_system_ca_bundle: >= 40 parseable certs", passed, failed, test_load_system_ca_bundle)
    run_test("TlsSocket.connect: valid cert succeeds", passed, failed, test_socket_connect)
    run_test("TlsSocket.send+recv: HTTP GET returns 200", passed, failed, test_socket_send_recv)
    run_test("TlsSocket.connect: wrong cert raises", passed, failed, test_socket_wrong_cert_raises)

    print()
    print("Results:", passed, "passed,", failed, "failed")
    if failed > 0:
        raise Error(String(failed) + " test(s) failed")
