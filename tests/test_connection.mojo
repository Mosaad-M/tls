# ============================================================================
# test_connection.mojo — TLS 1.3 handshake integration tests
# ============================================================================
# Tests the full client handshake against a local Python TLS 1.3 server.
# Certificates generated with Python cryptography library (ECDSA P-256 / SHA-256).
# ============================================================================

from ffi import external_call
from memory.unsafe_pointer import alloc
from crypto.cert import X509Cert, cert_parse
from crypto.record import CIPHER_AES_128_GCM
from tls.connection import tls13_client_handshake, TlsKeys


# ── Test certificate constants ─────────────────────────────────────────────
# CA (self-signed, TLS Test CA, ECDSA P-256)
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
    (addr + 0)[] = 2                              # AF_INET low byte
    (addr + 1)[] = 0                              # AF_INET high byte
    (addr + 2)[] = UInt8((port >> 8) & 0xFF)      # sin_port high
    (addr + 3)[] = UInt8(port & 0xFF)             # sin_port low
    (addr + 4)[] = 127                            # 127.0.0.1
    (addr + 5)[] = 0
    (addr + 6)[] = 0
    (addr + 7)[] = 1
    var ret = external_call["connect", Int32](fd, addr, Int32(16))
    addr.free()
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
    _ = external_call["system", Int32](cmd.unsafe_ptr())


def _kill_server(port: Int):
    """Kill the test server for the given port."""
    var cmd = (
        String("pkill -f 'tls_test_server.py ")
        + String(port)
        + String("'")
    )
    _ = external_call["system", Int32](cmd.unsafe_ptr())


def _make_trust_anchors() raises -> List[X509Cert]:
    var anchors = List[X509Cert]()
    anchors.append(cert_parse(hex_to_bytes(CA_DER_HEX)))
    return anchors^


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

    run_test("TLS 1.3 handshake with localhost cert", passed, failed, test_handshake_success)
    run_test("hostname mismatch cert raises", passed, failed, test_hostname_mismatch)

    print()
    print("Results:", passed, "passed,", failed, "failed")
    if failed > 0:
        raise Error(String(failed) + " test(s) failed")
