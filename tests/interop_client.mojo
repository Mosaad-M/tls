# ============================================================================
# interop_client.mojo — client half of tests/interop.sh
# ============================================================================
# Usage: interop_client <port> <CA DER hex> [<client cert DER hex> <client key hex>]
# Connects to 127.0.0.1:<port> as "localhost", sends an HTTP request to
# `openssl s_server -www` and prints the status page, which reports the
# negotiated protocol and cipher. With a client certificate it uses
# connect_with_client_cert (TLS 1.2 mTLS, P-256 ECDSA).
# ============================================================================

from std.ffi import external_call
from std.memory import alloc
from std.sys import argv
from crypto.cert import X509Cert, cert_parse
from tls.socket import TlsSocket


def _tcp_connect(port: Int) raises -> Int32:
    var fd = external_call["socket", Int32](Int32(2), Int32(1), Int32(0))
    if fd < 0:
        raise Error("socket() failed")
    var addr = alloc[UInt8](16)
    for i in range(16):
        addr[unsafe_offset=i] = 0
    addr[unsafe_offset=0] = 2
    addr[unsafe_offset=2] = UInt8((port >> 8) & 0xFF)
    addr[unsafe_offset=3] = UInt8(port & 0xFF)
    addr[unsafe_offset=4] = 127
    addr[unsafe_offset=7] = 1
    var ret = external_call["connect", Int32](fd, addr, Int32(16))
    addr.unsafe_free()
    if ret < 0:
        raise Error("connect() failed to 127.0.0.1:" + String(port))
    return fd


def _unhex(h: String) -> List[UInt8]:
    var raw = h.as_bytes()
    var out = List[UInt8](capacity=len(raw) // 2)
    for i in range(0, len(raw) - 1, 2):
        var hi = raw[i]
        var lo = raw[i + 1]
        var a: UInt8 = (hi - 48) if hi <= 57 else ((hi - 87) if hi >= 97 else (hi - 55))
        var b: UInt8 = (lo - 48) if lo <= 57 else ((lo - 87) if lo >= 97 else (lo - 55))
        out.append((a << 4) | b)
    return out^


def main() raises:
    var args = argv()
    var port = Int(String(args[1]))
    var anchors = List[X509Cert]()
    anchors.append(cert_parse(_unhex(String(args[2]))))

    var tls = TlsSocket(_tcp_connect(port))
    if len(args) >= 5:
        tls.connect_with_client_cert(
            "localhost", anchors, _unhex(String(args[3])), _unhex(String(args[4]))
        )
    else:
        tls.connect("localhost", anchors)
    tls.set_timeout(20)
    var req = String("GET / HTTP/1.0\r\n\r\n")
    var b = List[UInt8]()
    for c in req.as_bytes():
        b.append(c)
    _ = tls.send(b)
    var page = tls.recv_all(allow_truncation=True)
    print(String(unsafe_from_utf8=page^))
    tls.close()
