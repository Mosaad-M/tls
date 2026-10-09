# ============================================================================
# bench_handshake.mojo — TLS handshake latency against openssl s_server
# ============================================================================
# Run through bench/bench_handshake.sh (pixi run bench-handshake), which
# starts s_server with an ECDSA P-256 and an RSA-2048 certificate, for TLS 1.3
# and 1.2, and times the same handshakes from Python (OpenSSL) for reference:
#   bench_handshake PORT CA_DER_HEX COUNT
# ============================================================================

from std.ffi import external_call
from std.memory import alloc
from std.sys import argv
from std.time import perf_counter_ns
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
    var r = h.as_bytes()
    var out = List[UInt8]()
    for i in range(len(r) // 2):
        var a = r[2 * i]
        var c = r[2 * i + 1]
        var hi: UInt8 = (a - 48) if a <= 57 else (a - 87)
        var lo: UInt8 = (c - 48) if c <= 57 else (c - 87)
        out.append((hi << 4) | lo)
    return out^



def main() raises:
    var args = argv()
    var port = Int(String(args[1]))
    var anchors = List[X509Cert]()
    anchors.append(cert_parse(_unhex(String(args[2]))))
    var n = Int(String(args[3]))
    var best = 1 << 62
    var t0 = perf_counter_ns()
    for _ in range(n):
        var t1 = perf_counter_ns()
        var s = TlsSocket(_tcp_connect(port))
        s.connect("localhost", anchors)
        var d = Int(perf_counter_ns() - t1)
        if d < best:
            best = d
        s.close()
    var avg = Float64(perf_counter_ns() - t0) / Float64(n) / 1e6
    print("  tls:    avg", Float64(Int(avg * 100)) / 100.0, "ms/handshake, best", Float64(best // 10000) / 100.0, "ms")
