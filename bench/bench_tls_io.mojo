# ============================================================================
# bench_tls_io.mojo — TLS receive throughput against openssl s_server -WWW
# ============================================================================
# Run through bench/bench_tls_io.sh (pixi run bench-io), which serves a
# 256 MiB file, runs a second s_server that discards what it receives, and
# runs this once per AES-GCM path:
#   bench_tls_io PORT CA_DER_HEX SINK_PORT CHACHA_PORT
# ============================================================================

from std.ffi import external_call
from std.memory import alloc
from std.sys import argv
from std.time import perf_counter_ns
from crypto.aes_hw import GCM_HW
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


def _connect(port: Int, anchors: List[X509Cert]) raises -> TlsSocket:
    var tls = TlsSocket(_tcp_connect(port))
    tls.connect("localhost", anchors)
    return tls^


def _open(port: Int, anchors: List[X509Cert]) raises -> TlsSocket:
    var tls = TlsSocket(_tcp_connect(port))
    tls.connect("localhost", anchors)
    var req = String("GET /big.bin HTTP/1.0\r\n\r\n")
    var b = List[UInt8]()
    for c in req.as_bytes():
        b.append(c)
    _ = tls.send(b)
    return tls^


def _rate(n: Int, t0: Int) -> Int:
    return Int(Float64(n) / (Float64(perf_counter_ns() - t0) / 1e9) / 1e6)


def main() raises:
    var args = argv()
    var port = Int(String(args[1]))
    var anchors = List[X509Cert]()
    anchors.append(cert_parse(_unhex(String(args[2]))))
    var path = "hardware AES-GCM" if GCM_HW else "software AES-GCM"
    print("  [" + path + "]")

    var s = _open(port, anchors)
    var n = 0
    var t0 = perf_counter_ns()
    while n < 128 * 1024 * 1024:
        var c = s.recv(65536)
        if len(c) == 0:
            break
        n += len(c)
    print("  recv(64 KiB) loop, 128 MiB:     ", _rate(n, t0), "MB/s")
    s.close()   # s_server serves one client at a time

    var s2 = _open(port, anchors)
    t0 = perf_counter_ns()
    var all = s2.recv_all(max_size=300 * 1024 * 1024, allow_truncation=True)
    print("  recv_all, 256 MiB:              ", _rate(len(all), t0), "MB/s")
    s2.close()

    var s3 = _open(port, anchors)
    var msgs = 200000
    t0 = perf_counter_ns()
    for _ in range(msgs):
        _ = s3.recv_exact(5)
        _ = s3.recv_exact(59)
    var ns = perf_counter_ns() - t0
    print("  recv_exact(5) + recv_exact(59): ", Float64(Int(Float64(ns) / Float64(msgs) / 10.0)) / 100.0, "us/message")
    s3.close()

    var s4 = _connect(Int(String(args[3])), anchors)
    var chunk = List[UInt8](length=16384, fill=0x61)
    var sent = 0
    t0 = perf_counter_ns()
    while sent < 128 * 1024 * 1024:
        sent += s4.send(chunk)
    print("  send(16 KiB) loop, 128 MiB:     ", _rate(sent, t0), "MB/s")
    s4.close()

    var s5 = _open(Int(String(args[4])), anchors)
    n = 0
    t0 = perf_counter_ns()
    while n < 128 * 1024 * 1024:
        var c = s5.recv(65536)
        if len(c) == 0:
            break
        n += len(c)
    print("  recv loop, ChaCha20-Poly1305:   ", _rate(n, t0), "MB/s")
    s5.close()
