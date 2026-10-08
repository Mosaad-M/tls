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
    var raw = h.as_bytes()
    var out = List[UInt8](capacity=len(raw) // 2)
    for i in range(0, len(raw) - 1, 2):
        var hi = raw[i]
        var lo = raw[i + 1]
        var a: UInt8 = (hi - 48) if hi <= 57 else ((hi - 87) if hi >= 97 else (hi - 55))
        var b: UInt8 = (lo - 48) if lo <= 57 else ((lo - 87) if lo >= 97 else (lo - 55))
        out.append((a << 4) | b)
    return out^


def _bulk(port: Int, anchors: List[X509Cert], path: String, size: Int, mode: String, max_secs: Int) raises:
    """Download path (size bytes of the pattern i % 251) from s_server -WWW
    with one receive style; check every byte and the time bound."""
    var tls = TlsSocket(_tcp_connect(port))
    tls.connect("localhost", anchors)
    tls.set_timeout(30)
    var req = "GET " + path + " HTTP/1.0\r\n\r\n"
    var b = List[UInt8]()
    for c in req.as_bytes():
        b.append(c)
    _ = tls.send(b)
    # headers: read until \r\n\r\n one byte at a time (exercises recv(1))
    var tail = 0
    while tail < 4:
        var c = tls.recv(1)
        if len(c) == 0:
            raise Error("bulk: no response headers")
        var want = UInt8(13) if tail % 2 == 0 else UInt8(10)
        tail = tail + 1 if c[0] == want else (1 if c[0] == 13 else 0)
    var t = perf_counter_ns()
    var got = 0
    var bad = -1
    if mode == "recv_all":
        var body = tls.recv_all(max_size=size + 1024, allow_truncation=True)
        got = len(body)
        for i in range(len(body)):
            if body[i] != UInt8(i % 251):
                bad = i
                break
    elif mode == "recv":
        while got < size:
            var chunk = tls.recv(65536)
            if len(chunk) == 0:
                break
            for i in range(len(chunk)):
                if bad < 0 and chunk[i] != UInt8((got + i) % 251):
                    bad = got + i
            got += len(chunk)
    else:  # small: pg-style 5 + 59 byte reads
        while got + 64 <= size:
            var h = tls.recv_exact(5)
            var m = tls.recv_exact(59)
            if bad < 0 and (h[0] != UInt8(got % 251) or m[58] != UInt8((got + 63) % 251)):
                bad = got
            got += 64
    var secs = Float64(perf_counter_ns() - t) / 1e9
    print("bulk", mode, ":", got, "bytes in", secs, "s =", Int(Float64(got) / secs / 1e6), "MB/s")
    if got != size:
        raise Error("bulk " + mode + ": got " + String(got) + " of " + String(size) + " bytes")
    if bad >= 0:
        raise Error("bulk " + mode + ": wrong byte at " + String(bad))
    if secs > Float64(max_secs):
        raise Error("bulk " + mode + ": took " + String(secs) + " s (limit " + String(max_secs) + ")")


def main() raises:
    var args = argv()
    var port = Int(String(args[1]))
    var anchors = List[X509Cert]()
    anchors.append(cert_parse(_unhex(String(args[2]))))
    if len(args) >= 8 and String(args[3]) == "--bulk":
        # interop_client PORT CA --bulk PATH SIZE MODE MAX_SECS
        _bulk(port, anchors, String(args[4]), Int(String(args[5])), String(args[6]), Int(String(args[7])))
        return

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
