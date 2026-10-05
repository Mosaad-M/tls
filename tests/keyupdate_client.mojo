# ============================================================================
# keyupdate_client.mojo — client half of tests/keyupdate_interop.sh
# ============================================================================
# Usage: keyupdate_client.mojo <port> <CA DER hex>
# Connects to `openssl s_server` on 127.0.0.1:<port>, reads until the server
# has sent "after-K" (it sends KeyUpdate before "after-k" and KeyUpdate with
# update_requested before "after-K"), then sends "ping-after-update" under
# the client's updated keys and closes.
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


def main() raises:
    var port = Int(String(argv()[1]))
    # argv[2]: the test CA as DER hex (the script converts tests/ca.pem)
    var ca_hex = String(argv()[2]).as_bytes()
    var der = List[UInt8](capacity=len(ca_hex) // 2)
    for i in range(0, len(ca_hex) - 1, 2):
        var hi = ca_hex[i]
        var lo = ca_hex[i + 1]
        var h: UInt8 = (hi - 48) if hi <= 57 else (hi - 87)
        var l: UInt8 = (lo - 48) if lo <= 57 else (lo - 87)
        der.append((h << 4) | l)
    var anchors = List[X509Cert]()
    anchors.append(cert_parse(der))

    var tls = TlsSocket(_tcp_connect(port))
    tls.connect("localhost", anchors)
    tls.set_timeout(20)
    var text = String()
    while text.find("after-K") < 0:
        var chunk = tls.recv(4096)
        text += String(unsafe_from_utf8=chunk^)
    for marker in ["hello", "after-k", "after-K"]:
        if text.find(marker) < 0:
            raise Error("missing '" + marker + "' in: " + text)
    var ping = String("ping-after-update\n")
    var b = List[UInt8]()
    for c in ping.as_bytes():
        b.append(c)
    _ = tls.send(b)
    print("client: received all data across both key updates; sent ping")
    tls.close()
