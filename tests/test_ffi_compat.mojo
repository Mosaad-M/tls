# ============================================================================
# test_ffi_compat.mojo — C-call signatures shared with dependent packages
# ============================================================================
# Mojo allows only one signature per C function in a program. The tcp
# package and the dependents (requests, websocket, pg, mojo-pkg) declare
# these calls with the argument types below; if tls declared any of them
# differently, every program importing both would fail to compile.
# (C functions that Mojo's std declares itself - open/read/write, errno
# access, getenv, clock_gettime - are not declared by tls or the dependents
# at all; tests/test_std_compat.mojo checks that side.)
#
# Both sides must be reachable for the compiler to compare them, so this
# calls them for real on fd -1 (each fails harmlessly with EBADF).
# ============================================================================

from std.ffi import external_call
from std.memory import alloc
from crypto.cert import X509Cert, cert_chain_verify
from tls.connection import tls_read_some, tls_set_timeout, tls_prepare_fd, tls_tcp_write


def _tcp_style_calls(fd: Int32) -> Int:
    var buf = alloc[UInt8](16)
    # tcp.mojo: _send / _recv
    var a = external_call["send", Int](fd, Int(buf), Int(1), Int32(0))
    var b = external_call["recv", Int](fd, Int(buf), Int(1), Int32(0))
    # tcp.mojo: _set_socket_timeouts
    var c = external_call["setsockopt", Int32](fd, Int32(0), Int32(0), Int(buf), Int32(16))
    # requests / pg / tcp: memcpy
    var d = external_call["memcpy", Int](Int(buf), Int(buf) + 8, Int(4))
    # requests: _unix_time_secs (tls: cert_chain_verify's clock)
    var e = external_call["time", Int64](Int(0))
    buf.unsafe_free()
    return a + b + Int(c) + d + Int(e)


def main() raises:
    var fd = Int32(-1)
    _ = _tcp_style_calls(fd)
    tls_prepare_fd(fd)
    try:
        tls_set_timeout(fd, 1)
    except:
        pass
    try:
        _ = tls_read_some(fd, 16)
    except:
        pass
    try:
        var one: List[UInt8] = [1]
        tls_tcp_write(fd, one)
    except:
        pass
    try:
        cert_chain_verify(List[X509Cert](), List[X509Cert](), "example.com")
    except:
        pass
    print("=== FFI signature compatibility: compiled ===")
    print("Results: 1 passed, 0 failed")
