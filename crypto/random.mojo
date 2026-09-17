# ============================================================================
# crypto/random.mojo — CSPRNG via /dev/urandom
# ============================================================================
# API:
#   csprng_bytes(n: Int) raises -> List[UInt8]
#       Reads n cryptographically-secure random bytes from /dev/urandom.
#       Uses POSIX open/read/close — works on Linux and macOS.
# ============================================================================

from std.ffi import external_call
from std.memory import alloc


def csprng_bytes(n: Int) raises -> List[UInt8]:
    """Read n bytes from the OS CSPRNG via /dev/urandom."""
    if n == 0:
        return List[UInt8]()

    # Build null-terminated path
    var path = String("/dev/urandom")
    var pb = path.as_bytes()
    var pn = len(pb)
    var pbuf = alloc[UInt8](pn + 1)
    for i in range(pn):
        pbuf[unsafe_offset=i] = pb[i]
    pbuf[unsafe_offset=pn] = 0

    var fd = external_call["open", Int32](pbuf, Int32(0))  # O_RDONLY = 0
    pbuf.unsafe_free()
    if fd < 0:
        raise Error("csprng_bytes: cannot open /dev/urandom")

    var buf = alloc[UInt8](n)
    var total = 0
    while total < n:
        var got = external_call["read", Int](fd, buf.unsafe_offset(total), n - total)
        if got <= 0:
            buf.unsafe_free()
            _ = external_call["close", Int32](fd)
            raise Error("csprng_bytes: read from /dev/urandom failed")
        total += got
    _ = external_call["close", Int32](fd)

    var out = List[UInt8](capacity=n)
    for i in range(n):
        out.append(buf[unsafe_offset=i])
    buf.unsafe_free()
    return out^
