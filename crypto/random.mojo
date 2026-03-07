# ============================================================================
# crypto/random.mojo — CSPRNG via /dev/urandom
# ============================================================================
# API:
#   csprng_bytes(n: Int) raises -> List[UInt8]
#       Reads n cryptographically-secure random bytes from /dev/urandom.
# ============================================================================

from ffi import external_call
from memory.unsafe_pointer import alloc


fn csprng_bytes(n: Int) raises -> List[UInt8]:
    """Read n bytes from /dev/urandom. Raises on I/O error."""
    if n == 0:
        return List[UInt8]()

    # Open /dev/urandom — unsafe_ptr() returns null-terminated UnsafePointer[UInt8]
    var path = String("/dev/urandom")
    var cstr = path.unsafe_ptr()
    var O_RDONLY: Int32 = 0
    var fd = external_call["open", Int32](cstr, O_RDONLY)
    if fd < 0:
        raise Error("csprng_bytes: failed to open /dev/urandom")

    # Allocate buffer
    var buf = alloc[UInt8](n)

    # Read exactly n bytes (loop to handle short reads)
    var total_read: Int = 0
    while total_read < n:
        var ptr = buf + total_read
        var remaining = n - total_read
        var nread = external_call["read", Int](fd, ptr, remaining)
        if nread <= 0:
            _ = external_call["close", Int32](fd)
            buf.free()
            raise Error("csprng_bytes: read from /dev/urandom failed")
        total_read += nread

    _ = external_call["close", Int32](fd)

    # Copy into List[UInt8]
    var out = List[UInt8](capacity=n)
    for i in range(n):
        out.append((buf + i)[])
    buf.free()
    return out^
