# ============================================================================
# crypto/random.mojo — CSPRNG via /dev/urandom
# ============================================================================
# API:
#   csprng_bytes(n: Int) raises -> List[UInt8]
#       Reads n cryptographically-secure random bytes from /dev/urandom.
# ============================================================================

from ffi import external_call
from memory.unsafe_pointer import alloc


def csprng_bytes(n: Int) raises -> List[UInt8]:
    """Read n bytes from the OS CSPRNG via getrandom() syscall."""
    if n == 0:
        return List[UInt8]()

    var buf = alloc[UInt8](n)
    var ret = external_call["getrandom", Int](buf, n, Int(0))
    if ret < 0:
        buf.free()
        raise Error("csprng_bytes: getrandom failed")

    var out = List[UInt8](capacity=n)
    for i in range(n):
        out.append((buf + i)[])
    buf.free()
    return out^
