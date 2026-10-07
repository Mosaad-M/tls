# ============================================================================
# crypto/random.mojo — CSPRNG via /dev/urandom
# ============================================================================
# API:
#   csprng_bytes(n: Int) raises -> List[UInt8]
#       Reads n cryptographically-secure random bytes from /dev/urandom
#       (Linux and macOS), through std open() so that tls declares no file
#       I/O C functions of its own (see tests/test_std_compat.mojo).
# ============================================================================


def csprng_bytes(n: Int) raises -> List[UInt8]:
    """Read n bytes from the OS CSPRNG via /dev/urandom."""
    if n == 0:
        return List[UInt8]()
    var out: List[UInt8]
    try:
        with open("/dev/urandom", "r") as f:
            out = f.read_bytes(n)  # loops until n bytes or end of file
    except:
        raise Error("csprng_bytes: cannot read /dev/urandom")
    if len(out) != n:
        raise Error("csprng_bytes: short read from /dev/urandom")
    return out^
