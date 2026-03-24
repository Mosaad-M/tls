# ============================================================================
# bench_crypto.mojo — Performance benchmarks for tls_pure crypto primitives
# ============================================================================
#
# Run: pixi run bench
# ============================================================================

from ffi import external_call
from memory.unsafe_pointer import alloc

from crypto.curve25519 import x25519, x25519_public_key
from crypto.p256 import p256_ecdh, p256_public_key


def _clock_ns() -> Int:
    """Return monotonic time in nanoseconds via clock_gettime(CLOCK_MONOTONIC)."""
    var ts = alloc[UInt8](16)
    for i in range(16):
        (ts + i)[] = 0
    _ = external_call["clock_gettime", Int32](Int32(1), ts)
    var secs: Int64 = 0
    var nsecs: Int64 = 0
    for i in range(8):
        secs |= Int64(Int((ts + i)[]) << (i * 8))
        nsecs |= Int64(Int((ts + 8 + i)[]) << (i * 8))
    ts.free()
    return Int(secs) * 1_000_000_000 + Int(nsecs)


def print_result(name: String, iters: Int, elapsed_ns: Int):
    var ns_per_op = elapsed_ns // iters
    print(
        name
        + ": "
        + String(ns_per_op)
        + " ns/op  ("
        + String(elapsed_ns // 1_000_000)
        + " ms / "
        + String(iters)
        + " iters)"
    )


def bench_x25519() raises:
    """Benchmark x25519 scalar multiplication (Montgomery ladder)."""
    var iters = 200
    # Fixed private key (32 bytes, clamped per RFC 7748)
    var scalar = List[UInt8](capacity=32)
    for i in range(32):
        scalar.append(UInt8((i * 7 + 1) & 0xFF))
    scalar[0] &= 248
    scalar[31] &= 127
    scalar[31] |= 64
    # Base point u=9
    var u = List[UInt8](capacity=32)
    u.append(9)
    for _ in range(31):
        u.append(0)

    var start = _clock_ns()
    for _ in range(iters):
        _ = x25519(scalar.copy(), u.copy())
    print_result("x25519 (Montgomery ladder)", iters, _clock_ns() - start)


def bench_p256_keygen() raises:
    """Benchmark P-256 public key generation (base point scalar mult)."""
    var iters = 100
    var priv = List[UInt8](capacity=32)
    for i in range(32):
        priv.append(UInt8((i * 17 + 3) & 0xFF))
    priv[0] = 0x3F  # keep in valid range

    var start = _clock_ns()
    for _ in range(iters):
        _ = p256_public_key(priv.copy())
    print_result("P-256 public key (base point mult)", iters, _clock_ns() - start)


def bench_p256_ecdh() raises:
    """Benchmark P-256 ECDH shared secret (arbitrary point scalar mult)."""
    var iters = 100
    var priv = List[UInt8](capacity=32)
    for i in range(32):
        priv.append(UInt8((i * 13 + 5) & 0xFF))
    priv[0] = 0x3F
    var pub = p256_public_key(priv.copy())

    var start = _clock_ns()
    for _ in range(iters):
        _ = p256_ecdh(priv.copy(), pub.copy())
    print_result("P-256 ECDH (arbitrary point mult)", iters, _clock_ns() - start)


def main() raises:
    print("=== tls_pure Crypto Benchmarks ===")
    print()
    bench_x25519()
    bench_p256_keygen()
    bench_p256_ecdh()
    print()
    print("Note: P-384 benchmark requires exported p384 ECDH function.")
    print("=== Done ===")
