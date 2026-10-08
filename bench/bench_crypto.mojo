# ============================================================================
# bench_crypto.mojo — throughput and latency of the crypto primitives
# ============================================================================
#   pixi run bench
# Times are wall-clock (std.time.perf_counter_ns) on the build machine; compare
# runs on the same machine only.
# ============================================================================

from std.time import perf_counter_ns
from crypto.curve25519 import x25519, x25519_public_key
from crypto.p256 import p256_ecdh, p256_public_key, p256_ecdsa_sign
from crypto.gcm import gcm_encrypt, GcmKey
from crypto.poly1305 import chacha20_poly1305_encrypt, chacha20_poly1305_decrypt, poly1305_mac
from crypto.chacha20 import chacha20_encrypt
from crypto.hash import sha256
from crypto.record import AeadKey, record_seal_k, record_open_into, CIPHER_AES_256_GCM


def _bytes(n: Int, seed: Int) -> List[UInt8]:
    var out = List[UInt8](capacity=n)
    for i in range(n):
        out.append(UInt8((i * 31 + seed * 7 + 1) & 0xFF))
    return out^


def _per_op(name: String, iters: Int, elapsed_ns: Int):
    print(
        name + ": " + String(elapsed_ns // iters) + " ns/op  ("
        + String(elapsed_ns // 1_000_000) + " ms / " + String(iters) + " iters)"
    )


def _throughput(name: String, total_bytes: Int, elapsed_ns: Int):
    var mb_per_s = Float64(total_bytes) / Float64(elapsed_ns) * 1000.0
    print(name + ": " + String(Float64(Int(mb_per_s * 10)) / 10.0) + " MB/s")


def bench_aead() raises:
    var size = 256 * 1024
    var rounds = 4
    var pt = _bytes(size, 1)
    var aad = _bytes(13, 2)
    var nonce = _bytes(12, 3)

    var key128 = _bytes(16, 4)
    var start = perf_counter_ns()
    for _ in range(rounds):
        _ = gcm_encrypt(key128, nonce, pt, aad)
    _throughput("AES-128-GCM encrypt (256 KiB)", size * rounds, Int(perf_counter_ns() - start))

    var key256 = _bytes(32, 5)
    start = perf_counter_ns()
    for _ in range(rounds):
        _ = gcm_encrypt(key256, nonce, pt, aad)
    _throughput("AES-256-GCM encrypt (256 KiB)", size * rounds, Int(perf_counter_ns() - start))

    start = perf_counter_ns()
    for _ in range(rounds):
        _ = chacha20_poly1305_encrypt(key256, nonce, aad, pt)
    _throughput("ChaCha20-Poly1305 encrypt (256 KiB)", size * rounds, Int(perf_counter_ns() - start))

    # Small records: per-record cost dominates (key setup, GHASH tail)
    var small = _bytes(64, 6)
    var n_small = 2000
    start = perf_counter_ns()
    for _ in range(n_small):
        _ = gcm_encrypt(key128, nonce, small, aad)
    _per_op("AES-128-GCM encrypt 64-byte record", n_small, Int(perf_counter_ns() - start))

    # The same with the key prepared once, as TLS records use it (1.6.1)
    var gk = GcmKey(key128)
    start = perf_counter_ns()
    for _ in range(n_small):
        _ = gk.seal(nonce, small, aad)
    _per_op("AES-128-GCM encrypt 64-byte record, prepared key", n_small, Int(perf_counter_ns() - start))
    var big = _bytes(16384, 7)
    start = perf_counter_ns()
    for _ in range(200):
        _ = gk.seal(nonce, big, aad)
    _throughput("AES-128-GCM encrypt 16 KiB records, prepared key", 16384 * 200, Int(perf_counter_ns() - start))

    # AES-256-GCM (what TLS 1.3 servers usually pick), seal and open, and the
    # whole record layer around them (1.8.1: fused AES-CTR + GHASH, in place)
    var gk256 = GcmKey(key256)
    var reps = 2000
    start = perf_counter_ns()
    for _ in range(reps):
        _ = gk256.seal(nonce, big, aad)
    _throughput("AES-256-GCM seal 16 KiB, prepared key", 16384 * reps, Int(perf_counter_ns() - start))
    var sealed = gk256.seal(nonce, big, aad)
    start = perf_counter_ns()
    for _ in range(reps):
        _ = gk256.open(nonce, sealed[0], sealed[1], aad)
    _throughput("AES-256-GCM open 16 KiB, prepared key", 16384 * reps, Int(perf_counter_ns() - start))

    var ak = AeadKey()
    start = perf_counter_ns()
    for i in range(reps):
        _ = record_seal_k(ak, CIPHER_AES_256_GCM, key256, nonce, UInt64(i), 0x17, big)
    _throughput("TLS 1.3 record seal, 16 KiB (AES-256-GCM)", 16384 * reps, Int(perf_counter_ns() - start))
    var rec = record_seal_k(ak, CIPHER_AES_256_GCM, key256, nonce, 0, 0x17, big)
    var out = List[UInt8](capacity=16384 + 16)
    start = perf_counter_ns()
    for _ in range(reps):
        out.resize(unsafe_uninit_length=0)
        _ = record_open_into(ak, CIPHER_AES_256_GCM, key256, nonce, 0, Int(rec.unsafe_ptr()), len(rec), out)
    _throughput("TLS 1.3 record open in place, 16 KiB (AES-256-GCM)", 16384 * reps, Int(perf_counter_ns() - start))

    # ChaCha20-Poly1305 (1.8.2: 16 blocks per SIMD step, radix-2^44 Poly1305)
    start = perf_counter_ns()
    for _ in range(reps):
        _ = chacha20_encrypt(key256, nonce, 1, big)
    _throughput("ChaCha20 alone, 16 KiB", 16384 * reps, Int(perf_counter_ns() - start))
    start = perf_counter_ns()
    for _ in range(reps):
        _ = poly1305_mac(key256, big)
    _throughput("Poly1305 alone, 16 KiB", 16384 * reps, Int(perf_counter_ns() - start))
    start = perf_counter_ns()
    for _ in range(reps):
        _ = chacha20_poly1305_encrypt(key256, nonce, aad, big)
    _throughput("ChaCha20-Poly1305 seal 16 KiB", 16384 * reps, Int(perf_counter_ns() - start))
    var csealed = chacha20_poly1305_encrypt(key256, nonce, aad, big)
    start = perf_counter_ns()
    for _ in range(reps):
        _ = chacha20_poly1305_decrypt(key256, nonce, aad, csealed[0], csealed[1])
    _throughput("ChaCha20-Poly1305 open 16 KiB", 16384 * reps, Int(perf_counter_ns() - start))


def bench_x25519() raises:
    var iters = 200
    var scalar = _bytes(32, 7)
    var u = List[UInt8](capacity=32)
    u.append(9)
    for _ in range(31):
        u.append(0)
    var start = perf_counter_ns()
    for _ in range(iters):
        _ = x25519(scalar, u)
    _per_op("X25519 scalar mult", iters, Int(perf_counter_ns() - start))


def bench_p256() raises:
    var iters = 50
    var priv = _bytes(32, 8)
    priv[0] = 0x3F  # keep it below n
    var start = perf_counter_ns()
    for _ in range(iters):
        _ = p256_public_key(priv)
    _per_op("P-256 public key (k*G)", iters, Int(perf_counter_ns() - start))

    var peer = p256_public_key(_bytes(32, 9))
    start = perf_counter_ns()
    for _ in range(iters):
        _ = p256_ecdh(priv, peer)
    _per_op("P-256 ECDH", iters, Int(perf_counter_ns() - start))

    var h = sha256(_bytes(100, 10))
    var nonce = _bytes(32, 11)
    start = perf_counter_ns()
    for _ in range(iters):
        _ = p256_ecdsa_sign(priv, h, nonce)
    _per_op("P-256 ECDSA sign", iters, Int(perf_counter_ns() - start))


def main() raises:
    print("=== tls crypto benchmarks ===")
    bench_aead()
    bench_x25519()
    bench_p256()
