# ============================================================================
# ct_check.mojo — dudect-style timing-leak check (manual, not in CI)
# ============================================================================
# For each primitive, time many runs on two input classes, interleaved in a
# random order: a fixed secret input vs random secret inputs. Welch's t-test
# compares the two timing distributions (after cropping the slowest 10% to
# remove interrupts). |t| > 4.5 is the usual dudect threshold for "the timing
# depends on the secret". The old table / BigInt implementations (tests/ref_*)
# run alongside the constant-time ones for comparison.
#
#   pixi run mojo run -I . -I tests bench/ct_check.mojo
# Timing tests are noisy; run on an idle machine and compare relative values.
# ============================================================================

from std.time import perf_counter_ns
from std.math import sqrt
from crypto.aes import AES
from crypto.gcm import gcm_encrypt
from crypto.aes_hw import GCM_HW
from crypto.p256 import p256_ecdh, p256_public_key
from crypto.random import csprng_bytes
from ref_aes_table import RefAES
from ref_gcm_table import ref_gcm_encrypt
from ref_p256_bigint import ref_p256_ecdh


def _welch_t(a: List[Float64], b: List[Float64]) -> Float64:
    """Welch's t over the fastest 90% of the pooled samples."""
    var all = List[Float64]()
    for i in range(len(a)):
        all.append(a[i])
    for i in range(len(b)):
        all.append(b[i])
    sort(all)
    var cut = all[Int(Float64(len(all)) * 0.9)]
    var n1 = 0.0
    var s1 = 0.0
    var q1 = 0.0
    for i in range(len(a)):
        if a[i] <= cut:
            n1 += 1.0
            s1 += a[i]
            q1 += a[i] * a[i]
    var n2 = 0.0
    var s2 = 0.0
    var q2 = 0.0
    for i in range(len(b)):
        if b[i] <= cut:
            n2 += 1.0
            s2 += b[i]
            q2 += b[i] * b[i]
    var m1 = s1 / n1
    var m2 = s2 / n2
    var v1 = q1 / n1 - m1 * m1
    var v2 = q2 / n2 - m2 * m2
    var den = sqrt(v1 / n1 + v2 / n2)
    if den == 0.0:
        return 0.0
    return (m1 - m2) / den


def _report(name: String, t: Float64):
    var verdict = "LEAK" if abs(t) > 4.5 else "ok"
    print("  " + name + ": t = " + String(Float64(Int(t * 100)) / 100.0) + "  (" + verdict + ")")


def _classes(n: Int) raises -> List[Bool]:
    var r = csprng_bytes(n)
    var out = List[Bool](capacity=n)
    for i in range(n):
        out.append((r[i] & 1) == 1)
    return out^


def check_aes(n: Int) raises:
    var key = csprng_bytes(16)
    var fixed = List[UInt8](capacity=16)
    for _ in range(16):
        fixed.append(0)
    var classes = _classes(n)
    var inputs = List[List[UInt8]]()
    for i in range(n):
        inputs.append(fixed.copy() if classes[i] else csprng_bytes(16))
    var aes = AES(key)
    var old_aes = RefAES(key)
    var a_new = List[Float64]()
    var b_new = List[Float64]()
    var a_old = List[Float64]()
    var b_old = List[Float64]()
    for i in range(n):
        var t0 = perf_counter_ns()
        _ = aes.encrypt_block(inputs[i])
        var t1 = perf_counter_ns()
        _ = old_aes.encrypt_block(inputs[i])
        var t2 = perf_counter_ns()
        if classes[i]:
            a_new.append(Float64(t1 - t0))
            a_old.append(Float64(t2 - t1))
        else:
            b_new.append(Float64(t1 - t0))
            b_old.append(Float64(t2 - t1))
    print("AES-128 block, fixed vs random plaintext (" + String(n) + " runs):")
    _report("table AES (1.4.5)     ", _welch_t(a_old, b_old))
    _report("bitsliced AES (1.4.6) ", _welch_t(a_new, b_new))


def check_gcm(n: Int) raises:
    # Secret: the key (hence H). Fixed key vs random keys, same message.
    var fixed_key = csprng_bytes(16)
    var iv = csprng_bytes(12)
    var msg = csprng_bytes(64)
    var aad = List[UInt8]()
    var classes = _classes(n)
    var keys = List[List[UInt8]]()
    for i in range(n):
        keys.append(fixed_key.copy() if classes[i] else csprng_bytes(16))
    var a_new = List[Float64]()
    var b_new = List[Float64]()
    var a_old = List[Float64]()
    var b_old = List[Float64]()
    for i in range(n):
        var t0 = perf_counter_ns()
        _ = gcm_encrypt(keys[i], iv, msg, aad)
        var t1 = perf_counter_ns()
        _ = ref_gcm_encrypt(keys[i], iv, msg, aad)
        var t2 = perf_counter_ns()
        if classes[i]:
            a_new.append(Float64(t1 - t0))
            a_old.append(Float64(t2 - t1))
        else:
            b_new.append(Float64(t1 - t0))
            b_old.append(Float64(t2 - t1))
    print("AES-GCM 64 bytes, fixed vs random key (" + String(n) + " runs):")
    _report("table GCM (1.4.5)     ", _welch_t(a_old, b_old))
    comptime if GCM_HW:
        _report("hardware AES-GCM (1.8)", _welch_t(a_new, b_new))
    else:
        _report("constant-time (1.4.6) ", _welch_t(a_new, b_new))


def check_p256(n: Int) raises:
    # Secret: the scalar. Fixed scalar with 192 leading zero bits (the
    # Minerva case) vs random full-length scalars.
    var peer = p256_public_key(_short(csprng_bytes(31)))
    var small = _short(csprng_bytes(8))
    var classes = _classes(n)
    var scalars = List[List[UInt8]]()
    for i in range(n):
        if classes[i]:
            scalars.append(small.copy())
        else:
            var k = csprng_bytes(32)
            k[0] &= 0x7F
            k[0] |= 0x40
            scalars.append(k^)
    var a_new = List[Float64]()
    var b_new = List[Float64]()
    var a_old = List[Float64]()
    var b_old = List[Float64]()
    for i in range(n):
        var t0 = perf_counter_ns()
        _ = p256_ecdh(scalars[i], peer)
        var t1 = perf_counter_ns()
        _ = ref_p256_ecdh(scalars[i], peer)
        var t2 = perf_counter_ns()
        if classes[i]:
            a_new.append(Float64(t1 - t0))
            a_old.append(Float64(t2 - t1))
        else:
            b_new.append(Float64(t1 - t0))
            b_old.append(Float64(t2 - t1))
    print("P-256 ECDH, 64-bit vs 255-bit scalar (" + String(n) + " runs):")
    _report("BigInt ladder (1.4.5)  ", _welch_t(a_old, b_old))
    _report("constant-time (1.4.6)  ", _welch_t(a_new, b_new))


def _short(tail: List[UInt8]) -> List[UInt8]:
    var out = List[UInt8](capacity=32)
    for _ in range(32 - len(tail)):
        out.append(0)
    for i in range(len(tail)):
        out.append(tail[i])
    if len(tail) > 0 and out[32 - len(tail)] == 0:
        out[32 - len(tail)] = 1
    return out^


def main() raises:
    print("=== dudect-style timing check (|t| > 4.5 = timing depends on the secret) ===")
    check_aes(20000)
    check_gcm(4000)
    check_p256(300)
