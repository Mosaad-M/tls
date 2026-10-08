# ============================================================================
# test_chacha_fast.mojo — vectorized ChaCha20 / radix-2^44 Poly1305 against
# the scalar implementation of tls 1.8.1 (tests/ref_chacha20_poly1305.mojo)
# ============================================================================
# ChaCha20: every length around the 4- and 16-block steps, counters near
# 2^32 wraparound, in place. Poly1305: 2,000 random keys and messages plus
# all-0xFF keys/messages (largest limbs, final carry, h >= p). AEAD: the
# address-based seal/open against the reference, AAD 0..64, in place, and a
# forged tag that must leave the destination untouched.
# ============================================================================

from crypto.chacha20 import chacha20_encrypt, chacha20_xor_into
from crypto.poly1305 import (
    poly1305_mac, chacha20_poly1305_encrypt, chacha20_poly1305_decrypt,
    chacha20_poly1305_seal_into, chacha20_poly1305_open_into,
)
from crypto.random import csprng_bytes
from ref_chacha20_poly1305 import (
    ref_chacha20_encrypt, ref_poly1305_mac, ref_chacha20_poly1305_encrypt,
)


def run_test[test_fn: def() thin raises -> None](name: String, mut passed: Int, mut failed: Int):
    try:
        test_fn()
        print("  PASS:", name)
        passed += 1
    except e:
        print("  FAIL:", name, "-", String(e))
        failed += 1


def _rand(n: Int) raises -> List[UInt8]:
    return csprng_bytes(n) if n > 0 else List[UInt8]()


def test_chacha20_vs_reference() raises:
    var lens: List[Int] = [
        0, 1, 63, 64, 65, 255, 256, 257, 511, 512, 513, 1023, 1024, 1025,
        1087, 1088, 1089, 16383, 16384, 16385, 70000,
    ]
    var counters: List[UInt32] = [0, 1, 7, 0xFFFFFFF0, 0xFFFFFFFF]
    for n in lens:
        for ctr in counters:
            var key = _rand(32)
            var nonce = _rand(12)
            var data = _rand(n)
            var want = ref_chacha20_encrypt(key, nonce, ctr, data)
            if chacha20_encrypt(key, nonce, ctr, data) != want:
                raise Error("len " + String(n) + " counter " + String(ctr))
            # in place
            var buf = data.copy()
            chacha20_xor_into(key, nonce, ctr, Int(buf.unsafe_ptr()), Int(buf.unsafe_ptr()), n)
            if buf != want:
                raise Error("in place: len " + String(n) + " counter " + String(ctr))


def test_poly1305_vs_reference() raises:
    var seed = csprng_bytes(4000)
    for c in range(2000):
        var n = Int(seed[2 * c]) | (Int(seed[2 * c + 1]) << 8)
        n = n % 2100 if c % 20 != 0 else n % 70000
        var key = _rand(32)
        var msg = _rand(n)
        if poly1305_mac(key, msg) != ref_poly1305_mac(key, msg):
            raise Error("random case " + String(c) + " (len " + String(n) + ")")
    # extremes: largest limbs everywhere
    var ones = List[UInt8](length=32, fill=0xFF)
    for n in [0, 1, 15, 16, 17, 31, 32, 33, 48, 64, 1000, 16384]:
        var m = List[UInt8](length=n, fill=0xFF)
        if poly1305_mac(ones, m) != ref_poly1305_mac(ones, m):
            raise Error("all-0xFF, len " + String(n))
        var zk = List[UInt8](length=32, fill=0)
        if poly1305_mac(zk, m) != ref_poly1305_mac(zk, m):
            raise Error("zero key, len " + String(n))


def test_aead_into_vs_reference() raises:
    var lens: List[Int] = [0, 1, 15, 16, 17, 63, 64, 65, 255, 256, 257, 1025, 16384, 16385]
    for i in range(65 + len(lens)):
        var n = lens[i - 65] if i >= 65 else 300
        var aad_len = i if i < 65 else 13
        var key = _rand(32)
        var nonce = _rand(12)
        var pt = _rand(n)
        var aad = _rand(aad_len)
        var want = ref_chacha20_poly1305_encrypt(key, nonce, aad, pt)
        var what = "len " + String(n) + ", aad " + String(aad_len)

        var got = chacha20_poly1305_encrypt(key, nonce, aad, pt)
        if got[0] != want[0] or got[1] != want[1]:
            raise Error(what + ": List seal differs")
        if chacha20_poly1305_decrypt(key, nonce, aad, want[0], want[1]) != pt:
            raise Error(what + ": List open does not round-trip")

        # in place
        var buf = pt.copy()
        var t = chacha20_poly1305_seal_into(key, nonce, Int(aad.unsafe_ptr()), aad_len, Int(buf.unsafe_ptr()), Int(buf.unsafe_ptr()), n)
        var tag = List[UInt8]()
        for j in range(16):
            tag.append(t[j])
        if buf != want[0] or tag != want[1]:
            raise Error(what + ": in-place seal differs")
        var ok = chacha20_poly1305_open_into(key, nonce, Int(aad.unsafe_ptr()), aad_len, Int(buf.unsafe_ptr()), Int(buf.unsafe_ptr()), n, Int(tag.unsafe_ptr()))
        _ = len(tag)
        if not ok or buf != pt:
            raise Error(what + ": in-place open does not round-trip")

        # forged tag: False, destination untouched
        var bad = want[1].copy()
        bad[n % 16] ^= 0x01
        var dst = List[UInt8](length=n, fill=0xAA)
        ok = chacha20_poly1305_open_into(key, nonce, Int(aad.unsafe_ptr()), aad_len, Int(want[0].unsafe_ptr()), Int(dst.unsafe_ptr()), n, Int(bad.unsafe_ptr()))
        _ = len(bad)
        _ = len(aad)
        if ok:
            raise Error(what + ": forged tag accepted")
        for j in range(n):
            if dst[j] != 0xAA:
                raise Error(what + ": failed open wrote to dst at " + String(j))


def main() raises:
    var passed = 0
    var failed = 0
    print("test_chacha_fast")
    run_test[test_chacha20_vs_reference]("ChaCha20 vs scalar: step boundaries, counter wrap, in place", passed, failed)
    run_test[test_poly1305_vs_reference]("Poly1305 vs scalar: 2,000 random + extreme limbs", passed, failed)
    run_test[test_aead_into_vs_reference]("ChaCha20-Poly1305 seal_into/open_into vs scalar: AAD 0..64, in place, forged tag", passed, failed)
    print("Results:", passed, "passed,", failed, "failed")
    if failed > 0:
        raise Error(String(failed) + " test(s) failed")
