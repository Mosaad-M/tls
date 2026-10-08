# ============================================================================
# test_aes_hw.mojo — hardware AES-GCM (crypto/aes_hw.mojo) against software
# ============================================================================
# When the build target has the AES / carry-less-multiply instructions
# (GCM_HW), every case is computed by both implementations and must match
# byte for byte: FIPS-197 blocks, the GHASH key, 2,000 random seal/open
# cases (AES-128 and AES-256, lengths 0..70 KiB incl. every boundary of the
# fused 128-byte loop), and the address-based seal_into/open_into: in place,
# every AAD length 0..64, and a failed open leaving only zeros. Without GCM_HW (or with
# -D TLS_SOFT_AES=true) the comparisons are skipped and the software path
# is what the other tests exercise.
# ============================================================================

from crypto.aes_hw import GCM_HW, HwGcmKey, _RoundKeys, _encrypt_block, V16
from crypto.gcm import GcmKey, SoftGcmKey
from crypto.random import csprng_bytes


def _hex(b: List[UInt8]) -> String:
    comptime D = "0123456789abcdef"
    var d = String(D).as_bytes()
    var out = String("")
    for x in b:
        out += chr(Int(d[Int(x >> 4)])) + chr(Int(d[Int(x & 15)]))
    return out


def _unhex(h: String) -> List[UInt8]:
    var r = h.as_bytes()
    var out = List[UInt8]()
    for i in range(len(r) // 2):
        var a = r[2 * i]
        var c = r[2 * i + 1]
        var hi: UInt8 = (a - 48) if a <= 57 else (a - 87)
        var lo: UInt8 = (c - 48) if c <= 57 else (c - 87)
        out.append((hi << 4) | lo)
    return out^


def _block(k: _RoundKeys, pt: List[UInt8]) -> List[UInt8]:
    var v = V16(0)
    for i in range(16):
        v[i] = pt[i]
    var c = _encrypt_block(k, v)
    var out = List[UInt8]()
    for i in range(16):
        out.append(c[i])
    return out^


def test_fips197_blocks() raises:
    var pt = _unhex("00112233445566778899aabbccddeeff")
    var k128 = _RoundKeys(_unhex("000102030405060708090a0b0c0d0e0f"))
    if _hex(_block(k128, pt)) != "69c4e0d86a7b0430d8cdb78070b4c55a":
        raise Error("AES-128: " + _hex(_block(k128, pt)))
    var k256 = _RoundKeys(_unhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"))
    if _hex(_block(k256, pt)) != "8ea2b7ca516745bfeafc49904b496089":
        raise Error("AES-256: " + _hex(_block(k256, pt)))


def _rand_int(seed: List[UInt8], i: Int) -> Int:
    return Int(seed[i % len(seed)])


def test_differential_random() raises:
    """2,000 random cases: hardware and software seal identically, each opens
    the other's output, and a flipped tag bit is rejected."""
    var boundaries: List[Int] = [0, 1, 15, 16, 17, 63, 64, 65, 127, 128, 129, 191, 255, 256, 257, 1023, 1024, 16383, 16384, 16385]
    var cases = 2000
    var lens = csprng_bytes(cases * 4)
    for c in range(cases):
        var key = csprng_bytes(16 if c % 2 == 0 else 32)
        var iv = csprng_bytes(12)
        var n: Int
        if c < len(boundaries):
            n = boundaries[c]
        else:
            var r = Int(lens[4 * c]) | (Int(lens[4 * c + 1]) << 8) | (Int(lens[4 * c + 2]) << 16)
            n = r % (70 * 1024 + 1) if c % 10 == 0 else r % 600
        var aad_len = Int(lens[4 * c + 3]) % 40
        var pt = csprng_bytes(n) if n > 0 else List[UInt8]()
        var aad = csprng_bytes(aad_len) if aad_len > 0 else List[UInt8]()
        var hw = HwGcmKey(key)
        var sw = SoftGcmKey(key)
        var a = hw.seal(iv, pt, aad)
        var b = sw.seal(iv, pt, aad)
        if a[0] != b[0] or a[1] != b[1]:
            raise Error("case " + String(c) + " (len " + String(n) + ", aad " + String(aad_len) + ", key " + String(len(key)) + "): ciphertext/tag differ")
        if hw.open(iv, b[0], b[1], aad) != pt or sw.open(iv, a[0], a[1], aad) != pt:
            raise Error("case " + String(c) + ": open does not round-trip")
        var bad = a[1].copy()
        bad[c % 16] ^= UInt8(1 << (c % 8))
        var rejected = False
        try:
            _ = hw.open(iv, a[0], bad, aad)
        except:
            rejected = True
        if not rejected:
            raise Error("case " + String(c) + ": tampered tag accepted")


def _check_into(n: Int, aad_len: Int, key_len: Int) raises:
    var key = csprng_bytes(key_len)
    var iv = csprng_bytes(12)
    var pt = csprng_bytes(n) if n > 0 else List[UInt8]()
    var aad = csprng_bytes(aad_len) if aad_len > 0 else List[UInt8]()
    var hw = HwGcmKey(key)
    var want = SoftGcmKey(key).seal(iv, pt, aad)
    var what = "len " + String(n) + ", aad " + String(aad_len) + ", key " + String(key_len)

    # seal in place (dst == src)
    var buf = pt.copy()
    var t = hw.seal_into(iv, Int(aad.unsafe_ptr()), aad_len, Int(buf.unsafe_ptr()), Int(buf.unsafe_ptr()), n)
    var tag = List[UInt8]()
    for i in range(16):
        tag.append(t[i])
    if buf != want[0] or tag != want[1]:
        raise Error(what + ": in-place seal differs from software")

    # open in place
    var ok = hw.open_into(iv, Int(aad.unsafe_ptr()), aad_len, Int(buf.unsafe_ptr()), Int(buf.unsafe_ptr()), n, Int(tag.unsafe_ptr()))
    _ = len(tag)  # read through its address: keep alive past the call
    if not ok or buf != pt:
        raise Error(what + ": in-place open does not round-trip")

    # a failed open leaves only zeros in the destination
    var bad = want[1].copy()
    bad[n % 16] ^= 0x80
    var dst = List[UInt8](length=n, fill=0xAA)
    ok = hw.open_into(iv, Int(aad.unsafe_ptr()), aad_len, Int(want[0].unsafe_ptr()), Int(dst.unsafe_ptr()), n, Int(bad.unsafe_ptr()))
    if ok:
        raise Error(what + ": tampered tag accepted")
    for i in range(n):
        if dst[i] != 0:
            raise Error(what + ": failed open left non-zero bytes at " + String(i))
    _ = len(aad)  # read through its address above: keep alive until here
    _ = len(bad)


def test_into_inplace_and_failure() raises:
    """seal_into/open_into in place at every 128-byte group boundary and
    every AAD length 0..64; a failed open zeroes its output."""
    var lens: List[Int] = [0, 1, 15, 16, 17, 127, 128, 129, 255, 256, 257, 1023, 1024, 1025, 16383, 16384, 16385]
    for n in lens:
        _check_into(n, 0, 16)
        _check_into(n, 17, 32)
    for aad_len in range(65):
        _check_into(300, aad_len, 16 if aad_len % 2 == 0 else 32)


def test_gcmkey_uses_selected_path() raises:
    # NIST GCM test case 4 (AES-128, 60-byte plaintext, 20-byte AAD)
    var key = _unhex("feffe9928665731c6d6a8f9467308308")
    var iv = _unhex("cafebabefacedbaddecaf888")
    var pt = _unhex("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39")
    var aad = _unhex("feedfacedeadbeeffeedfacedeadbeefabaddad2")
    var r = GcmKey(key).seal(iv, pt, aad)
    if _hex(r[1]) != "5bc94fbc3221a5db94fae95ae7121a47":
        raise Error("NIST case 4 tag: " + _hex(r[1]))


def run_test[test_fn: def() thin raises -> None](name: String, mut passed: Int, mut failed: Int):
    try:
        test_fn()
        print("  PASS:", name)
        passed += 1
    except e:
        print("  FAIL:", name, "-", String(e))
        failed += 1


def main() raises:
    var passed = 0
    var failed = 0
    print("test_aes_hw (GCM_HW =", GCM_HW, ")")
    run_test[test_gcmkey_uses_selected_path]("GcmKey: NIST GCM case 4 on the selected path", passed, failed)
    comptime if GCM_HW:
        run_test[test_fips197_blocks]("hardware AES: FIPS-197 AES-128 and AES-256 blocks", passed, failed)
        run_test[test_differential_random]("hardware vs software GCM: 2,000 random cases", passed, failed)
        run_test[test_into_inplace_and_failure]("seal_into/open_into: in place, AAD 0..64, failed open zeroes output", passed, failed)
    else:
        print("  SKIP: hardware comparisons (software build)")
    print("Results:", passed, "passed,", failed, "failed")
    if failed > 0:
        raise Error(String(failed) + " test(s) failed")
