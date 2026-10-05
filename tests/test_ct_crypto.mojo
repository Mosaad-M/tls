# ============================================================================
# test_ct_crypto.mojo — constant-time crypto against reference implementations
# ============================================================================
# The constant-time AES / AES-GCM (crypto/aes.mojo, crypto/gcm.mojo) and the
# constant-time P-256 secret-key operations (crypto/p256.mojo) must give the
# same results as the previous implementations, which are kept as test
# oracles (tests/ref_*.mojo; the old P-256 BigInt ladder still serves
# signature verification). Run with: mojo run -I . -I tests ...
# ============================================================================

from crypto.aes import AES
from crypto.gcm import gcm_encrypt, gcm_decrypt
from crypto.random import csprng_bytes
from ref_aes_table import RefAES
from ref_gcm_table import ref_gcm_encrypt
from crypto.p256 import p256_public_key, p256_ecdh, p256_ecdsa_sign, p256_ecdsa_verify
from ref_p256_bigint import ref_p256_public_key, ref_p256_ecdh, ref_p256_ecdsa_sign


def run_test[test_fn: def() thin raises -> None](
    name: String,
    mut passed: Int,
    mut failed: Int,
):
    try:
        test_fn()
        print("  PASS:", name)
        passed += 1
    except e:
        print("  FAIL:", name, "-", String(e))
        failed += 1


def _hex(b: List[UInt8]) -> String:
    var digits = "0123456789abcdef".as_bytes()
    var out = String()
    for i in range(len(b)):
        out += chr(Int(digits[Int(b[i] >> 4)]))
        out += chr(Int(digits[Int(b[i] & 0x0F)]))
    return out


def _same(a: List[UInt8], b: List[UInt8], what: String) raises:
    if len(a) != len(b):
        raise Error(what + ": length " + String(len(a)) + " vs " + String(len(b)))
    for i in range(len(a)):
        if a[i] != b[i]:
            raise Error(what + ": " + _hex(a) + " != " + _hex(b))


# ── AES ─────────────────────────────────────────────────────────────────────

def test_aes_matches_reference() raises:
    for key_len in [16, 32]:
        for _ in range(50):
            var key = csprng_bytes(key_len)
            var block = csprng_bytes(16)
            _same(AES(key).encrypt_block(block), RefAES(key).encrypt_block(block),
                  "AES-" + String(key_len * 8) + " block")


def test_aes_blocks4_matches_single() raises:
    var key = csprng_bytes(32)
    var aes = AES(key)
    var four = csprng_bytes(64)
    var enc = aes.encrypt_blocks4(four)
    for b in range(4):
        var one = List[UInt8]()
        var want = List[UInt8]()
        for i in range(16):
            one.append(four[b * 16 + i])
            want.append(enc[b * 16 + i])
        _same(RefAES(key).encrypt_block(one), want, "block " + String(b) + " of 4")


def test_gcm_matches_reference() raises:
    # Every length 0..100 covers empty, partial, whole, and 4-block-batch
    # boundaries for both the CTR keystream and GHASH.
    for key_len in [16, 32]:
        for n in range(101):
            var key = csprng_bytes(key_len)
            var iv = csprng_bytes(12)
            var pt = csprng_bytes(n)
            var aad = csprng_bytes(n % 23)
            var got = gcm_encrypt(key, iv, pt, aad)
            var want = ref_gcm_encrypt(key, iv, pt, aad)
            _same(got[0], want[0], "GCM ciphertext len " + String(n))
            _same(got[1], want[1], "GCM tag len " + String(n))
            _same(gcm_decrypt(key, iv, got[0], got[1], aad), pt, "GCM round trip")


def test_gcm_long_message() raises:
    var key = csprng_bytes(16)
    var iv = csprng_bytes(12)
    var pt = csprng_bytes(16384 + 7)
    var aad = csprng_bytes(13)
    var got = gcm_encrypt(key, iv, pt, aad)
    var want = ref_gcm_encrypt(key, iv, pt, aad)
    _same(got[0], want[0], "GCM 16 KiB ciphertext")
    _same(got[1], want[1], "GCM 16 KiB tag")


def test_gcm_rejects_bad_tag() raises:
    var key = csprng_bytes(16)
    var iv = csprng_bytes(12)
    var got = gcm_encrypt(key, iv, csprng_bytes(40), List[UInt8]())
    var tag = got[1].copy()
    tag[0] ^= 1
    var raised = False
    try:
        _ = gcm_decrypt(key, iv, got[0], tag, List[UInt8]())
    except:
        raised = True
    if not raised:
        raise Error("tampered tag accepted")


# ── P-256 ───────────────────────────────────────────────────────────────────

def _from_hex(h: String) -> List[UInt8]:
    var raw = h.as_bytes()
    var out = List[UInt8](capacity=len(raw) // 2)
    for i in range(0, len(raw) - 1, 2):
        var hi = raw[i]
        var lo = raw[i + 1]
        var a: UInt8 = (hi - 48) if hi <= 57 else (hi - 87)
        var b: UInt8 = (lo - 48) if lo <= 57 else (lo - 87)
        out.append((a << 4) | b)
    return out^


def _scalar(last_bytes: List[UInt8]) -> List[UInt8]:
    """32-byte big-endian scalar ending in last_bytes (leading zeros)."""
    var out = List[UInt8](capacity=32)
    for _ in range(32 - len(last_bytes)):
        out.append(0)
    for i in range(len(last_bytes)):
        out.append(last_bytes[i])
    return out^


def _edge_scalars() -> List[List[UInt8]]:
    var out = List[List[UInt8]]()
    out.append(_scalar([1]))
    out.append(_scalar([2]))
    out.append(_scalar([0x01, 0xFF]))                  # 247 leading zero bits
    out.append(_scalar([0x80, 0, 0, 0, 0, 0, 0, 0]))  # single high bit, short
    # n - 1
    out.append(_from_hex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550"))
    return out^


def test_p256_public_key_matches_reference() raises:
    var scalars = _edge_scalars()
    for _ in range(20):
        var k = csprng_bytes(32)
        k[0] &= 0x7F  # stay below n
        scalars.append(k^)
    for i in range(len(scalars)):
        _same(p256_public_key(scalars[i]), ref_p256_public_key(scalars[i]), "k*G #" + String(i))


def test_p256_ecdh_matches_reference() raises:
    var peer = ref_p256_public_key(_scalar(csprng_bytes(31)))
    var scalars = _edge_scalars()
    for _ in range(10):
        var k = csprng_bytes(32)
        k[0] &= 0x7F
        scalars.append(k^)
    for i in range(len(scalars)):
        _same(p256_ecdh(scalars[i], peer), ref_p256_ecdh(scalars[i], peer), "ECDH #" + String(i))


def test_p256_nist_cdh_vector() raises:
    # NIST CAVP ECC CDH primitive test vectors, P-256, COUNT = 0
    var d = _from_hex("7d7dc5f71eb29ddaf80d6214632eeae03d9058af1fb6d22ed80badb62bc1a534")
    var peer = List[UInt8]()
    peer.append(0x04)
    var qx = _from_hex("700c48f77f56584c5cc632ca65640db91b6bacce3a4df6b42ce7cc838833d287")
    var qy = _from_hex("db71e509e3fd9b060ddb20ba5c51dcc5948d46fbf640dfe0441782cab85fa4ac")
    for i in range(32):
        peer.append(qx[i])
    for i in range(32):
        peer.append(qy[i])
    _same(p256_ecdh(d, peer),
          _from_hex("46fc62106420ff012e54a434fbdd2d25ccc5852060561e68040dd7778997bd7b"),
          "CAVP Z")
    var pub = p256_public_key(d)
    var want = List[UInt8]()
    want.append(0x04)
    var ux = _from_hex("ead218590119e8876b29146ff89ca61770c4edbbf97d38ce385ed281d8a6b230")
    var uy = _from_hex("28af61281fd35e2fa7002523acc85a429cb06ee6648325389f59edfce1405141")
    for i in range(32):
        want.append(ux[i])
    for i in range(32):
        want.append(uy[i])
    _same(pub, want, "CAVP Q_IUT")


def test_p256_sign_matches_reference() raises:
    # The nonce derivation is deterministic, so signatures must be identical.
    for i in range(10):
        var d = csprng_bytes(32)
        d[0] &= 0x7F
        var h = csprng_bytes(32)
        var nonce = csprng_bytes(32)
        var got = p256_ecdsa_sign(d, h, nonce)
        var want = ref_p256_ecdsa_sign(d, h, nonce)
        _same(got[0], want[0], "r #" + String(i))
        _same(got[1], want[1], "s #" + String(i))
        p256_ecdsa_verify(p256_public_key(d), h, got[0], got[1])


def test_p256_rejects_bad_scalars() raises:
    var zero = _scalar([0])
    var n = _from_hex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551")
    for k in [zero.copy(), n.copy()]:
        var raised = False
        try:
            _ = p256_public_key(k)
        except:
            raised = True
        if not raised:
            raise Error("out-of-range private key accepted")


def main() raises:
    var passed = 0
    var failed = 0
    print("=== Constant-time crypto vs reference ===")
    print()
    run_test[test_aes_matches_reference]("AES-128/256 single blocks vs table AES", passed, failed)
    run_test[test_aes_blocks4_matches_single]("AES 4-block batch vs single blocks", passed, failed)
    run_test[test_gcm_matches_reference]("AES-GCM lengths 0..100 vs table GCM", passed, failed)
    run_test[test_gcm_long_message]("AES-GCM 16 KiB record vs table GCM", passed, failed)
    run_test[test_gcm_rejects_bad_tag]("AES-GCM rejects a tampered tag", passed, failed)
    run_test[test_p256_public_key_matches_reference]("P-256 k*G vs BigInt ladder (edge + random)", passed, failed)
    run_test[test_p256_ecdh_matches_reference]("P-256 ECDH vs BigInt ladder (edge + random)", passed, failed)
    run_test[test_p256_nist_cdh_vector]("P-256 NIST CAVP ECC CDH vector", passed, failed)
    run_test[test_p256_sign_matches_reference]("P-256 ECDSA signatures identical to BigInt signer", passed, failed)
    run_test[test_p256_rejects_bad_scalars]("P-256 rejects private keys 0 and n", passed, failed)
    print()
    print("Results:", passed, "passed,", failed, "failed")
    if failed > 0:
        raise Error(String(failed) + " test(s) failed")
