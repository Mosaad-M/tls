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
from crypto.gcm import gcm_encrypt, gcm_decrypt, GcmKey
from crypto.record import AeadKey, record_seal_k, record_open_k, record_seal, CIPHER_AES_128_GCM, CTYPE_APPLICATION_DATA
from crypto.random import csprng_bytes
from ref_aes_table import RefAES
from ref_gcm_table import ref_gcm_encrypt
from crypto.p256 import p256_public_key, p256_ecdh, p256_ecdsa_sign, p256_ecdsa_verify
from ref_p256_bigint import ref_p256_public_key, ref_p256_ecdh, ref_p256_ecdsa_sign, ref_p256_ecdsa_verify
from crypto.p384 import p384_public_key, p384_ecdh, p384_ecdsa_verify
from ref_p384_bigint import (
    _p384_p, _p384_gx, _p384_gy, _p384_scalar_mul_affine, _p384_to_affine,
    ref_p384_ecdsa_verify,
)
import crypto.ec_ct as ct
from std.collections import InlineArray
from crypto.bigint import bigint_from_bytes, bigint_to_bytes


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


def test_gcm_key_reuse_matches_reference() raises:
    # One prepared key, many records with different nonces and lengths
    for key_len in [16, 32]:
        var key = csprng_bytes(key_len)
        var gk = GcmKey(key)
        for n in range(0, 200, 7):
            var iv = csprng_bytes(12)
            var pt = csprng_bytes(n)
            var aad = csprng_bytes(13)
            var got = gk.seal(iv, pt, aad)
            var want = ref_gcm_encrypt(key, iv, pt, aad)
            _same(got[0], want[0], "reused-key ciphertext len " + String(n))
            _same(got[1], want[1], "reused-key tag len " + String(n))
            _same(gk.open(iv, got[0], got[1], aad), pt, "reused-key round trip")


def test_aead_key_follows_key_changes() raises:
    # The cache must notice a new key (KeyUpdate) and never reuse the old one
    var ak = AeadKey()
    var iv = csprng_bytes(12)
    var k1 = csprng_bytes(16)
    var k2 = csprng_bytes(16)
    var pt = csprng_bytes(40)
    _same(record_seal_k(ak, CIPHER_AES_128_GCM, k1, iv, 0, CTYPE_APPLICATION_DATA, pt),
          record_seal(CIPHER_AES_128_GCM, k1, iv, 0, CTYPE_APPLICATION_DATA, pt), "first key")
    _same(record_seal_k(ak, CIPHER_AES_128_GCM, k2, iv, 0, CTYPE_APPLICATION_DATA, pt),
          record_seal(CIPHER_AES_128_GCM, k2, iv, 0, CTYPE_APPLICATION_DATA, pt), "after a key change")
    var rec = record_seal(CIPHER_AES_128_GCM, k1, iv, 5, CTYPE_APPLICATION_DATA, pt)
    _same(record_open_k(ak, CIPHER_AES_128_GCM, k1, iv, 5, rec)[1], pt, "back to the first key")


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


# ── P-384 ───────────────────────────────────────────────────────────────────

def _ref_p384_public_key(k: List[UInt8]) raises -> List[UInt8]:
    """k*G with the BigInt ladder that P-384 verification uses."""
    var p = _p384_p()
    var aff = _p384_to_affine(_p384_scalar_mul_affine(bigint_from_bytes(k), _p384_gx(), _p384_gy(), p), p)
    var out = List[UInt8]()
    out.append(0x04)
    var xb = bigint_to_bytes(aff[0], 48)
    var yb = bigint_to_bytes(aff[1], 48)
    for i in range(48):
        out.append(xb[i])
    for i in range(48):
        out.append(yb[i])
    return out^


def _scalar48(tail: List[UInt8]) -> List[UInt8]:
    var out = List[UInt8](capacity=48)
    for _ in range(48 - len(tail)):
        out.append(0)
    for i in range(len(tail)):
        out.append(tail[i])
    return out^


def test_p384_public_key_matches_reference() raises:
    var scalars = List[List[UInt8]]()
    scalars.append(_scalar48([1]))
    scalars.append(_scalar48([2]))
    scalars.append(_scalar48([0x01, 0x00, 0x01]))
    # n - 1
    scalars.append(_from_hex("ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52972"))
    for _ in range(6):
        var k = csprng_bytes(48)
        k[0] &= 0x7F
        scalars.append(k^)
    for i in range(len(scalars)):
        _same(p384_public_key(scalars[i]), _ref_p384_public_key(scalars[i]), "P-384 k*G #" + String(i))


def test_p384_nist_cdh_vector() raises:
    # NIST CAVP ECC CDH primitive test vectors, P-384, COUNT = 0
    var d = _from_hex("3cc3122a68f0d95027ad38c067916ba0eb8c38894d22e1b15618b6818a661774ad463b205da88cf699ab4d43c9cf98a1")
    var peer = List[UInt8]()
    peer.append(0x04)
    var qx = _from_hex("a7c76b970c3b5fe8b05d2838ae04ab47697b9eaf52e764592efda27fe7513272734466b400091adbf2d68c58e0c50066")
    var qy = _from_hex("ac68f19f2e1cb879aed43a9969b91a0839c4c38a49749b661efedf243451915ed0905a32b060992b468c64766fc8437a")
    for i in range(48):
        peer.append(qx[i])
    for i in range(48):
        peer.append(qy[i])
    _same(p384_ecdh(d, peer),
          _from_hex("5f9d29dc5e31a163060356213669c8ce132e22f57c9a04f40ba7fcead493b457e5621e766c40a2e3d4d6a04b25e533f1"),
          "CAVP P-384 Z")
    var want = List[UInt8]()
    want.append(0x04)
    var ux = _from_hex("9803807f2f6d2fd966cdd0290bd410c0190352fbec7ff6247de1302df86f25d34fe4a97bef60cff548355c015dbb3e5f")
    var uy = _from_hex("ba26ca69ec2f5b5d9dad20cc9da711383a9dbe34ea3fa5a2af75b46502629ad54dd8b7d73a8abb06a3a3be47d650cc99")
    for i in range(48):
        want.append(ux[i])
    for i in range(48):
        want.append(uy[i])
    _same(p384_public_key(d), want, "CAVP P-384 Q_IUT")


def test_p384_ecdh_agrees() raises:
    var a = csprng_bytes(48)
    a[0] &= 0x7F
    var b = csprng_bytes(48)
    b[0] &= 0x7F
    _same(p384_ecdh(a, p384_public_key(b)), p384_ecdh(b, p384_public_key(a)), "P-384 ECDH agreement")


def test_p384_rejects_off_curve_peer() raises:
    var pub = p384_public_key(_scalar48([7]))
    pub[96] ^= 1
    var raised = False
    try:
        _ = p384_ecdh(_scalar48([3]), pub)
    except:
        raised = True
    if not raised:
        raise Error("off-curve P-384 peer key accepted")


# ── ECDSA verification: 64-bit Montgomery (ec_ct) vs the BigInt reference ──

def _sign_with[N: Int](c: ct.Curve[N], d: List[UInt8], h: List[UInt8]) raises -> Tuple[List[UInt8], List[UInt8]]:
    """A valid ECDSA signature built from ec_ct primitives (tests only:
    random nonce, no low-s)."""
    var om = c.order.copy()
    while True:
        var k = csprng_bytes(8 * N)
        k[0] &= 0x7F
        if not ct.scalar_in_range(k, om):
            continue
        var big_r = ct.to_affine(ct.scalar_mult(k, c.g, c), c.field)
        var r = ct.reduce_once(big_r[0], om)
        var e = ct.reduce_once(ct.limbs_from_be[N](h, 0), om)
        var rd = ct.mont_mul(ct.to_mont(r, om), ct.to_mont(ct.limbs_from_be[N](d, 0), om), om)
        var sum = ct.add(ct.to_mont(e, om), rd, om)
        var s = ct.from_mont(ct.mont_mul(ct.mont_inv(ct.to_mont(ct.limbs_from_be[N](k, 0), om), om), sum, om), om)
        if ct.is_zero(r) == 1 or ct.is_zero(s) == 1:
            continue
        return (ct.limbs_to_be(r), ct.limbs_to_be(s))


def _verifies_256(pub: List[UInt8], h: List[UInt8], r: List[UInt8], s: List[UInt8]) -> Tuple[Bool, Bool]:
    var new_ok = True
    var ref_ok = True
    try:
        p256_ecdsa_verify(pub, h, r, s)
    except:
        new_ok = False
    try:
        ref_p256_ecdsa_verify(pub, h, r, s)
    except:
        ref_ok = False
    return (new_ok, ref_ok)


def _verifies_384(pub: List[UInt8], h: List[UInt8], r: List[UInt8], s: List[UInt8]) -> Tuple[Bool, Bool]:
    var new_ok = True
    var ref_ok = True
    try:
        p384_ecdsa_verify(pub, h, r, s)
    except:
        new_ok = False
    try:
        ref_p384_ecdsa_verify(pub, h, r, s)
    except:
        ref_ok = False
    return (new_ok, ref_ok)


def _bump(v: List[UInt8], i: Int) -> List[UInt8]:
    var w = v.copy()
    w[i] ^= 0x01
    return w^


def _negatives(n_hex: String, size: Int, pub: List[UInt8], h: List[UInt8], r: List[UInt8], s: List[UInt8]) -> List[List[List[UInt8]]]:
    """(pub, hash, r, s) variants that must all be rejected."""
    var out = List[List[List[UInt8]]]()
    var zero = List[UInt8](length=size, fill=0)
    var n = _from_hex(n_hex)
    var bad_pub = pub.copy()
    bad_pub[len(bad_pub) - 1] ^= 0x01               # off the curve
    var inf = List[UInt8](length=len(pub), fill=0)
    inf[0] = 0x04                                    # (0, 0): not a point
    var big = List[UInt8](length=size + 1, fill=0xFF)  # wider than the order
    out.append([pub.copy(), _bump(h, 0), r.copy(), s.copy()])
    out.append([pub.copy(), h.copy(), _bump(r, size - 1), s.copy()])
    out.append([pub.copy(), h.copy(), r.copy(), _bump(s, size - 1)])
    out.append([pub.copy(), h.copy(), zero.copy(), s.copy()])
    out.append([pub.copy(), h.copy(), r.copy(), zero.copy()])
    out.append([pub.copy(), h.copy(), n.copy(), s.copy()])
    out.append([pub.copy(), h.copy(), r.copy(), n.copy()])
    out.append([pub.copy(), h.copy(), big.copy(), s.copy()])
    out.append([bad_pub^, h.copy(), r.copy(), s.copy()])
    out.append([inf^, h.copy(), r.copy(), s.copy()])
    out.append([pub.copy(), h.copy(), s.copy(), r.copy()])  # r and s swapped
    return out^


def test_p256_verify_matches_reference() raises:
    var c = ct.p256_curve()
    var n_hex = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"
    for i in range(24):
        var d = csprng_bytes(32)
        d[0] &= 0x7F
        var pub = p256_public_key(d)
        var h = csprng_bytes(32)
        var sig = _sign_with(c, d, h)
        var ok = _verifies_256(pub, h, sig[0], sig[1])
        if not ok[0] or not ok[1]:
            raise Error("valid signature #" + String(i) + " rejected: new=" + String(ok[0]) + " ref=" + String(ok[1]))
        # also tls's own signer (low-s, deterministic nonce)
        var own = p256_ecdsa_sign(d, h, csprng_bytes(32))
        if not _verifies_256(pub, h, own[0], own[1])[0]:
            raise Error("p256_ecdsa_sign output rejected #" + String(i))
        var negs = _negatives(n_hex, 32, pub, h, sig[0], sig[1])
        for j in range(len(negs)):
            var v = _verifies_256(negs[j][0], negs[j][1], negs[j][2], negs[j][3])
            if v[0] or v[1]:
                raise Error("negative #" + String(j) + " accepted: new=" + String(v[0]) + " ref=" + String(v[1]))


def test_p384_verify_matches_reference() raises:
    var c = ct.p384_curve()
    var n_hex = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973"
    for i in range(8):
        var d = csprng_bytes(48)
        d[0] &= 0x7F
        var pub = p384_public_key(d)
        var h = csprng_bytes(48)
        var sig = _sign_with(c, d, h)
        var ok = _verifies_384(pub, h, sig[0], sig[1])
        if not ok[0] or not ok[1]:
            raise Error("valid signature #" + String(i) + " rejected: new=" + String(ok[0]) + " ref=" + String(ok[1]))
        var negs = _negatives(n_hex, 48, pub, h, sig[0], sig[1])
        for j in range(len(negs)):
            var v = _verifies_384(negs[j][0], negs[j][1], negs[j][2], negs[j][3])
            if v[0] or v[1]:
                raise Error("negative #" + String(j) + " accepted: new=" + String(v[0]) + " ref=" + String(v[1]))


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
    run_test[test_gcm_key_reuse_matches_reference]("GcmKey reused across records vs table GCM", passed, failed)
    run_test[test_aead_key_follows_key_changes]("AeadKey cache follows key changes", passed, failed)
    run_test[test_p256_public_key_matches_reference]("P-256 k*G vs BigInt ladder (edge + random)", passed, failed)
    run_test[test_p256_ecdh_matches_reference]("P-256 ECDH vs BigInt ladder (edge + random)", passed, failed)
    run_test[test_p256_nist_cdh_vector]("P-256 NIST CAVP ECC CDH vector", passed, failed)
    run_test[test_p256_sign_matches_reference]("P-256 ECDSA signatures identical to BigInt signer", passed, failed)
    run_test[test_p256_rejects_bad_scalars]("P-256 rejects private keys 0 and n", passed, failed)
    run_test[test_p384_public_key_matches_reference]("P-384 k*G vs BigInt ladder (edge + random)", passed, failed)
    run_test[test_p384_nist_cdh_vector]("P-384 NIST CAVP ECC CDH vector", passed, failed)
    run_test[test_p384_ecdh_agrees]("P-384 ECDH both directions agree", passed, failed)
    run_test[test_p384_rejects_off_curve_peer]("P-384 ECDH rejects an off-curve peer key", passed, failed)
    run_test[test_p256_verify_matches_reference]("P-256 ECDSA verify vs BigInt reference (valid + 11 negatives each)", passed, failed)
    run_test[test_p384_verify_matches_reference]("P-384 ECDSA verify vs BigInt reference (valid + 11 negatives each)", passed, failed)
    print()
    print("Results:", passed, "passed,", failed, "failed")
    if failed > 0:
        raise Error(String(failed) + " test(s) failed")
