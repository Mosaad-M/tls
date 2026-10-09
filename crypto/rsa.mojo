# ============================================================================
# rsa.mojo — RSA signature verification (PKCS#1 v1.5 and PSS)
# ============================================================================
# API:
#   rsa_pkcs1_verify(n_bytes, e_bytes, msg_hash, sig)           → raises on bad
#   rsa_pss_verify(n_bytes, e_bytes, msg_hash, sig, salt_len)   → raises on bad
#
# Both functions accept big-endian byte arrays for n, e, sig. msg_hash is a
# SHA-256, SHA-384 or SHA-512 digest (32, 48 or 64 bytes); its length selects
# the DigestInfo (PKCS#1) or the hash and MGF1 hash (PSS).
# ============================================================================

from crypto.bigint import (
    bigint_from_bytes, bigint_bit_len, bigint_cmp,
)
from crypto.hash import sha256, sha384, sha512


# ============================================================================
# Hashes: SHA-256, SHA-384 and SHA-512, chosen by digest length
# ============================================================================

def _check_hash_len(h_len: Int, what: String) raises:
    if h_len != 32 and h_len != 48 and h_len != 64:
        raise Error(what + ": hash must be 32, 48 or 64 bytes (SHA-256/384/512)")


def _hash(data: List[UInt8], h_len: Int) -> List[UInt8]:
    if h_len == 64:
        return sha512(data)
    if h_len == 48:
        return sha384(data)
    return sha256(data)


def _digest_info(h_len: Int) -> List[UInt8]:
    """PKCS#1 v1.5 DigestInfo prefix (RFC 8017 §9.2 note 1):
    30 L 30 0d 06 09 60 86 48 01 65 03 04 02 id 05 00 04 h_len, where
    (L, id) = (0x31, 1) SHA-256, (0x41, 2) SHA-384, (0x51, 3) SHA-512."""
    var b = List[UInt8](capacity=19)
    b.append(0x30); b.append(UInt8(0x11 + h_len))
    b.append(0x30); b.append(0x0D)
    b.append(0x06); b.append(0x09)
    b.append(0x60); b.append(0x86); b.append(0x48); b.append(0x01)
    b.append(0x65); b.append(0x03); b.append(0x04); b.append(0x02)
    b.append(UInt8(1 if h_len == 32 else (2 if h_len == 48 else 3)))
    b.append(0x05); b.append(0x00)
    b.append(0x04); b.append(UInt8(h_len))
    return b^


def _mgf1(seed: List[UInt8], length: Int, h_len: Int) -> List[UInt8]:
    """MGF1(seed, length) with the hash whose digest is h_len bytes."""
    var out = List[UInt8](capacity=length)
    var counter: UInt32 = 0
    while len(out) < length:
        # Build seed || counter (4-byte big-endian)
        var input = List[UInt8](capacity=len(seed) + 4)
        for i in range(len(seed)):
            input.append(seed[i])
        input.append(UInt8((counter >> 24) & 0xFF))
        input.append(UInt8((counter >> 16) & 0xFF))
        input.append(UInt8((counter >> 8) & 0xFF))
        input.append(UInt8(counter & 0xFF))
        var h = _hash(input, h_len)
        for i in range(len(h)):
            if len(out) < length:
                out.append(h[i])
        counter += 1
    return out^


# ============================================================================
# Internal: sig^e mod n → zero-padded EM bytes
# ============================================================================

# ============================================================================
# sig^e mod n: Montgomery exponentiation on 64-bit limbs
# ============================================================================
# Verification handles only public data, so the exponent may be scanned with
# branches. Limbs are little-endian UInt64; products go through UInt128.

comptime _MAX_RSA_LIMBS = 128  # 8192-bit moduli


@always_inline
def _limb(p: Pointer[UInt64, MutAnyOrigin], i: Int) -> UInt64:
    return p[unsafe_offset=i]


def _be_to_limbs(b: List[UInt8], k: Int) raises -> List[UInt64]:
    """Big-endian bytes as k little-endian limbs. Leading zero bytes beyond
    8k are ignored; a value that does not fit raises."""
    var out = List[UInt64](length=k, fill=0)
    var n = len(b)
    for i in range(n):
        var bit = 8 * (n - 1 - i)
        if (bit >> 6) >= k:
            if b[i] != 0:
                raise Error("rsa: value wider than the modulus")
            continue
        out[bit >> 6] |= UInt64(b[i]) << UInt64(bit & 63)
    return out^


def _limbs_to_be(a: List[UInt64], n_bytes: Int) -> List[UInt8]:
    var out = List[UInt8](length=n_bytes, fill=0)
    for i in range(n_bytes):
        var bit = 8 * (n_bytes - 1 - i)
        if (bit >> 6) < len(a):
            out[i] = UInt8((a[bit >> 6] >> UInt64(bit & 63)) & 0xFF)
    return out^


struct _MontCtx(Movable):
    """Montgomery context for an odd k-limb modulus m, R = 2^(64k)."""
    var k: Int
    var m: List[UInt64]
    var m0inv: UInt64        # -m^-1 mod 2^64
    var t: List[UInt64]      # scratch, k + 2 limbs

    def __init__(out self, m: List[UInt64]):
        self.k = len(m)
        self.m = m.copy()
        # Newton: inv = m0^-1 mod 2^64 (each step doubles the correct bits)
        var inv: UInt64 = 1
        for _ in range(6):
            inv *= 2 - m[0] * inv
        self.m0inv = UInt64(0) - inv
        self.t = List[UInt64](length=self.k + 2, fill=0)

    def mul(mut self, a: List[UInt64], b: List[UInt64], mut out: List[UInt64]):
        """out = a * b * R^-1 mod m (CIOS); a, b < m; out may alias neither."""
        var k = self.k
        var ap = Pointer[UInt64, MutAnyOrigin](unsafe_from_address=Int(a.unsafe_ptr()))
        var bp = Pointer[UInt64, MutAnyOrigin](unsafe_from_address=Int(b.unsafe_ptr()))
        var mp = Pointer[UInt64, MutAnyOrigin](unsafe_from_address=Int(self.m.unsafe_ptr()))
        var t = Pointer[UInt64, MutAnyOrigin](unsafe_from_address=Int(self.t.unsafe_ptr()))
        for i in range(k + 2):
            t[unsafe_offset=i] = 0
        for i in range(k):
            var bi = _limb(bp, i)
            var c: UInt64 = 0
            for j in range(k):
                var uv = UInt128(t[unsafe_offset=j]) + UInt128(_limb(ap, j)) * UInt128(bi) + UInt128(c)
                t[unsafe_offset=j] = UInt64(uv)
                c = UInt64(uv >> 64)
            var top = UInt128(t[unsafe_offset=k]) + UInt128(c)
            t[unsafe_offset=k] = UInt64(top)
            t[unsafe_offset=k + 1] = UInt64(top >> 64)
            var mq = t[unsafe_offset=0] * self.m0inv
            var uv = UInt128(t[unsafe_offset=0]) + UInt128(mq) * UInt128(_limb(mp, 0))
            c = UInt64(uv >> 64)
            for j in range(1, k):
                uv = UInt128(t[unsafe_offset=j]) + UInt128(mq) * UInt128(_limb(mp, j)) + UInt128(c)
                t[unsafe_offset=j - 1] = UInt64(uv)
                c = UInt64(uv >> 64)
            var hi = UInt128(t[unsafe_offset=k]) + UInt128(c)
            t[unsafe_offset=k - 1] = UInt64(hi)
            t[unsafe_offset=k] = t[unsafe_offset=k + 1] + UInt64(hi >> 64)
        # out = t - m if t >= m (t < 2m)
        var op = Pointer[UInt64, MutAnyOrigin](unsafe_from_address=Int(out.unsafe_ptr()))
        var borrow: UInt64 = 0
        for j in range(k):
            var d = UInt128(t[unsafe_offset=j]) - UInt128(_limb(mp, j)) - UInt128(borrow)
            op[unsafe_offset=j] = UInt64(d)
            borrow = UInt64(d >> 127)
        if t[unsafe_offset=k] == 0 and borrow == 1:  # t < m: keep t
            for j in range(k):
                op[unsafe_offset=j] = t[unsafe_offset=j]

    def double(mut self, mut a: List[UInt64]):
        """a = 2a mod m (a < m)."""
        var k = self.k
        var carry: UInt64 = 0
        for j in range(k):
            var v = a[j]
            a[j] = (v << 1) | carry
            carry = v >> 63
        # subtract m if 2a >= m (carry out, or a >= m)
        var d = List[UInt64](length=k, fill=0)
        var borrow: UInt64 = 0
        for j in range(k):
            var x = UInt128(a[j]) - UInt128(self.m[j]) - UInt128(borrow)
            d[j] = UInt64(x)
            borrow = UInt64(x >> 127)
        if carry == 1 or borrow == 0:
            a = d^


def _rsa_raw(sig: List[UInt8], n_bytes: List[UInt8], e_bytes: List[UInt8], em_len: Int) raises -> List[UInt8]:
    """sig^e mod n as em_len big-endian bytes (n odd, sig < n: checked by the
    callers' range check and here)."""
    var start = 0
    while start < len(n_bytes) and n_bytes[start] == 0:
        start += 1
    var nb = len(n_bytes) - start
    var k = (nb + 7) // 8
    if k == 0:
        raise Error("rsa: modulus is zero")
    if k > _MAX_RSA_LIMBS:
        raise Error("rsa: modulus too large (over 8192 bits)")
    if n_bytes[len(n_bytes) - 1] & 1 == 0:
        raise Error("rsa: modulus must be odd")
    var m = _be_to_limbs(n_bytes, k)
    var ctx = _MontCtx(m)

    # R mod m: m's top bit is in limb k-1; 2^(bits-1) < m, then double up to 2^(64k)
    var bits = 64 * (k - 1)
    var top = m[k - 1]
    while top != 0:
        bits += 1
        top >>= 1
    var r_mod = List[UInt64](length=k, fill=0)
    r_mod[(bits - 1) >> 6] = UInt64(1) << UInt64((bits - 1) & 63)
    for _ in range(64 * k - (bits - 1)):
        ctx.double(r_mod)
    # R^2 mod m: 64k = c * 2^s; Montgomery form of 2^c is 2^c * R (c doublings
    # of R mod m); s Montgomery squarings turn it into the form of 2^(64k) = R,
    # i.e. R * R mod m.
    var c = 64 * k
    var sq = 0
    while c % 2 == 0:
        c //= 2
        sq += 1
    var r2 = r_mod.copy()
    for _ in range(c):
        ctx.double(r2)
    var tmp = List[UInt64](length=k, fill=0)
    for _ in range(sq):
        ctx.mul(r2, r2, tmp)
        var _sw = r2^
        r2 = tmp^
        tmp = _sw^

    var base = _be_to_limbs(sig, k)
    # sig < m (RFC 8017 RSAVP1 step 1)
    var lt = False
    for j in range(k - 1, -1, -1):
        if base[j] != m[j]:
            lt = base[j] < m[j]
            break
    if not lt:
        raise Error("rsa: signature representative out of range")
    var bm = List[UInt64](length=k, fill=0)
    ctx.mul(base, r2, bm)  # Montgomery form of sig

    # left-to-right square-and-multiply over the public exponent
    var acc = r_mod.copy()   # Montgomery form of 1
    var started = False
    for i in range(len(e_bytes)):
        for bit in range(7, -1, -1):
            var set = (e_bytes[i] >> UInt8(bit)) & 1 == 1
            if started:
                ctx.mul(acc, acc, tmp)
                var _sw = acc^
                acc = tmp^
                tmp = _sw^
            if set:
                if started:
                    ctx.mul(acc, bm, tmp)
                    var _sw = acc^
                    acc = tmp^
                    tmp = _sw^
                else:
                    acc = bm.copy()
                    started = True
    if not started:
        raise Error("rsa: public exponent is zero")
    var one = List[UInt64](length=k, fill=0)
    one[0] = 1
    ctx.mul(acc, one, tmp)  # out of Montgomery form
    return _limbs_to_be(tmp, em_len)


# ============================================================================
# PKCS#1 v1.5 signature verification
# ============================================================================

def rsa_pkcs1_verify(
    n_bytes:  List[UInt8],   # RSA modulus (big-endian)
    e_bytes:  List[UInt8],   # RSA public exponent (big-endian)
    msg_hash: List[UInt8],   # SHA-256, SHA-384 or SHA-512 message hash
    sig:      List[UInt8],   # signature (same length as n)
) raises:
    """Verify an RSA PKCS#1 v1.5 signature (SHA-256/384/512). Raises on invalid."""
    var hash_len = len(msg_hash)
    _check_hash_len(hash_len, "rsa_pkcs1")
    var n = bigint_from_bytes(n_bytes)
    var k = len(n_bytes)
    if len(sig) != k:
        raise Error("rsa_pkcs1: signature length != key length")
    # 00 01 FF*8 00 DigestInfo(19) Hash: shorter moduli cannot hold an encoding
    if k < 11 + 19 + hash_len:
        raise Error("rsa_pkcs1: modulus too short")
    # RFC 8017 RSAVP1 step 1: s must be < n (else s + n is a second encoding)
    if bigint_cmp(bigint_from_bytes(sig), n) >= 0:
        raise Error("rsa_pkcs1: signature representative out of range")

    # Recover encoded message: em = sig^e mod n, padded to k bytes
    var em = _rsa_raw(sig, n_bytes, e_bytes, k)

    # Verify PKCS#1 v1.5 format: 0x00 0x01 0xFF...0xFF 0x00 DigestInfo Hash
    if em[0] != 0x00 or em[1] != 0x01:
        raise Error("rsa_pkcs1: bad EM header (expected 00 01)")

    # Find end of 0xFF padding (at least 8 bytes required)
    var i = 2
    while i < k and em[i] == 0xFF:
        i += 1
    if i < 10:  # at least 8 FF bytes (i started at 2, so >= 10 means >= 8 FFs)
        raise Error("rsa_pkcs1: padding too short (need ≥ 8 FF bytes)")
    if i >= k or em[i] != 0x00:
        raise Error("rsa_pkcs1: expected 0x00 separator after FF padding")
    i += 1  # skip separator

    var di = _digest_info(hash_len)
    if i + 19 + hash_len != k:
        raise Error("rsa_pkcs1: EM length mismatch")
    for j in range(19):
        if em[i + j] != di[j]:
            raise Error("rsa_pkcs1: DigestInfo prefix mismatch")
    i += 19

    # Verify hash (constant-time comparison to avoid timing side channel)
    var diff: UInt8 = 0
    for j in range(hash_len):
        diff |= em[i + j] ^ msg_hash[j]
    if diff != 0:
        raise Error("rsa_pkcs1: hash mismatch")


# ============================================================================
# RSA-PSS signature verification (MGF1 with the message hash)
# ============================================================================

def rsa_pss_verify(
    n_bytes:  List[UInt8],   # RSA modulus (big-endian)
    e_bytes:  List[UInt8],   # RSA public exponent (big-endian)
    msg_hash: List[UInt8],   # SHA-256, SHA-384 or SHA-512 message hash
    sig:      List[UInt8],   # signature
    salt_len: Int,           # expected salt length (the hash length in TLS)
) raises:
    """Verify an RSA-PSS signature (SHA-256/384/512, MGF1 with the same hash)."""
    var h_len = len(msg_hash)
    _check_hash_len(h_len, "rsa_pss")
    var n    = bigint_from_bytes(n_bytes)
    var mod_bits = bigint_bit_len(n)
    var em_bits  = mod_bits - 1
    var em_len   = (em_bits + 7) // 8
    var k        = (mod_bits + 7) // 8
    if len(sig) != k:
        raise Error("rsa_pss: signature length != key length")
    if em_len < h_len + salt_len + 2:
        raise Error("rsa_pss: key too small for given hash/salt")
    # RFC 8017 RSAVP1 step 1: s must be < n
    if bigint_cmp(bigint_from_bytes(sig), n) >= 0:
        raise Error("rsa_pss: signature representative out of range")

    # Recover m = s^e mod n as k bytes. EM is its low em_len bytes; when
    # em_len < k (modBits = 1 mod 8) the dropped high byte must be zero.
    var m_full = _rsa_raw(sig, n_bytes, e_bytes, k)
    for i in range(k - em_len):
        if m_full[i] != 0:
            raise Error("rsa_pss: encoded message longer than emLen")
    var em = List[UInt8](capacity=em_len)
    for i in range(k - em_len, k):
        em.append(m_full[i])

    # Last byte must be 0xBC
    if em[em_len - 1] != 0xBC:
        raise Error("rsa_pss: last byte not 0xBC")

    # Split em into maskedDB || H || 0xBC
    # H occupies bytes [em_len-hLen-1 .. em_len-2]
    var h_start = em_len - h_len - 1
    var h_bytes = List[UInt8](capacity=h_len)
    for i in range(h_len):
        h_bytes.append(em[h_start + i])

    # Unmask DB: DB = maskedDB XOR MGF1(H, h_start)
    var masked_db = List[UInt8](capacity=h_start)
    for i in range(h_start):
        masked_db.append(em[i])
    var db_mask = _mgf1(h_bytes, h_start, h_len)
    var db = List[UInt8](capacity=h_start)
    for i in range(h_start):
        db.append(masked_db[i] ^ db_mask[i])

    # RFC 8017 §9.1.2 step 6: the leftmost 8*em_len - em_bits bits of
    # maskedDB must be zero (checked, not just cleared), then clear them in DB
    var top_bits = 8 * em_len - em_bits
    if top_bits > 0:
        if em[0] & ~UInt8(0xFF >> top_bits) != 0:
            raise Error("rsa_pss: nonzero leftmost bits in maskedDB")
        db[0] = db[0] & UInt8(0xFF >> top_bits)

    # Check DB format: 0x00...0x00 0x01 salt
    var pad_len = h_start - salt_len - 1
    if pad_len < 0:
        raise Error("rsa_pss: salt_len too large for key size")
    for i in range(pad_len):
        if db[i] != 0x00:
            raise Error("rsa_pss: DB zero-padding mismatch")
    if db[pad_len] != 0x01:
        raise Error("rsa_pss: DB 0x01 separator missing")

    # Extract salt
    var salt = List[UInt8](capacity=salt_len)
    for i in range(salt_len):
        salt.append(db[pad_len + 1 + i])

    # Compute H' = Hash(0x00^8 || mHash || salt)
    var m_prime = List[UInt8](capacity=8 + h_len + salt_len)
    for _ in range(8):
        m_prime.append(0x00)
    for i in range(h_len):
        m_prime.append(msg_hash[i])
    for i in range(salt_len):
        m_prime.append(salt[i])
    var h_prime = _hash(m_prime, h_len)

    # Verify H' == H (constant-time comparison to avoid timing side channel)
    var pss_diff: UInt8 = 0
    for i in range(h_len):
        pss_diff |= h_prime[i] ^ h_bytes[i]
    if pss_diff != 0:
        raise Error("rsa_pss: hash mismatch")
