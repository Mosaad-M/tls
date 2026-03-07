# ============================================================================
# rsa.mojo — RSA signature verification (PKCS#1 v1.5 and PSS)
# ============================================================================
# API:
#   rsa_pkcs1_verify(n_bytes, e_bytes, msg_hash, sig)           → raises on bad
#   rsa_pss_verify(n_bytes, e_bytes, msg_hash, sig, salt_len)   → raises on bad
#
# Both functions accept big-endian byte arrays for n, e, sig.
# msg_hash must be a 32-byte SHA-256 digest.
# ============================================================================

from crypto.bigint import (
    BigInt, bigint_from_bytes, bigint_to_bytes, bigint_modexp, bigint_bit_len,
)
from crypto.hash import sha256, sha384


# ============================================================================
# SHA-256 DigestInfo ASN.1 prefix (for PKCS#1 v1.5)
# 30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20
# ============================================================================

fn _sha256_di() -> List[UInt8]:
    var b = List[UInt8](capacity=19)
    b.append(0x30); b.append(0x31)
    b.append(0x30); b.append(0x0D)
    b.append(0x06); b.append(0x09)
    b.append(0x60); b.append(0x86); b.append(0x48); b.append(0x01)
    b.append(0x65); b.append(0x03); b.append(0x04); b.append(0x02)
    b.append(0x01); b.append(0x05); b.append(0x00)
    b.append(0x04); b.append(0x20)
    return b^


fn _sha384_di() -> List[UInt8]:
    """SHA-384 DigestInfo prefix for PKCS#1 v1.5: 30 41 30 0d 06 09 ... 02 02 05 00 04 30."""
    var b = List[UInt8](capacity=19)
    b.append(0x30); b.append(0x41)
    b.append(0x30); b.append(0x0D)
    b.append(0x06); b.append(0x09)
    b.append(0x60); b.append(0x86); b.append(0x48); b.append(0x01)
    b.append(0x65); b.append(0x03); b.append(0x04); b.append(0x02)
    b.append(0x02); b.append(0x05); b.append(0x00)
    b.append(0x04); b.append(0x30)
    return b^


# ============================================================================
# MGF1 with SHA-256
# ============================================================================

fn _mgf1_sha256(seed: List[UInt8], length: Int) -> List[UInt8]:
    """MGF1(seed, length) using SHA-256."""
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
        var h = sha256(input)
        for i in range(len(h)):
            if len(out) < length:
                out.append(h[i])
        counter += 1
    return out^


fn _mgf1_sha384(seed: List[UInt8], length: Int) -> List[UInt8]:
    """MGF1(seed, length) using SHA-384."""
    var out = List[UInt8](capacity=length)
    var counter: UInt32 = 0
    while len(out) < length:
        var input = List[UInt8](capacity=len(seed) + 4)
        for i in range(len(seed)):
            input.append(seed[i])
        input.append(UInt8((counter >> 24) & 0xFF))
        input.append(UInt8((counter >> 16) & 0xFF))
        input.append(UInt8((counter >> 8) & 0xFF))
        input.append(UInt8(counter & 0xFF))
        var h = sha384(input)
        for i in range(len(h)):
            if len(out) < length:
                out.append(h[i])
        counter += 1
    return out^


# ============================================================================
# Internal: sig^e mod n → zero-padded EM bytes
# ============================================================================

fn _rsa_raw(sig: List[UInt8], n: BigInt, e: BigInt, em_len: Int) -> List[UInt8]:
    """Compute sig^e mod n and return as em_len big-endian bytes."""
    var sig_int = bigint_from_bytes(sig)
    var em_int  = bigint_modexp(sig_int, e, n)
    return bigint_to_bytes(em_int, em_len)


# ============================================================================
# PKCS#1 v1.5 signature verification (SHA-256)
# ============================================================================

fn rsa_pkcs1_verify(
    n_bytes:  List[UInt8],   # RSA modulus (big-endian)
    e_bytes:  List[UInt8],   # RSA public exponent (big-endian)
    msg_hash: List[UInt8],   # 32-byte SHA-256 or 48-byte SHA-384 message hash
    sig:      List[UInt8],   # signature (same length as n)
) raises:
    """Verify RSA-PKCS#1 v1.5 SHA-256 or SHA-384 signature. Raises on invalid."""
    var hash_len = len(msg_hash)
    if hash_len != 32 and hash_len != 48:
        raise Error("rsa_pkcs1: hash must be 32 (SHA-256) or 48 (SHA-384) bytes")
    var n = bigint_from_bytes(n_bytes)
    var e = bigint_from_bytes(e_bytes)
    var k = len(n_bytes)
    if len(sig) != k:
        raise Error("rsa_pkcs1: signature length != key length")

    # Recover encoded message: em = sig^e mod n, padded to k bytes
    var em = _rsa_raw(sig, n, e, k)

    # Verify PKCS#1 v1.5 format: 0x00 0x01 0xFF...0xFF 0x00 DigestInfo Hash
    if em[0] != 0x00 or em[1] != 0x01:
        raise Error("rsa_pkcs1: bad EM header (expected 00 01)")

    # Find end of 0xFF padding (at least 8 bytes required)
    var i = 2
    while i < k and em[i] == 0xFF:
        i += 1
    if i < 10:  # at least 8 FF bytes (i started at 2, so >= 10 means >= 8 FFs)
        raise Error("rsa_pkcs1: padding too short (need ≥ 8 FF bytes)")
    if em[i] != 0x00:
        raise Error("rsa_pkcs1: expected 0x00 separator after FF padding")
    i += 1  # skip separator

    # Choose DigestInfo prefix based on hash length
    var di: List[UInt8]
    if hash_len == 32:
        di = _sha256_di()
    else:
        di = _sha384_di()
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
# RSA-PSS signature verification (SHA-256, MGF1-SHA-256)
# ============================================================================

fn rsa_pss_verify(
    n_bytes:  List[UInt8],   # RSA modulus (big-endian)
    e_bytes:  List[UInt8],   # RSA public exponent (big-endian)
    msg_hash: List[UInt8],   # 32-byte SHA-256 or 48-byte SHA-384 message hash
    sig:      List[UInt8],   # signature
    salt_len: Int,           # expected salt length (32 for SHA-256, 48 for SHA-384)
) raises:
    """Verify RSA-PSS (MGF1) signature. Supports SHA-256 (32-byte) and SHA-384 (48-byte) hashes."""
    var h_len = len(msg_hash)
    if h_len != 32 and h_len != 48:
        raise Error("rsa_pss: hash must be 32 (SHA-256) or 48 (SHA-384) bytes")
    var n    = bigint_from_bytes(n_bytes)
    var e    = bigint_from_bytes(e_bytes)
    var mod_bits = bigint_bit_len(n)
    var em_bits  = mod_bits - 1
    var em_len   = (em_bits + 7) // 8
    var k        = (mod_bits + 7) // 8
    if len(sig) != k:
        raise Error("rsa_pss: signature length != key length")
    if em_len < h_len + salt_len + 2:
        raise Error("rsa_pss: key too small for given hash/salt")

    # Recover EM: sig^e mod n, padded to em_len bytes
    var em = _rsa_raw(sig, n, e, em_len)

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
    var db_mask: List[UInt8]
    if h_len == 48:
        db_mask = _mgf1_sha384(h_bytes, h_start)
    else:
        db_mask = _mgf1_sha256(h_bytes, h_start)
    var db = List[UInt8](capacity=h_start)
    for i in range(h_start):
        db.append(masked_db[i] ^ db_mask[i])

    # Zero out the (8*em_len - em_bits) most significant bits of db[0]
    var top_bits = 8 * em_len - em_bits
    if top_bits > 0:
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
    var h_prime: List[UInt8]
    if h_len == 48:
        h_prime = sha384(m_prime)
    else:
        h_prime = sha256(m_prime)

    # Verify H' == H (constant-time comparison to avoid timing side channel)
    var pss_diff: UInt8 = 0
    for i in range(h_len):
        pss_diff |= h_prime[i] ^ h_bytes[i]
    if pss_diff != 0:
        raise Error("rsa_pss: hash mismatch")
