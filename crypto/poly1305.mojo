# ============================================================================
# crypto/poly1305.mojo — Poly1305 MAC + ChaCha20-Poly1305 AEAD (RFC 8439)
# ============================================================================
#
# Poly1305 computes a 128-bit (16-byte) MAC:
#   MAC = ((accumulate message blocks with r) + s) mod 2^128
#   where r, s are derived from the 32-byte one-time key
#
# Uses 5 × 26-bit limbs for arithmetic in GF(2^130 - 5).
#
# Security:
#   - Tag comparison is constant-time (via OR-accumulation)
#   - Poly1305 key is derived from ChaCha20 block at counter=0
#   - Plaintext returned only after tag verification
# ============================================================================

from crypto.chacha20 import chacha20_block, chacha20_encrypt
from crypto.hmac import hmac_equal


# ============================================================================
# 26-bit limb helpers
# ============================================================================

fn _load_le32_p(data: List[UInt8], off: Int) -> UInt32:
    return (
        UInt32(data[off]) |
        (UInt32(data[off + 1]) << 8) |
        (UInt32(data[off + 2]) << 16) |
        (UInt32(data[off + 3]) << 24)
    )


# ============================================================================
# Poly1305 MAC
# ============================================================================

fn poly1305_mac(key: List[UInt8], msg: List[UInt8]) raises -> List[UInt8]:
    """Compute Poly1305 MAC.

    Args:
        key: 32-byte one-time key (r = key[0:16], s = key[16:32])
        msg: Message to authenticate (any length)
    Returns:
        16-byte authentication tag
    """
    if len(key) != 32:
        raise Error("Poly1305 key must be 32 bytes")

    # Load and clamp r (bytes 0..15 of key, little-endian)
    var r0 = _load_le32_p(key, 0)  & UInt32(0x0FFFFFFF)
    var r1 = _load_le32_p(key, 4)  & UInt32(0x0FFFFFFC)
    var r2 = _load_le32_p(key, 8)  & UInt32(0x0FFFFFFC)
    var r3 = _load_le32_p(key, 12) & UInt32(0x0FFFFFFC)

    # Split r into 5 × 26-bit limbs from the 128-bit clamped value
    # 128-bit r value (LE): r0 | r1<<32 | r2<<64 | r3<<96
    var rr0 = UInt64(r0) & 0x3FFFFFF
    var rr1 = ((UInt64(r0) >> 26) | (UInt64(r1) << 6)) & 0x3FFFFFF
    var rr2 = ((UInt64(r1) >> 20) | (UInt64(r2) << 12)) & 0x3FFFFFF
    var rr3 = ((UInt64(r2) >> 14) | (UInt64(r3) << 18)) & 0x3FFFFFF
    var rr4 = UInt64(r3) >> 8

    # Pre-compute 5 * r[1..4] (for modular reduction: x * 2^130 ≡ 5x mod 2^130-5)
    var s1 = rr1 * 5
    var s2 = rr2 * 5
    var s3 = rr3 * 5
    var s4 = rr4 * 5

    # Accumulator h (5 × 26-bit limbs)
    var h0: UInt64 = 0
    var h1: UInt64 = 0
    var h2: UInt64 = 0
    var h3: UInt64 = 0
    var h4: UInt64 = 0

    # Process each 16-byte block
    var n_full = len(msg) // 16
    var n_tail = len(msg) % 16
    var idx = 0

    for _ in range(n_full):
        # Load 16 bytes as 4 × LE uint32
        var m0 = _load_le32_p(msg, idx)
        var m1 = _load_le32_p(msg, idx + 4)
        var m2 = _load_le32_p(msg, idx + 8)
        var m3 = _load_le32_p(msg, idx + 12)
        idx += 16

        # Split into 5 × 26-bit limbs and add 2^128 (hibit)
        var t0 = UInt64(m0) & 0x3FFFFFF
        var t1 = ((UInt64(m0) >> 26) | (UInt64(m1) << 6)) & 0x3FFFFFF
        var t2 = ((UInt64(m1) >> 20) | (UInt64(m2) << 12)) & 0x3FFFFFF
        var t3 = ((UInt64(m2) >> 14) | (UInt64(m3) << 18)) & 0x3FFFFFF
        var t4 = (UInt64(m3) >> 8) | UInt64(1 << 24)  # hibit = 2^128 in limb 4

        h0 += t0; h1 += t1; h2 += t2; h3 += t3; h4 += t4

        # Multiply h × r in GF(2^130 - 5)
        var d0 = h0*rr0 + h1*s4 + h2*s3 + h3*s2 + h4*s1
        var d1 = h0*rr1 + h1*rr0 + h2*s4 + h3*s3 + h4*s2
        var d2 = h0*rr2 + h1*rr1 + h2*rr0 + h3*s4 + h4*s3
        var d3 = h0*rr3 + h1*rr2 + h2*rr1 + h3*rr0 + h4*s4
        var d4 = h0*rr4 + h1*rr3 + h2*rr2 + h3*rr1 + h4*rr0

        # Carry propagation (reduce mod 2^130 - 5)
        var c: UInt64
        c = d0 >> 26; h0 = d0 & 0x3FFFFFF; d1 += c
        c = d1 >> 26; h1 = d1 & 0x3FFFFFF; d2 += c
        c = d2 >> 26; h2 = d2 & 0x3FFFFFF; d3 += c
        c = d3 >> 26; h3 = d3 & 0x3FFFFFF; d4 += c
        c = d4 >> 26; h4 = d4 & 0x3FFFFFF; h0 += c * 5
        c = h0 >> 26; h0 = h0 & 0x3FFFFFF; h1 += c

    # Process partial last block (if any)
    if n_tail > 0:
        var tmp = List[UInt8](capacity=16)
        for i in range(n_tail):
            tmp.append(msg[idx + i])
        tmp.append(0x01)  # hibit (at position n_tail, not at 16)
        while len(tmp) < 16:
            tmp.append(0x00)

        var m0 = _load_le32_p(tmp, 0)
        var m1 = _load_le32_p(tmp, 4)
        var m2 = _load_le32_p(tmp, 8)
        var m3 = _load_le32_p(tmp, 12)

        var t0 = UInt64(m0) & 0x3FFFFFF
        var t1 = ((UInt64(m0) >> 26) | (UInt64(m1) << 6)) & 0x3FFFFFF
        var t2 = ((UInt64(m1) >> 20) | (UInt64(m2) << 12)) & 0x3FFFFFF
        var t3 = ((UInt64(m2) >> 14) | (UInt64(m3) << 18)) & 0x3FFFFFF
        var t4 = UInt64(m3) >> 8  # no hibit added here (already in byte stream)

        h0 += t0; h1 += t1; h2 += t2; h3 += t3; h4 += t4

        var d0 = h0*rr0 + h1*s4 + h2*s3 + h3*s2 + h4*s1
        var d1 = h0*rr1 + h1*rr0 + h2*s4 + h3*s3 + h4*s2
        var d2 = h0*rr2 + h1*rr1 + h2*rr0 + h3*s4 + h4*s3
        var d3 = h0*rr3 + h1*rr2 + h2*rr1 + h3*rr0 + h4*s4
        var d4 = h0*rr4 + h1*rr3 + h2*rr2 + h3*rr1 + h4*rr0

        var c: UInt64
        c = d0 >> 26; h0 = d0 & 0x3FFFFFF; d1 += c
        c = d1 >> 26; h1 = d1 & 0x3FFFFFF; d2 += c
        c = d2 >> 26; h2 = d2 & 0x3FFFFFF; d3 += c
        c = d3 >> 26; h3 = d3 & 0x3FFFFFF; d4 += c
        c = d4 >> 26; h4 = d4 & 0x3FFFFFF; h0 += c * 5
        c = h0 >> 26; h0 = h0 & 0x3FFFFFF; h1 += c

    # Full carry propagation
    var c: UInt64
    c = h1 >> 26; h1 &= 0x3FFFFFF; h2 += c
    c = h2 >> 26; h2 &= 0x3FFFFFF; h3 += c
    c = h3 >> 26; h3 &= 0x3FFFFFF; h4 += c
    c = h4 >> 26; h4 &= 0x3FFFFFF; h0 += c * 5
    c = h0 >> 26; h0 &= 0x3FFFFFF; h1 += c

    # Compute h - p where p = 2^130 - 5
    # If h >= p, use h - p; otherwise use h
    var g0 = h0 + 5
    c = g0 >> 26; g0 &= 0x3FFFFFF
    var g1 = h1 + c
    c = g1 >> 26; g1 &= 0x3FFFFFF
    var g2 = h2 + c
    c = g2 >> 26; g2 &= 0x3FFFFFF
    var g3 = h3 + c
    c = g3 >> 26; g3 &= 0x3FFFFFF
    var g4 = h4 + c - (UInt64(1) << 26)

    # Select h or g based on top bit of g4
    var mask = (g4 >> 63) - 1  # all 1s if g4 < 2^63 (i.e., no underflow → h >= p)
    g0 &= mask; g1 &= mask; g2 &= mask; g3 &= mask; g4 &= mask
    mask = ~mask
    h0 = (h0 & mask) | g0
    h1 = (h1 & mask) | g1
    h2 = (h2 & mask) | g2
    h3 = (h3 & mask) | g3
    h4 = (h4 & mask) | g4

    # Reconstruct 128-bit h from 5 limbs.
    # Each fi must only include the bits of the NEXT limb that fall within the
    # 32-bit word boundary — using full-width 64-bit shifts would double-count
    # the upper bits via the carry propagation below.
    var f0 = h0 | ((h1 & 0x3F) << 26)            # h0[0..25] + h1[0..5]
    var f1 = (h1 >> 6) | ((h2 & 0xFFF) << 20)    # h1[6..25] + h2[0..11]
    var f2 = (h2 >> 12) | ((h3 & 0x3FFFF) << 14) # h2[12..25] + h3[0..17]
    var f3 = (h3 >> 18) | (h4 << 8)              # h3[18..25] + h4 (upper bits truncated below)

    # Add s (key[16:32], little-endian)
    var s0 = UInt64(_load_le32_p(key, 16))
    var s_1 = UInt64(_load_le32_p(key, 20))
    var s_2 = UInt64(_load_le32_p(key, 24))
    var s_3 = UInt64(_load_le32_p(key, 28))

    f0 += s0;    c = f0 >> 32; f0 &= 0xFFFFFFFF
    f1 += s_1 + c; c = f1 >> 32; f1 &= 0xFFFFFFFF
    f2 += s_2 + c; c = f2 >> 32; f2 &= 0xFFFFFFFF
    f3 += s_3 + c; f3 &= 0xFFFFFFFF

    # Serialize as 16-byte LE
    var tag = List[UInt8](capacity=16)
    tag.append(UInt8(f0 & 0xFF));        tag.append(UInt8((f0 >> 8) & 0xFF))
    tag.append(UInt8((f0 >> 16) & 0xFF)); tag.append(UInt8((f0 >> 24) & 0xFF))
    tag.append(UInt8(f1 & 0xFF));        tag.append(UInt8((f1 >> 8) & 0xFF))
    tag.append(UInt8((f1 >> 16) & 0xFF)); tag.append(UInt8((f1 >> 24) & 0xFF))
    tag.append(UInt8(f2 & 0xFF));        tag.append(UInt8((f2 >> 8) & 0xFF))
    tag.append(UInt8((f2 >> 16) & 0xFF)); tag.append(UInt8((f2 >> 24) & 0xFF))
    tag.append(UInt8(f3 & 0xFF));        tag.append(UInt8((f3 >> 8) & 0xFF))
    tag.append(UInt8((f3 >> 16) & 0xFF)); tag.append(UInt8((f3 >> 24) & 0xFF))
    return tag^


# ============================================================================
# ChaCha20-Poly1305 AEAD helpers
# ============================================================================

fn _pad16_poly(data: List[UInt8]) -> List[UInt8]:
    """Zero-pad data to 16-byte boundary."""
    var n = len(data)
    var padded = ((n + 15) // 16) * 16
    var out = List[UInt8](capacity=padded)
    for b in data:
        out.append(b)
    while len(out) < padded:
        out.append(0x00)
    return out^


fn _le64(n: Int) -> List[UInt8]:
    """Encode n as 8-byte little-endian."""
    var out = List[UInt8](capacity=8)
    var v = UInt64(n)
    for _ in range(8):
        out.append(UInt8(v & 0xFF))
        v >>= 8
    return out^


fn _build_poly1305_input(aad: List[UInt8], ct: List[UInt8]) -> List[UInt8]:
    """Build the Poly1305 MAC input for ChaCha20-Poly1305:
       pad(AAD) || pad(CT) || len(AAD) LE64 || len(CT) LE64
    """
    var aad_pad = _pad16_poly(aad)
    var ct_pad  = _pad16_poly(ct)
    var out = List[UInt8](capacity=len(aad_pad) + len(ct_pad) + 16)
    for b in aad_pad:
        out.append(b)
    for b in ct_pad:
        out.append(b)
    var la = _le64(len(aad))
    var lc = _le64(len(ct))
    for b in la:
        out.append(b)
    for b in lc:
        out.append(b)
    return out^


# ============================================================================
# Public AEAD API
# ============================================================================

fn chacha20_poly1305_encrypt(
    key: List[UInt8],
    nonce: List[UInt8],
    aad: List[UInt8],
    plaintext: List[UInt8],
) raises -> Tuple[List[UInt8], List[UInt8]]:
    """ChaCha20-Poly1305 encrypt.

    Args:
        key:       32-byte key
        nonce:     12-byte nonce
        aad:       Additional authenticated data
        plaintext: Data to encrypt
    Returns:
        Tuple of (ciphertext, tag)
    """
    if len(key) != 32:
        raise Error("ChaCha20-Poly1305 key must be 32 bytes")
    if len(nonce) != 12:
        raise Error("ChaCha20-Poly1305 nonce must be 12 bytes")

    # Derive Poly1305 one-time key (counter=0)
    var otk = chacha20_block(key, 0, nonce)
    var poly_key = List[UInt8](capacity=32)
    for i in range(32):
        poly_key.append(otk[i])

    # Encrypt plaintext (counter=1)
    var ciphertext = chacha20_encrypt(key, nonce, 1, plaintext)

    # Compute MAC over constructed input
    var mac_input = _build_poly1305_input(aad, ciphertext)
    var tag = poly1305_mac(poly_key, mac_input)

    return ciphertext^, tag^


fn chacha20_poly1305_decrypt(
    key: List[UInt8],
    nonce: List[UInt8],
    aad: List[UInt8],
    ciphertext: List[UInt8],
    tag: List[UInt8],
) raises -> List[UInt8]:
    """ChaCha20-Poly1305 decrypt and verify.

    Verifies tag before returning plaintext (constant-time comparison).
    Raises Error("authentication failed") if tag does not match.
    """
    if len(key) != 32:
        raise Error("ChaCha20-Poly1305 key must be 32 bytes")
    if len(nonce) != 12:
        raise Error("ChaCha20-Poly1305 nonce must be 12 bytes")
    if len(tag) != 16:
        raise Error("ChaCha20-Poly1305 tag must be 16 bytes")

    # Derive Poly1305 one-time key
    var otk = chacha20_block(key, 0, nonce)
    var poly_key = List[UInt8](capacity=32)
    for i in range(32):
        poly_key.append(otk[i])

    # Recompute expected tag
    var mac_input = _build_poly1305_input(aad, ciphertext)
    var expected_tag = poly1305_mac(poly_key, mac_input)

    # Constant-time comparison
    if not hmac_equal(tag, expected_tag):
        raise Error("authentication failed")

    # Decrypt only after tag is verified
    return chacha20_encrypt(key, nonce, 1, ciphertext)
