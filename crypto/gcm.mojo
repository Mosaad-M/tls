# ============================================================================
# crypto/gcm.mojo — AES-GCM AEAD (NIST SP 800-38D)
# ============================================================================
#
# AES-GCM combines:
#   - AES-CTR for confidentiality
#   - GHASH for authentication (polynomial MAC over GF(2^128))
#
# Tag = GHASH(H, AAD, CT) XOR E(key, J0)
#   where H  = E(key, 0^128)          — hash subkey
#         J0 = IV || 0x00000001       — counter block (for 96-bit IV)
#         CTR encryption starts at inc32(J0) = IV || 0x00000002
#
# Security:
#   - Constant time: bitsliced AES (crypto/aes.mojo) and table-free GHASH
#   - Tag verification is constant-time (OR-accumulation, no early exit)
#   - Plaintext is NOT returned until tag verification passes
#   - 12-byte (96-bit) IV only — the standard safe form
# ============================================================================

from crypto.aes import AES
from crypto.hmac import hmac_equal


# ============================================================================
# GHASH — constant-time GF(2^128) multiply (port of BearSSL ghash_ctmul64)
# ============================================================================
# The carry-less 64x64 product is computed with ordinary integer
# multiplications on operands masked to every 4th bit: carries then land in
# bit positions that are masked away. No tables, no secret-dependent branches.
# (Integer multiply is constant time on the 64-bit CPUs this targets.)

@always_inline
def _bmul64(x: UInt64, y: UInt64) -> UInt64:
    """Low 64 bits of the carry-less product x * y."""
    comptime M0 = UInt64(0x1111111111111111)
    comptime M1 = UInt64(0x2222222222222222)
    comptime M2 = UInt64(0x4444444444444444)
    comptime M3 = UInt64(0x8888888888888888)
    var x0 = x & M0
    var x1 = x & M1
    var x2 = x & M2
    var x3 = x & M3
    var y0 = y & M0
    var y1 = y & M1
    var y2 = y & M2
    var y3 = y & M3
    var z0 = (x0 * y0) ^ (x1 * y3) ^ (x2 * y2) ^ (x3 * y1)
    var z1 = (x0 * y1) ^ (x1 * y0) ^ (x2 * y3) ^ (x3 * y2)
    var z2 = (x0 * y2) ^ (x1 * y1) ^ (x2 * y0) ^ (x3 * y3)
    var z3 = (x0 * y3) ^ (x1 * y2) ^ (x2 * y1) ^ (x3 * y0)
    return (z0 & M0) | (z1 & M1) | (z2 & M2) | (z3 & M3)


@always_inline
def _rev64(v: UInt64) -> UInt64:
    """Reverse the bit order of a 64-bit word."""
    var x = v
    x = ((x & UInt64(0x5555555555555555)) << 1) | ((x >> 1) & UInt64(0x5555555555555555))
    x = ((x & UInt64(0x3333333333333333)) << 2) | ((x >> 2) & UInt64(0x3333333333333333))
    x = ((x & UInt64(0x0F0F0F0F0F0F0F0F)) << 4) | ((x >> 4) & UInt64(0x0F0F0F0F0F0F0F0F))
    x = ((x & UInt64(0x00FF00FF00FF00FF)) << 8) | ((x >> 8) & UInt64(0x00FF00FF00FF00FF))
    x = ((x & UInt64(0x0000FFFF0000FFFF)) << 16) | ((x >> 16) & UInt64(0x0000FFFF0000FFFF))
    return (x << 32) | (x >> 32)


struct _GHashKey(Copyable, Movable):
    """H split into the halves (and bit-reversed halves) ghash_ctmul64 uses."""
    var h0: UInt64   # low 64 bits of H (big-endian bytes 8..15)
    var h1: UInt64   # high 64 bits of H (bytes 0..7)
    var h2: UInt64
    var h0r: UInt64
    var h1r: UInt64
    var h2r: UInt64

    def __init__(out self, h1: UInt64, h0: UInt64):
        self.h0 = h0
        self.h1 = h1
        self.h2 = h0 ^ h1
        self.h0r = _rev64(h0)
        self.h1r = _rev64(h1)
        self.h2r = self.h0r ^ self.h1r


@always_inline
def _ghash_block(k: _GHashKey, y1_in: UInt64, y0_in: UInt64) -> Tuple[UInt64, UInt64]:
    """(y1:y0) * H in GF(2^128), GHASH bit order. Returns (y1, y0)."""
    var y0 = y0_in
    var y1 = y1_in
    var y0r = _rev64(y0)
    var y1r = _rev64(y1)
    var y2 = y0 ^ y1
    var y2r = y0r ^ y1r

    var z0 = _bmul64(y0, k.h0)
    var z1 = _bmul64(y1, k.h1)
    var z2 = _bmul64(y2, k.h2)
    var z0h = _bmul64(y0r, k.h0r)
    var z1h = _bmul64(y1r, k.h1r)
    var z2h = _bmul64(y2r, k.h2r)
    z2 ^= z0 ^ z1
    z2h ^= z0h ^ z1h
    z0h = _rev64(z0h) >> 1
    z1h = _rev64(z1h) >> 1
    z2h = _rev64(z2h) >> 1

    var v0 = z0
    var v1 = z0h ^ z2
    var v2 = z1 ^ z2h
    var v3 = z1h

    v3 = (v3 << 1) | (v2 >> 63)
    v2 = (v2 << 1) | (v1 >> 63)
    v1 = (v1 << 1) | (v0 >> 63)
    v0 = v0 << 1

    v2 ^= v0 ^ (v0 >> 1) ^ (v0 >> 2) ^ (v0 >> 7)
    v1 ^= (v0 << 63) ^ (v0 << 62) ^ (v0 << 57)
    v3 ^= v1 ^ (v1 >> 1) ^ (v1 >> 2) ^ (v1 >> 7)
    v2 ^= (v1 << 63) ^ (v1 << 62) ^ (v1 << 57)
    return (v3, v2)


@always_inline
def _load64be(b: List[UInt8], off: Int) -> UInt64:
    var v: UInt64 = 0
    for i in range(8):
        v = (v << 8) | UInt64(b[off + i])
    return v


# ============================================================================
# CTR-mode helpers
# ============================================================================

def _inc32(ctr: List[UInt8]) -> List[UInt8]:
    """Increment the 32-bit big-endian counter in the last 4 bytes of ctr."""
    var out = ctr.copy()
    var i = 15
    while i >= 12:
        out[i] = out[i] + 1
        if out[i] != 0:
            break
        i -= 1
    return out^


def _aes_ctr(aes: AES, j0: List[UInt8], data: List[UInt8]) raises -> List[UInt8]:
    """XOR data with AES-CTR keystream starting at counter = inc32(j0).

    Counters are encrypted four at a time (the bitsliced AES's natural width).
    """
    var out = List[UInt8](capacity=len(data))
    var ctr = _inc32(j0)
    var pos = 0
    var counters = List[UInt8](capacity=64)
    while pos < len(data):
        counters.clear()
        for _ in range(4):
            for i in range(16):
                counters.append(ctr[i])
            ctr = _inc32(ctr)
        var ks = aes.encrypt_blocks4(counters)
        var n = min(64, len(data) - pos)
        for i in range(n):
            out.append(data[pos + i] ^ ks[i])
        pos += n
    return out^


# ============================================================================
# GHASH input construction
# ============================================================================

def _pad16(data: List[UInt8]) -> List[UInt8]:
    """Zero-pad data to a multiple of 16 bytes."""
    var n = len(data)
    var padded_n = ((n + 15) // 16) * 16
    var out = List[UInt8](capacity=padded_n)
    for i in range(n):
        out.append(data[i])
    for _ in range(padded_n - n):
        out.append(0x00)
    return out^


def _build_ghash_input(aad: List[UInt8], ct: List[UInt8]) -> List[UInt8]:
    """Build GHASH input: pad(AAD) || pad(CT) || len(AAD)_bits64 || len(CT)_bits64."""
    var aad_padded = _pad16(aad)
    var ct_padded  = _pad16(ct)
    var total = len(aad_padded) + len(ct_padded) + 16
    var out = List[UInt8](capacity=total)
    for b in aad_padded:
        out.append(b)
    for b in ct_padded:
        out.append(b)
    # len(AAD) in bits, 64-bit big-endian
    var aad_bits = UInt64(len(aad)) * 8
    for i in range(7, -1, -1):
        out.append(UInt8((aad_bits >> UInt64(i * 8)) & 0xFF))
    # len(CT) in bits, 64-bit big-endian
    var ct_bits = UInt64(len(ct)) * 8
    for i in range(7, -1, -1):
        out.append(UInt8((ct_bits >> UInt64(i * 8)) & 0xFF))
    return out^


# ============================================================================
# Shared key-setup helper (used by both encrypt and decrypt)
# ============================================================================

def _gcm_setup(aes: AES, iv: List[UInt8]) raises -> Tuple[_GHashKey, List[UInt8]]:
    """Return (GHASH key, J0) for a given AES instance and 12-byte IV."""
    # H = AES_K(0^128)
    var zero_block = List[UInt8](capacity=16)
    for _ in range(16):
        zero_block.append(0x00)
    var h_block = aes.encrypt_block(zero_block)
    var key = _GHashKey(_load64be(h_block, 0), _load64be(h_block, 8))

    # J0 = IV || 0x00000001
    var j0 = List[UInt8](capacity=16)
    for b in iv:
        j0.append(b)
    j0.append(0x00); j0.append(0x00); j0.append(0x00); j0.append(0x01)
    return key^, j0^


def _compute_tag(
    aes: AES,
    key: _GHashKey,
    j0: List[UInt8],
    aad: List[UInt8],
    ct: List[UInt8],
) raises -> List[UInt8]:
    """Compute the GCM authentication tag (constant-time GHASH)."""
    var ghash_input = _build_ghash_input(aad, ct)
    var y1: UInt64 = 0
    var y0: UInt64 = 0
    for b in range(len(ghash_input) // 16):
        var off = b * 16
        y1 ^= _load64be(ghash_input, off)
        y0 ^= _load64be(ghash_input, off + 8)
        var r = _ghash_block(key, y1, y0)
        y1 = r[0]
        y0 = r[1]

    var s_block = aes.encrypt_block(j0)
    var tag = List[UInt8](capacity=16)
    for i in range(8):
        tag.append(UInt8((y1 >> UInt64((7 - i) * 8)) & 0xFF) ^ s_block[i])
    for i in range(8):
        tag.append(UInt8((y0 >> UInt64((7 - i) * 8)) & 0xFF) ^ s_block[8 + i])
    return tag^


# ============================================================================
# Public API
# ============================================================================

def gcm_encrypt(
    key: List[UInt8],
    iv: List[UInt8],
    plaintext: List[UInt8],
    aad: List[UInt8],
) raises -> Tuple[List[UInt8], List[UInt8]]:
    """AES-GCM encrypt.

    Args:
        key:       AES key, 16 or 32 bytes (AES-128 or AES-256)
        iv:        Nonce, must be exactly 12 bytes
        plaintext: Data to encrypt (any length)
        aad:       Additional authenticated data (not encrypted)

    Returns:
        Tuple of (ciphertext, tag) — ciphertext same length as plaintext, tag is 16 bytes
    """
    if len(iv) != 12:
        raise Error("GCM IV must be 12 bytes")

    var aes = AES(key)
    var setup = _gcm_setup(aes, iv)
    var gkey = setup[0].copy()
    var j0   = setup[1].copy()

    var ciphertext = _aes_ctr(aes, j0, plaintext)
    var tag = _compute_tag(aes, gkey, j0, aad, ciphertext)

    return ciphertext^, tag^


def gcm_decrypt(
    key: List[UInt8],
    iv: List[UInt8],
    ciphertext: List[UInt8],
    tag: List[UInt8],
    aad: List[UInt8],
) raises -> List[UInt8]:
    """AES-GCM decrypt and verify.

    Verifies the authentication tag BEFORE returning plaintext.
    Raises Error if the tag does not match (constant-time comparison).

    Args:
        key:        AES key, 16 or 32 bytes
        iv:         Nonce, must be exactly 12 bytes
        ciphertext: Encrypted data
        tag:        16-byte authentication tag
        aad:        Additional authenticated data

    Returns:
        Plaintext (only if tag verification succeeds)
    """
    if len(iv) != 12:
        raise Error("GCM IV must be 12 bytes")
    if len(tag) != 16:
        raise Error("GCM tag must be 16 bytes")

    var aes = AES(key)
    var setup = _gcm_setup(aes, iv)
    var gkey = setup[0].copy()
    var j0   = setup[1].copy()

    # Recompute expected tag over the received ciphertext
    var expected_tag = _compute_tag(aes, gkey, j0, aad, ciphertext)

    # Constant-time tag comparison — MUST complete before decrypting
    if not hmac_equal(tag, expected_tag):
        raise Error("authentication failed")

    # Tag verified — decrypt
    return _aes_ctr(aes, j0, ciphertext)
