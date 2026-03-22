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
#   - Tag verification is constant-time (OR-accumulation, no early exit)
#   - Plaintext is NOT returned until tag verification passes
#   - 12-byte (96-bit) IV only — the standard safe form
# ============================================================================

from crypto.aes import AES
from crypto.hmac import hmac_equal


# ============================================================================
# GF(2^128) multiplication — GHASH spec compliant (NIST SP 800-38D Algorithm 1)
#
# Elements are (hi: UInt64, lo: UInt64) in big-endian bit order.
# Bit 0 of the 128-bit value is the MSB of hi.
# Reduction polynomial: x^128 + x^7 + x^2 + x + 1
# ============================================================================

def _gf128_mul_x(hi: UInt64, lo: UInt64) -> Tuple[UInt64, UInt64]:
    """Multiply GF(2^128) element by x (right-shift by 1 bit with conditional reduction)."""
    var lsb = lo & 1
    var r_lo = (lo >> 1) | (hi << 63)
    var r_hi = hi >> 1
    if lsb != 0:
        r_hi ^= UInt64(0xE100000000000000)
    return r_hi, r_lo


def _gf128_mul_x4(hi: UInt64, lo: UInt64) -> Tuple[UInt64, UInt64]:
    """Multiply GF(2^128) element by x^4 (four applications of mul_x)."""
    var r = _gf128_mul_x(hi, lo)
    r = _gf128_mul_x(r[0], r[1])
    r = _gf128_mul_x(r[0], r[1])
    return _gf128_mul_x(r[0], r[1])


# ============================================================================
# Precomputed 16-entry H-table for 4-bit GHASH
# ============================================================================

def _build_h_table(h_hi: UInt64, h_lo: UInt64) -> Tuple[List[UInt64], List[UInt64]]:
    """Build H_table[0..15] where H_table[v] = v * H in GF(2^128).

    Nibble bits are in MSB-first order: bit3=weight8, bit2=weight4, bit1=weight2, bit0=weight1.
    H_table[8]=H, H_table[4]=H*x, H_table[2]=H*x^2, H_table[1]=H*x^3.
    """
    # Four base vectors: b0=H*x^0=H, b1=H*x, b2=H*x^2, b3=H*x^3
    var b0_hi = h_hi;  var b0_lo = h_lo
    var r = _gf128_mul_x(h_hi, h_lo)
    var b1_hi = r[0];  var b1_lo = r[1]
    r = _gf128_mul_x(b1_hi, b1_lo)
    var b2_hi = r[0];  var b2_lo = r[1]
    r = _gf128_mul_x(b2_hi, b2_lo)
    var b3_hi = r[0];  var b3_lo = r[1]

    var hi_table = List[UInt64](capacity=16)
    var lo_table = List[UInt64](capacity=16)
    for v in range(16):
        var vh: UInt64 = 0
        var vl: UInt64 = 0
        if v & 8 != 0:
            vh ^= b0_hi; vl ^= b0_lo
        if v & 4 != 0:
            vh ^= b1_hi; vl ^= b1_lo
        if v & 2 != 0:
            vh ^= b2_hi; vl ^= b2_lo
        if v & 1 != 0:
            vh ^= b3_hi; vl ^= b3_lo
        hi_table.append(vh)
        lo_table.append(vl)
    return hi_table^, lo_table^


def _ghash_mul_block(
    hi_table: List[UInt64], lo_table: List[UInt64],
    y_hi: UInt64, y_lo: UInt64,
) -> Tuple[UInt64, UInt64]:
    """Multiply y by H using the precomputed 16-entry table.

    Processes 32 nibbles of y from LSB (i=0) to MSB (i=31), accumulating:
      acc = acc * x^4 XOR H_table[nib]
    which evaluates the Horner scheme y*H = sum_j H_table[nib_j] * x^{4j}.

    Nibble extraction: i=0..15 → y_lo nibbles LSB-first; i=16..31 → y_hi nibbles LSB-first.
    """
    var acc_hi: UInt64 = 0
    var acc_lo: UInt64 = 0
    for i in range(32):
        var nib: Int
        if i < 16:
            nib = Int((y_lo >> UInt64(4 * i)) & UInt64(0xF))
        else:
            nib = Int((y_hi >> UInt64(4 * (i - 16))) & UInt64(0xF))
        var r4 = _gf128_mul_x4(acc_hi, acc_lo)
        acc_hi = r4[0] ^ hi_table[nib]
        acc_lo = r4[1] ^ lo_table[nib]
    return acc_hi, acc_lo


# ============================================================================
# GHASH — polynomial hash over GF(2^128)
# ============================================================================

def _ghash(
    h_hi: UInt64, h_lo: UInt64,
    data: List[UInt8],
) -> Tuple[UInt64, UInt64]:
    """Compute GHASH_H(data).

    data must be a multiple of 16 bytes (caller zero-pads if needed).
    Returns (y_hi, y_lo) — 128-bit authentication value.
    """
    var y_hi: UInt64 = 0
    var y_lo: UInt64 = 0
    var n_blocks = len(data) // 16

    for b in range(n_blocks):
        # Load 16-byte block as big-endian (hi, lo)
        var off = b * 16
        var xi_hi: UInt64 = 0
        var xi_lo: UInt64 = 0
        for i in range(8):
            xi_hi = (xi_hi << 8) | UInt64(data[off + i])
        for i in range(8):
            xi_lo = (xi_lo << 8) | UInt64(data[off + 8 + i])

        y_hi ^= xi_hi
        y_lo ^= xi_lo
        var res = _gf128_mul(y_hi, y_lo, h_hi, h_lo)
        y_hi = res[0]
        y_lo = res[1]

    return y_hi, y_lo


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
    """XOR data with AES-CTR keystream starting at counter = inc32(j0)."""
    var out = List[UInt8](capacity=len(data))
    var ctr = _inc32(j0)
    var pos = 0
    while pos < len(data):
        var block = aes.encrypt_block(ctr)
        var n = min(16, len(data) - pos)
        for i in range(n):
            out.append(data[pos + i] ^ block[i])
        pos += n
        if pos < len(data):
            ctr = _inc32(ctr)
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

def _gcm_setup(
    aes: AES,
    iv: List[UInt8],
) raises -> Tuple[UInt64, UInt64, List[UInt8], List[UInt64], List[UInt64]]:
    """Return (H_hi, H_lo, J0, H_hi_table, H_lo_table) for a given AES instance and 12-byte IV."""
    # H = AES_K(0^128)
    var zero_block = List[UInt8](capacity=16)
    for _ in range(16):
        zero_block.append(0x00)
    var h_block = aes.encrypt_block(zero_block)
    var h_hi: UInt64 = 0
    var h_lo: UInt64 = 0
    for i in range(8):
        h_hi = (h_hi << 8) | UInt64(h_block[i])
    for i in range(8):
        h_lo = (h_lo << 8) | UInt64(h_block[8 + i])

    # J0 = IV || 0x00000001
    var j0 = List[UInt8](capacity=16)
    for b in iv:
        j0.append(b)
    j0.append(0x00); j0.append(0x00); j0.append(0x00); j0.append(0x01)

    # Precompute 16-entry GHASH multiplication table
    var tables = _build_h_table(h_hi, h_lo)
    var hi_tbl = tables[0].copy()
    var lo_tbl = tables[1].copy()
    return h_hi, h_lo, j0^, hi_tbl^, lo_tbl^


def _compute_tag(
    aes: AES,
    hi_table: List[UInt64], lo_table: List[UInt64],
    j0: List[UInt8],
    aad: List[UInt8],
    ct: List[UInt8],
) raises -> List[UInt8]:
    """Compute GCM authentication tag using 4-bit precomputed GHASH table."""
    var ghash_input = _build_ghash_input(aad, ct)
    # Use table-based GHASH (4x faster than bit-by-bit)
    var y_hi: UInt64 = 0
    var y_lo: UInt64 = 0
    var n_blocks = len(ghash_input) // 16
    for b in range(n_blocks):
        var off = b * 16
        var xi_hi: UInt64 = 0
        var xi_lo: UInt64 = 0
        for i in range(8):
            xi_hi = (xi_hi << 8) | UInt64(ghash_input[off + i])
        for i in range(8):
            xi_lo = (xi_lo << 8) | UInt64(ghash_input[off + 8 + i])
        y_hi ^= xi_hi
        y_lo ^= xi_lo
        var gh = _ghash_mul_block(hi_table, lo_table, y_hi, y_lo)
        y_hi = gh[0]
        y_lo = gh[1]

    var s_block = aes.encrypt_block(j0)
    var tag = List[UInt8](capacity=16)
    for i in range(8):
        tag.append(UInt8((y_hi >> UInt64((7 - i) * 8)) & 0xFF) ^ s_block[i])
    for i in range(8):
        tag.append(UInt8((y_lo >> UInt64((7 - i) * 8)) & 0xFF) ^ s_block[8 + i])
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
    var j0        = setup[2].copy()
    var hi_table  = setup[3].copy()
    var lo_table  = setup[4].copy()

    var ciphertext = _aes_ctr(aes, j0, plaintext)
    var tag = _compute_tag(aes, hi_table, lo_table, j0, aad, ciphertext)

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
    var j0        = setup[2].copy()
    var hi_table  = setup[3].copy()
    var lo_table  = setup[4].copy()

    # Recompute expected tag over the received ciphertext
    var expected_tag = _compute_tag(aes, hi_table, lo_table, j0, aad, ciphertext)

    # Constant-time tag comparison — MUST complete before decrypting
    if not hmac_equal(tag, expected_tag):
        raise Error("authentication failed")

    # Tag verified — decrypt
    return _aes_ctr(aes, j0, ciphertext)
