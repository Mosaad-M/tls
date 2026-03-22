# ============================================================================
# crypto/chacha20.mojo — ChaCha20 stream cipher (RFC 8439)
# ============================================================================
#
# ChaCha20 state: 16 × UInt32 words
#   [0..3]  = constants "expa","nd 3","2-by","te k"
#   [4..11] = key (32 bytes, little-endian words)
#   [12]    = block counter (32-bit)
#   [13..15]= nonce (12 bytes, little-endian words)
#
# Quarter round: a += b; d ^= a; d <<<= 16
#                c += d; b ^= c; b <<<= 12
#                a += b; d ^= a; d <<<= 8
#                c += d; b ^= c; b <<<= 7
# ============================================================================

from collections import InlineArray


def _rotl32(v: UInt32, n: Int) -> UInt32:
    return (v << UInt32(n)) | (v >> UInt32(32 - n))


def _quarter_round(
    mut s: InlineArray[UInt32, 16],
    a: Int, b: Int, c: Int, d: Int,
):
    s[a] = s[a] + s[b]; s[d] ^= s[a]; s[d] = _rotl32(s[d], 16)
    s[c] = s[c] + s[d]; s[b] ^= s[c]; s[b] = _rotl32(s[b], 12)
    s[a] = s[a] + s[b]; s[d] ^= s[a]; s[d] = _rotl32(s[d], 8)
    s[c] = s[c] + s[d]; s[b] ^= s[c]; s[b] = _rotl32(s[b], 7)


def _load_le32(data: List[UInt8], off: Int) -> UInt32:
    return (
        UInt32(data[off]) |
        (UInt32(data[off + 1]) << 8) |
        (UInt32(data[off + 2]) << 16) |
        (UInt32(data[off + 3]) << 24)
    )


def _store_le32(v: UInt32, mut data: List[UInt8]):
    data.append(UInt8(v & 0xFF))
    data.append(UInt8((v >> 8) & 0xFF))
    data.append(UInt8((v >> 16) & 0xFF))
    data.append(UInt8((v >> 24) & 0xFF))


def chacha20_block(
    key: List[UInt8],
    counter: UInt32,
    nonce: List[UInt8],
) raises -> List[UInt8]:
    """Produce one 64-byte ChaCha20 keystream block.

    Args:
        key:     32-byte ChaCha20 key
        counter: 32-bit block counter
        nonce:   12-byte nonce
    Returns:
        64-byte keystream block
    """
    if len(key) != 32:
        raise Error("ChaCha20 key must be 32 bytes")
    if len(nonce) != 12:
        raise Error("ChaCha20 nonce must be 12 bytes")

    # Build initial state
    var s = InlineArray[UInt32, 16](fill=UInt32(0))
    s[0]  = UInt32(0x61707865)  # "expa"
    s[1]  = UInt32(0x3320646e)  # "nd 3"
    s[2]  = UInt32(0x79622d32)  # "2-by"
    s[3]  = UInt32(0x6b206574)  # "te k"
    for i in range(8):
        s[4 + i] = _load_le32(key, i * 4)
    s[12] = counter
    s[13] = _load_le32(nonce, 0)
    s[14] = _load_le32(nonce, 4)
    s[15] = _load_le32(nonce, 8)

    # Save initial state for final addition
    var init = s.copy()

    # 20 rounds = 10 double rounds
    for _ in range(10):
        # Column rounds
        _quarter_round(s, 0, 4,  8, 12)
        _quarter_round(s, 1, 5,  9, 13)
        _quarter_round(s, 2, 6, 10, 14)
        _quarter_round(s, 3, 7, 11, 15)
        # Diagonal rounds
        _quarter_round(s, 0, 5, 10, 15)
        _quarter_round(s, 1, 6, 11, 12)
        _quarter_round(s, 2, 7,  8, 13)
        _quarter_round(s, 3, 4,  9, 14)

    # Add initial state
    for i in range(16):
        s[i] = s[i] + init[i]

    # Serialize little-endian
    var keystream = List[UInt8](capacity=64)
    for i in range(16):
        _store_le32(s[i], keystream)
    return keystream^


def chacha20_encrypt(
    key: List[UInt8],
    nonce: List[UInt8],
    counter: UInt32,
    data: List[UInt8],
) raises -> List[UInt8]:
    """Encrypt (or decrypt) data using ChaCha20 CTR mode.

    Args:
        key:     32-byte key
        nonce:   12-byte nonce
        counter: Initial block counter (typically 0 for key generation, 1 for data)
        data:    Plaintext or ciphertext bytes
    Returns:
        XOR of data with keystream
    """
    var out = List[UInt8](capacity=len(data))
    var pos = 0
    var ctr = counter
    while pos < len(data):
        var block = chacha20_block(key, ctr, nonce)
        var n = min(64, len(data) - pos)
        for i in range(n):
            out.append(data[pos + i] ^ block[i])
        pos += n
        ctr += 1
    return out^
