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
#
# chacha20_xor_into computes 16 blocks at once (4 for the tail): each state word is a SIMD
# vector whose lane i belongs to block i, so the rounds are the scalar code
# on vectors (add, xor, rotate: constant time, portable, no intrinsics).
# ============================================================================

from std.bit import rotate_bits_left
from std.collections import InlineArray
from std.ffi import external_call
from std.math import iota
from std.memory import bitcast
from std.sys.info import is_little_endian


comptime _WIDE = 16   # blocks per step for bulk data (fastest on M1: 8 -> 1.2, 16 -> 1.7 GB/s)
comptime _NARROW = 4  # blocks per step for the tail, so short records stay cheap


@always_inline
def _qr[W: Int, a: Int, b: Int, c: Int, d: Int](mut x: InlineArray[SIMD[DType.uint32, W], 16]):
    x[a] += x[b]; x[d] = rotate_bits_left[16](x[d] ^ x[a])
    x[c] += x[d]; x[b] = rotate_bits_left[12](x[b] ^ x[c])
    x[a] += x[b]; x[d] = rotate_bits_left[8](x[d] ^ x[a])
    x[c] += x[d]; x[b] = rotate_bits_left[7](x[b] ^ x[c])


@always_inline
def _xor_step[W: Int](
    k: SIMD[DType.uint32, 8], n: SIMD[DType.uint32, 4], ctr: UInt32, src: Int, dst: Int
):
    """dst[0:64W] = src[0:64W] ^ keystream blocks ctr .. ctr+W-1 (dst may equal src)."""
    comptime _V = SIMD[DType.uint32, W]
    var x = InlineArray[_V, 16](fill=_V(0))
    x[0] = _V(0x61707865)
    x[1] = _V(0x3320646E)
    x[2] = _V(0x79622D32)
    x[3] = _V(0x6B206574)
    comptime for i in range(8):
        x[4 + i] = _V(k[i])
    x[12] = _V(ctr) + iota[DType.uint32, W]()  # wraps mod 2^32 like the scalar code
    x[13] = _V(n[0])
    x[14] = _V(n[1])
    x[15] = _V(n[2])
    var init = x.copy()
    for _ in range(10):
        _qr[W, 0, 4, 8, 12](x); _qr[W, 1, 5, 9, 13](x); _qr[W, 2, 6, 10, 14](x); _qr[W, 3, 7, 11, 15](x)
        _qr[W, 0, 5, 10, 15](x); _qr[W, 1, 6, 11, 12](x); _qr[W, 2, 7, 8, 13](x); _qr[W, 3, 4, 9, 14](x)
    comptime for i in range(16):
        x[i] += init[i]

    # Transpose lanes -> blocks, four blocks (one 4x4 word tile per group of
    # four state words) at a time, and XOR 16 bytes per load/store.
    var s = Pointer[UInt8, MutAnyOrigin](unsafe_from_address=src)
    var o = Pointer[UInt8, MutAnyOrigin](unsafe_from_address=dst)
    comptime for h in range(W // 4):
        comptime for g in range(4):
            var r0 = x[4 * g + 0].slice[4, offset=4 * h]()
            var r1 = x[4 * g + 1].slice[4, offset=4 * h]()
            var r2 = x[4 * g + 2].slice[4, offset=4 * h]()
            var r3 = x[4 * g + 3].slice[4, offset=4 * h]()
            var lo = bitcast[DType.uint64, 4](r0.interleave(r1))
            var hi = bitcast[DType.uint64, 4](r2.interleave(r3))
            # four blocks' words 4g..4g+3, block-major
            var t = bitcast[DType.uint8, 64](lo.interleave(hi))
            comptime for j in range(4):
                var off = 64 * (4 * h + j) + 16 * g
                var ks = t.slice[16, offset=16 * j]()
                o.unsafe_offset(off).unsafe_store(0, s.unsafe_offset(off).unsafe_load[width=16]() ^ ks)


def chacha20_xor_into(
    key: List[UInt8], nonce: List[UInt8], counter: UInt32, src: Int, dst: Int, n: Int
) raises:
    """XOR n bytes at src with the ChaCha20 keystream starting at block
    `counter` and write them to dst (dst may equal src)."""
    comptime assert is_little_endian(), "ChaCha20 loads words in host byte order"
    if len(key) != 32:
        raise Error("ChaCha20 key must be 32 bytes")
    if len(nonce) != 12:
        raise Error("ChaCha20 nonce must be 12 bytes")
    var k = bitcast[DType.uint32, 8](
        Pointer[UInt8, MutAnyOrigin](unsafe_from_address=Int(key.unsafe_ptr())).unsafe_load[width=32]()
    )
    var nb = Pointer[UInt8, MutAnyOrigin](unsafe_from_address=Int(nonce.unsafe_ptr()))
    var nw = SIMD[DType.uint32, 4](0)
    comptime for i in range(3):
        nw[i] = bitcast[DType.uint32, 1](nb.unsafe_offset(4 * i).unsafe_load[width=4]())[0]
    var ctr = counter
    var off = 0
    while off + 64 * _WIDE <= n:
        _xor_step[_WIDE](k, nw, ctr, src + off, dst + off)
        off += 64 * _WIDE
        ctr += UInt32(_WIDE)
    while off + 64 * _NARROW <= n:
        _xor_step[_NARROW](k, nw, ctr, src + off, dst + off)
        off += 64 * _NARROW
        ctr += UInt32(_NARROW)
    if off < n:
        # last partial step: through a zeroed stack buffer
        var buf = InlineArray[UInt8, 64 * _NARROW](fill=0)
        var b = Int(buf.unsafe_ptr())
        _ = external_call["memcpy", Int](b, src + off, n - off)
        _xor_step[_NARROW](k, nw, ctr, b, b)
        _ = external_call["memcpy", Int](dst + off, b, n - off)


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
    var out = List[UInt8](length=64, fill=0)
    var a = Int(out.unsafe_ptr())
    chacha20_xor_into(key, nonce, counter, a, a, 64)
    return out^


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
    var n = len(data)
    var out = List[UInt8](unsafe_uninit_length=n)
    chacha20_xor_into(key, nonce, counter, Int(data.unsafe_ptr()), Int(out.unsafe_ptr()), n)
    return out^
