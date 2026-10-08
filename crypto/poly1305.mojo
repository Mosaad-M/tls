# ============================================================================
# crypto/poly1305.mojo — Poly1305 MAC + ChaCha20-Poly1305 AEAD (RFC 8439)
# ============================================================================
#
# Poly1305 computes a 128-bit (16-byte) MAC:
#   MAC = ((accumulate message blocks with r) + s) mod 2^128
#   where r, s are derived from the 32-byte one-time key
#
# Arithmetic in GF(2^130 - 5) uses 3 limbs of 44/44/42 bits with 64x64->128
# multiplies (poly1305-donna-64); the AEAD streams AAD, ciphertext, padding
# and lengths into it without building the MAC input.
#
# Security:
#   - Constant time: fixed multiplies, adds and masks; no secret branches
#   - Tag comparison is constant-time (via OR-accumulation)
#   - Poly1305 key is derived from ChaCha20 block at counter=0
#   - Decryption runs only after the tag verified: a forged record never
#     produces any plaintext
# ============================================================================

from std.collections import InlineArray
from std.memory import bitcast
from crypto.chacha20 import chacha20_block, chacha20_xor_into

comptime _M44: UInt64 = 0xFFFFFFFFFFF
comptime _M42: UInt64 = 0x3FFFFFFFFFF


@always_inline
def _le128(addr: Int) -> SIMD[DType.uint64, 2]:
    return bitcast[DType.uint64, 2](Pointer[UInt8, MutAnyOrigin](unsafe_from_address=addr).unsafe_load[width=16]())


@always_inline
def _mul(a: UInt64, b: UInt64) -> UInt128:
    return UInt128(a) * UInt128(b)


struct _Poly1305(Movable):
    """Streaming Poly1305 state (radix 2^44)."""
    var r0: UInt64
    var r1: UInt64
    var r2: UInt64
    var s1: UInt64
    var s2: UInt64
    var h0: UInt64
    var h1: UInt64
    var h2: UInt64
    var q0: UInt64  # r^2 (two blocks per step: h = (h + m1) r^2 + m2 r)
    var q1: UInt64
    var q2: UInt64
    var t1: UInt64
    var t2: UInt64
    var pad: SIMD[DType.uint64, 2]
    var buf: InlineArray[UInt8, 16]
    var buf_len: Int

    def __init__(out self, key_addr: Int):
        """key_addr: 32 bytes, r = key[0:16] (clamped), s = key[16:32]."""
        var t = _le128(key_addr)
        self.r0 = t[0] & 0xFFC0FFFFFFF
        self.r1 = ((t[0] >> 44) | (t[1] << 20)) & 0xFFFFFC0FFFF
        self.r2 = (t[1] >> 24) & 0x00FFFFFFC0F
        self.s1 = self.r1 * (5 << 2)
        self.s2 = self.r2 * (5 << 2)
        self.h0 = 0
        self.h1 = 0
        self.h2 = 0
        # r^2 = r * r, carried like a block result (limbs ~44 bits)
        var d0 = _mul(self.r0, self.r0) + _mul(self.r1, self.s2) + _mul(self.r2, self.s1)
        var d1 = _mul(self.r0, self.r1) + _mul(self.r1, self.r0) + _mul(self.r2, self.s2)
        var d2 = _mul(self.r0, self.r2) + _mul(self.r1, self.r1) + _mul(self.r2, self.r0)
        var c = UInt64(d0 >> 44)
        var q0 = UInt64(d0) & _M44
        d1 += UInt128(c)
        c = UInt64(d1 >> 44)
        var q1 = UInt64(d1) & _M44
        d2 += UInt128(c)
        c = UInt64(d2 >> 42)
        var q2 = UInt64(d2) & _M42
        q0 += c * 5
        c = q0 >> 44
        q0 &= _M44
        q1 += c
        self.q0 = q0
        self.q1 = q1
        self.q2 = q2
        self.t1 = q1 * (5 << 2)
        self.t2 = q2 * (5 << 2)
        self.pad = _le128(key_addr + 16)
        self.buf = InlineArray[UInt8, 16](fill=0)
        self.buf_len = 0

    @always_inline
    def _blocks(mut self, addr: Int, nblocks: Int, hibit: UInt64):
        var pairs = nblocks // 2
        if pairs > 0:
            self._pairs(addr, pairs, hibit)
        if nblocks % 2 == 1:
            self._run[True](addr + 32 * pairs, 1, hibit, SIMD[DType.uint64, 2](0))

    @always_inline
    def _pairs(mut self, addr: Int, npairs: Int, hibit: UInt64):
        """Two blocks per step: h = (h + m1) * r^2 + m2 * r, one reduction.
        The two products are independent, so the multiplies overlap."""
        var r0 = self.r0
        var r1 = self.r1
        var r2 = self.r2
        var s1 = self.s1
        var s2 = self.s2
        var q0 = self.q0
        var q1 = self.q1
        var q2 = self.q2
        var t1 = self.t1
        var t2 = self.t2
        var h0 = self.h0
        var h1 = self.h1
        var h2 = self.h2
        for i in range(npairs):
            var a = _le128(addr + 32 * i)
            var b = _le128(addr + 32 * i + 16)
            h0 += a[0] & _M44
            h1 += ((a[0] >> 44) | (a[1] << 20)) & _M44
            h2 += ((a[1] >> 24) & _M42) | hibit
            var m0 = b[0] & _M44
            var m1 = ((b[0] >> 44) | (b[1] << 20)) & _M44
            var m2 = ((b[1] >> 24) & _M42) | hibit
            var d0 = _mul(h0, q0) + _mul(h1, t2) + _mul(h2, t1) + _mul(m0, r0) + _mul(m1, s2) + _mul(m2, s1)
            var d1 = _mul(h0, q1) + _mul(h1, q0) + _mul(h2, t2) + _mul(m0, r1) + _mul(m1, r0) + _mul(m2, s2)
            var d2 = _mul(h0, q2) + _mul(h1, q1) + _mul(h2, q0) + _mul(m0, r2) + _mul(m1, r1) + _mul(m2, r0)
            var c = UInt64(d0 >> 44)
            h0 = UInt64(d0) & _M44
            d1 += UInt128(c)
            c = UInt64(d1 >> 44)
            h1 = UInt64(d1) & _M44
            d2 += UInt128(c)
            c = UInt64(d2 >> 42)
            h2 = UInt64(d2) & _M42
            h0 += c * 5
            c = h0 >> 44
            h0 &= _M44
            h1 += c
        self.h0 = h0
        self.h1 = h1
        self.h2 = h2

    @always_inline
    def _run[FROM_MEMORY: Bool](mut self, addr: Int, nblocks: Int, hibit: UInt64, word: SIMD[DType.uint64, 2]):
        """Absorb nblocks 16-byte blocks from addr, or (FROM_MEMORY False)
        the single block `word`."""
        var r0 = self.r0
        var r1 = self.r1
        var r2 = self.r2
        var s1 = self.s1
        var s2 = self.s2
        var h0 = self.h0
        var h1 = self.h1
        var h2 = self.h2
        for i in range(nblocks):
            var t: SIMD[DType.uint64, 2]
            comptime if FROM_MEMORY:
                t = _le128(addr + 16 * i)
            else:
                t = word
            h0 += t[0] & _M44
            h1 += ((t[0] >> 44) | (t[1] << 20)) & _M44
            h2 += ((t[1] >> 24) & _M42) | hibit
            var d0 = _mul(h0, r0) + _mul(h1, s2) + _mul(h2, s1)
            var d1 = _mul(h0, r1) + _mul(h1, r0) + _mul(h2, s2)
            var d2 = _mul(h0, r2) + _mul(h1, r1) + _mul(h2, r0)
            var c = UInt64(d0 >> 44)
            h0 = UInt64(d0) & _M44
            d1 += UInt128(c)
            c = UInt64(d1 >> 44)
            h1 = UInt64(d1) & _M44
            d2 += UInt128(c)
            c = UInt64(d2 >> 42)
            h2 = UInt64(d2) & _M42
            h0 += c * 5
            c = h0 >> 44
            h0 &= _M44
            h1 += c
        self.h0 = h0
        self.h1 = h1
        self.h2 = h2

    def update(mut self, addr: Int, n: Int):
        """Absorb n bytes; a partial block waits in the buffer."""
        var src = Pointer[UInt8, MutAnyOrigin](unsafe_from_address=addr)
        var off = 0
        if self.buf_len > 0:
            var take = min(16 - self.buf_len, n)
            for i in range(take):
                self.buf[self.buf_len + i] = src[unsafe_offset=i]
            self.buf_len += take
            off = take
            if self.buf_len < 16:
                return
            self._blocks(Int(self.buf.unsafe_ptr()), 1, UInt64(1) << 40)
            self.buf_len = 0
        var full = (n - off) // 16
        if full > 0:
            self._blocks(addr + off, full, UInt64(1) << 40)
            off += 16 * full
        for i in range(n - off):
            self.buf[i] = src[unsafe_offset=off + i]
        self.buf_len = n - off

    def lengths(mut self, a: Int, b: Int):
        """Absorb le64(a) || le64(b) as one block (buffer must be empty)."""
        self._run[False](0, 1, UInt64(1) << 40, SIMD[DType.uint64, 2](UInt64(a), UInt64(b)))

    def pad16(mut self):
        """Zero-pad the pending partial block to 16 bytes (RFC 8439 §2.8)."""
        if self.buf_len > 0:
            for i in range(self.buf_len, 16):
                self.buf[i] = 0
            self._blocks(Int(self.buf.unsafe_ptr()), 1, UInt64(1) << 40)
            self.buf_len = 0

    def finish(mut self) -> SIMD[DType.uint8, 16]:
        if self.buf_len > 0:
            # final partial block: append 0x01, zero-fill, no 2^128 bit
            self.buf[self.buf_len] = 1
            for i in range(self.buf_len + 1, 16):
                self.buf[i] = 0
            self._blocks(Int(self.buf.unsafe_ptr()), 1, 0)
            self.buf_len = 0
        var h0 = self.h0
        var h1 = self.h1
        var h2 = self.h2
        # fully carry h (twice: the first pass can leave a carry into h1)
        var c: UInt64
        for _ in range(2):
            c = h1 >> 44
            h1 &= _M44
            h2 += c
            c = h2 >> 42
            h2 &= _M42
            h0 += c * 5
            c = h0 >> 44
            h0 &= _M44
            h1 += c
        # g = h - p = h + 5 - 2^130; use g when it does not underflow (h >= p)
        var g0 = h0 + 5
        c = g0 >> 44
        g0 &= _M44
        var g1 = h1 + c
        c = g1 >> 44
        g1 &= _M44
        var g2 = h2 + c - (UInt64(1) << 42)
        var mask = (g2 >> 63) - 1  # all ones when h >= p
        g0 &= mask
        g1 &= mask
        g2 &= mask
        mask = ~mask
        h0 = (h0 & mask) | g0
        h1 = (h1 & mask) | g1
        h2 = (h2 & mask) | g2
        # h + s mod 2^128
        var t0 = self.pad[0]
        var t1 = self.pad[1]
        h0 += t0 & _M44
        c = h0 >> 44
        h0 &= _M44
        h1 += (((t0 >> 44) | (t1 << 20)) & _M44) + c
        c = h1 >> 44
        h1 &= _M44
        h2 += ((t1 >> 24) & _M42) + c
        h2 &= _M42
        var out = SIMD[DType.uint64, 2](h0 | (h1 << 44), (h1 >> 20) | (h2 << 24))
        return bitcast[DType.uint8, 16](out)


def _tag_list(t: SIMD[DType.uint8, 16]) -> List[UInt8]:
    var out = List[UInt8](capacity=16)
    for i in range(16):
        out.append(t[i])
    return out^


# ============================================================================
# Poly1305 MAC
# ============================================================================

def poly1305_mac(key: List[UInt8], msg: List[UInt8]) raises -> List[UInt8]:
    """Compute Poly1305 MAC.

    Args:
        key: 32-byte one-time key (r = key[0:16], s = key[16:32])
        msg: Message to authenticate (any length)
    Returns:
        16-byte authentication tag
    """
    if len(key) != 32:
        raise Error("Poly1305 key must be 32 bytes")
    var p = _Poly1305(Int(key.unsafe_ptr()))
    p.update(Int(msg.unsafe_ptr()), len(msg))
    return _tag_list(p.finish())


# ============================================================================
# ChaCha20-Poly1305 AEAD, address based (the record layer's path)
# ============================================================================

def _aead_check(key: List[UInt8], nonce: List[UInt8], n: Int) raises:
    if len(key) != 32:
        raise Error("ChaCha20-Poly1305 key must be 32 bytes")
    if len(nonce) != 12:
        raise Error("ChaCha20-Poly1305 nonce must be 12 bytes")
    # RFC 8439: a 32-bit block counter starting at 1 covers 2^38 - 64 bytes
    if n > 274877906880:
        raise Error("ChaCha20-Poly1305: message too long for one nonce")


def _aead_tag(
    key: List[UInt8], nonce: List[UInt8], aad_addr: Int, aad_len: Int, ct_addr: Int, n: Int
) raises -> SIMD[DType.uint8, 16]:
    """Poly1305 over pad16(AAD) || pad16(CT) || le64(len AAD) || le64(len CT),
    keyed with the first 32 bytes of ChaCha20 block 0."""
    var otk = chacha20_block(key, 0, nonce)
    var p = _Poly1305(Int(otk.unsafe_ptr()))
    _ = len(otk)  # read through its address above: keep alive until here
    p.update(aad_addr, aad_len)
    p.pad16()
    p.update(ct_addr, n)
    p.pad16()
    p.lengths(aad_len, n)
    return p.finish()


def chacha20_poly1305_seal_into(
    key: List[UInt8], nonce: List[UInt8], aad_addr: Int, aad_len: Int, src: Int, dst: Int, n: Int
) raises -> SIMD[DType.uint8, 16]:
    """Encrypt n bytes at src into dst (dst may equal src); returns the tag."""
    _aead_check(key, nonce, n)
    chacha20_xor_into(key, nonce, 1, src, dst, n)
    return _aead_tag(key, nonce, aad_addr, aad_len, dst, n)


def chacha20_poly1305_open_into(
    key: List[UInt8], nonce: List[UInt8], aad_addr: Int, aad_len: Int,
    src: Int, dst: Int, n: Int, tag_addr: Int,
) raises -> Bool:
    """Check the tag at tag_addr over the n ciphertext bytes at src, in
    constant time; only if it matches, decrypt into dst (dst may equal src).
    False on a mismatch, with nothing written to dst."""
    _aead_check(key, nonce, n)
    var expect = _aead_tag(key, nonce, aad_addr, aad_len, src, n)
    var given = Pointer[UInt8, MutAnyOrigin](unsafe_from_address=tag_addr).unsafe_load[width=16]()
    if (expect ^ given).reduce_or() != 0:
        return False
    chacha20_xor_into(key, nonce, 1, src, dst, n)
    return True


# ============================================================================
# Public AEAD API (Lists)
# ============================================================================

def chacha20_poly1305_encrypt(
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
    var n = len(plaintext)
    var ct = List[UInt8](unsafe_uninit_length=n)
    var t = chacha20_poly1305_seal_into(
        key, nonce, Int(aad.unsafe_ptr()), len(aad), Int(plaintext.unsafe_ptr()), Int(ct.unsafe_ptr()), n
    )
    return ct^, _tag_list(t)


def chacha20_poly1305_decrypt(
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
    _aead_check(key, nonce, len(ciphertext))
    if len(tag) != 16:
        raise Error("ChaCha20-Poly1305 tag must be 16 bytes")
    var n = len(ciphertext)
    var pt = List[UInt8](unsafe_uninit_length=n)
    if not chacha20_poly1305_open_into(
        key, nonce, Int(aad.unsafe_ptr()), len(aad), Int(ciphertext.unsafe_ptr()), Int(pt.unsafe_ptr()), n,
        Int(tag.unsafe_ptr()),
    ):
        raise Error("authentication failed")
    return pt^
