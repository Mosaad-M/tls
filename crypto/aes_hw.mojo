# ============================================================================
# aes_hw.mojo — AES-GCM on the CPU's AES and carry-less-multiply instructions
# ============================================================================
# ARMv8 (AESE/AESMC/PMULL) and x86 (AESENC/AESENCLAST/PCLMULQDQ). These
# instructions take the same time whatever the data and key, so this path is
# constant time like the software one (crypto/aes.mojo, crypto/gcm.mojo) and
# ~20x faster.
#
# GCM_HW is decided at compile time from the target's features: native
# builds on Apple Silicon, ARMv8 with the crypto extension, or x86 with AES-NI
# and PCLMUL use it; other targets (e.g. a portable x86-64-v2 build) use the
# software path. -D TLS_SOFT_AES=true forces the software path.
#
# GHASH works on byte-wise bit-reversed blocks: after reversing the bits of
# each byte, GCM's bit order (bit 0 = most significant bit of byte 0 = x^0)
# becomes the ordinary little-endian polynomial order, so multiplication is a
# plain carry-less product reduced by x^128 + x^7 + x^2 + x + 1.
# ============================================================================

from std.bit import byte_swap
from std.memory import bitcast
from std.sys import get_defined_bool
from std.sys.info import CompilationTarget
from std.sys.intrinsics import llvm_intrinsic
from crypto.aes import expand_key_words

comptime V16 = SIMD[DType.uint8, 16]
comptime U64x2 = SIMD[DType.uint64, 2]

comptime _X86 = CompilationTarget.is_x86()
comptime _HW_ARM = (not _X86) and CompilationTarget.has_neon() and CompilationTarget._has_feature["aes"]()
comptime _HW_X86 = _X86 and CompilationTarget._has_feature["aes"]() and CompilationTarget._has_feature["pclmul"]()
comptime GCM_HW = (not get_defined_bool["TLS_SOFT_AES", False]()) and (_HW_ARM or _HW_X86)


# ── Instructions ────────────────────────────────────────────────────────────

@always_inline
def _bitrev_bytes(v: V16) -> V16:
    return llvm_intrinsic["llvm.bitreverse.v16i8", V16, has_side_effect=False](v)


@always_inline
def _clmul(a: UInt64, b: UInt64) -> U64x2:
    """64 x 64 -> 128-bit carry-less product as (low, high) words."""
    comptime if _HW_X86:
        return llvm_intrinsic["llvm.x86.pclmulqdq", U64x2, has_side_effect=False](
            U64x2(a, 0), U64x2(b, 0), Int8(0)
        )
    else:
        var p = llvm_intrinsic["llvm.aarch64.neon.pmull64", V16, has_side_effect=False](a, b)
        return bitcast[DType.uint64, 2](p)


struct _RoundKeys(Copyable, Movable):
    var rk: InlineArray[V16, 15]
    var nr: Int

    def __init__(out self, key: List[UInt8]) raises:
        var w = expand_key_words(key)
        self.nr = len(w) // 4 - 1
        self.rk = InlineArray[V16, 15](fill=V16(0))
        for r in range(self.nr + 1):
            var v = V16(0)
            for j in range(4):
                var word = w[4 * r + j]
                for b in range(4):
                    v[4 * j + b] = UInt8((word >> UInt32(8 * b)) & 0xFF)
            self.rk[r] = v

    def __init__(out self, *, copy: Self):
        self.rk = copy.rk.copy()
        self.nr = copy.nr


@always_inline
def _encrypt_block(k: _RoundKeys, block: V16) -> V16:
    comptime if _HW_X86:
        var s = bitcast[DType.uint64, 2](block ^ k.rk[0])
        for r in range(1, k.nr):
            s = llvm_intrinsic["llvm.x86.aesni.aesenc", U64x2, has_side_effect=False](
                s, bitcast[DType.uint64, 2](k.rk[r])
            )
        s = llvm_intrinsic["llvm.x86.aesni.aesenclast", U64x2, has_side_effect=False](
            s, bitcast[DType.uint64, 2](k.rk[k.nr])
        )
        return bitcast[DType.uint8, 16](s)
    else:
        var s = block
        for r in range(k.nr - 1):
            s = llvm_intrinsic["llvm.aarch64.crypto.aese", V16, has_side_effect=False](s, k.rk[r])
            s = llvm_intrinsic["llvm.aarch64.crypto.aesmc", V16, has_side_effect=False](s)
        s = llvm_intrinsic["llvm.aarch64.crypto.aese", V16, has_side_effect=False](s, k.rk[k.nr - 1])
        return s ^ k.rk[k.nr]


@always_inline
def _enc8_rounds[NR: Int](rk: InlineArray[V16, 15], mut b: InlineArray[V16, 8]):
    """Eight blocks, rounds fully unrolled for NR (10 or 14): the round keys
    stay in registers and the AES units pipeline across the blocks."""
    comptime if _HW_X86:
        var s = InlineArray[U64x2, 8](fill=U64x2(0))
        comptime for i in range(8):
            s[i] = bitcast[DType.uint64, 2](b[i] ^ rk[0])
        comptime for r in range(1, NR):
            comptime for i in range(8):
                s[i] = llvm_intrinsic["llvm.x86.aesni.aesenc", U64x2, has_side_effect=False](
                    s[i], bitcast[DType.uint64, 2](rk[r])
                )
        comptime for i in range(8):
            b[i] = bitcast[DType.uint8, 16](
                llvm_intrinsic["llvm.x86.aesni.aesenclast", U64x2, has_side_effect=False](
                    s[i], bitcast[DType.uint64, 2](rk[NR])
                )
            )
    else:
        comptime for r in range(NR - 1):
            comptime for i in range(8):
                b[i] = llvm_intrinsic["llvm.aarch64.crypto.aesmc", V16, has_side_effect=False](
                    llvm_intrinsic["llvm.aarch64.crypto.aese", V16, has_side_effect=False](b[i], rk[r])
                )
        comptime for i in range(8):
            b[i] = llvm_intrinsic["llvm.aarch64.crypto.aese", V16, has_side_effect=False](b[i], rk[NR - 1]) ^ rk[NR]


@always_inline
def _encrypt8(rk: InlineArray[V16, 15], nr: Int, mut b: InlineArray[V16, 8]):
    if nr == 14:
        _enc8_rounds[14](rk, b)
    else:
        _enc8_rounds[10](rk, b)


# ── GF(2^128) in bit-reversed (ordinary polynomial) form ────────────────────
#
# Products use deferred Karatsuba: per block, three carry-less multiplies
# into separate low / high / middle accumulators (all in vector registers;
# the middle operand x0^x1 comes from one lane rotation, and h0^h1 is
# precomputed per power of H), then one combine and reduction per group of
# eight blocks multiplied by H^8..H^1.

@always_inline
def _to_field(block: V16) -> U64x2:
    return bitcast[DType.uint64, 2](_bitrev_bytes(block))


@always_inline
def _from_field(x: U64x2) -> V16:
    return _bitrev_bytes(bitcast[DType.uint8, 16](x))


@always_inline
def _acc_mul(mut lo: U64x2, mut hi: U64x2, mut mid: U64x2, x: U64x2, h: U64x2, hk: UInt64):
    """Accumulate x * h (unreduced): lo += x0*h0, hi += x1*h1,
    mid += (x0^x1)*(h0^h1)."""
    lo ^= _clmul(x[0], h[0])
    hi ^= _clmul(x[1], h[1])
    var t = x ^ x.rotate_left[1]()
    mid ^= _clmul(t[0], hk)


@always_inline
def _acc_reduce(lo: U64x2, hi: U64x2, mid: U64x2) -> U64x2:
    """Combine the Karatsuba terms into the 256-bit product w3:w2:w1:w0 and
    reduce modulo x^128 + x^7 + x^2 + x + 1 (x^128 = 0x87)."""
    var m = U64x2(lo[1], hi[0]) ^ mid ^ lo ^ hi   # (w1, w2)
    m ^= _clmul(hi[1], 0x87)                      # w3 * x^192 = w3 * x^64 * 0x87
    var b = _clmul(m[1], 0x87)                    # w2 * x^128 = w2 * 0x87
    return U64x2(lo[0] ^ b[0], m[0] ^ b[1])


@always_inline
def _gmul(x: U64x2, h: U64x2) -> U64x2:
    var lo = U64x2(0)
    var hi = U64x2(0)
    var mid = U64x2(0)
    _acc_mul(lo, hi, mid, x, h, h[0] ^ h[1])
    return _acc_reduce(lo, hi, mid)


# ── GCM ─────────────────────────────────────────────────────────────────────

struct HwGcmKey(Copyable, Movable):
    """An AES key prepared for hardware GCM: round keys and H^1..H^8 (with
    each power's h0^h1 for Karatsuba)."""
    var k: _RoundKeys
    var hp: InlineArray[U64x2, 8]     # hp[i] = H^(i+1)
    var hk: InlineArray[UInt64, 8]    # hk[i] = hp[i][0] ^ hp[i][1]

    def __init__(out self, key: List[UInt8]) raises:
        self.k = _RoundKeys(key)
        self.hp = InlineArray[U64x2, 8](fill=U64x2(0))
        self.hk = InlineArray[UInt64, 8](fill=0)
        var h = _to_field(_encrypt_block(self.k, V16(0)))
        self.hp[0] = h
        for i in range(1, 8):
            self.hp[i] = _gmul(self.hp[i - 1], h)
        for i in range(8):
            self.hk[i] = self.hp[i][0] ^ self.hp[i][1]

    def __init__(out self, *, copy: Self):
        self.k = _RoundKeys(copy=copy.k)
        self.hp = copy.hp.copy()
        self.hk = copy.hk.copy()

    @always_inline
    def _mul1(self, x: U64x2) -> U64x2:
        var lo = U64x2(0)
        var hi = U64x2(0)
        var mid = U64x2(0)
        _acc_mul(lo, hi, mid, x, self.hp[0], self.hk[0])
        return _acc_reduce(lo, hi, mid)

    @always_inline
    def _absorb8(self, y: U64x2, x: InlineArray[U64x2, 8]) -> U64x2:
        """y = (y ^ x0)*H^8 ^ x1*H^7 ^ ... ^ x7*H, one reduction."""
        var lo = U64x2(0)
        var hi = U64x2(0)
        var mid = U64x2(0)
        comptime for i in range(8):
            var xi = x[i]
            comptime if i == 0:
                xi ^= y
            _acc_mul(lo, hi, mid, xi, self.hp[7 - i], self.hk[7 - i])
        return _acc_reduce(lo, hi, mid)

    def _ghash(self, mut y: U64x2, p: Int, n: Int):
        """Absorb n bytes at address p (the last block zero-padded)."""
        var src = Pointer[UInt8, MutAnyOrigin](unsafe_from_address=p)
        var off = 0
        while off + 128 <= n:
            var lo = U64x2(0)
            var hi = U64x2(0)
            var mid = U64x2(0)
            comptime for i in range(8):
                var x = _to_field(src.unsafe_offset(off + 16 * i).unsafe_load[width=16]())
                comptime if i == 0:
                    x ^= y
                _acc_mul(lo, hi, mid, x, self.hp[7 - i], self.hk[7 - i])
            y = _acc_reduce(lo, hi, mid)
            off += 128
        while off + 16 <= n:
            y = self._mul1(y ^ _to_field(src.unsafe_offset(off).unsafe_load[width=16]()))
            off += 16
        if off < n:
            var last = V16(0)
            for i in range(n - off):
                last[i] = src[unsafe_offset=off + i]
            y = self._mul1(y ^ _to_field(last))

    def _crypt[DECRYPT: Bool](self, j0: V16, mut y: U64x2, src_addr: Int, dst_addr: Int, n: Int):
        """CTR mode and GHASH in one pass: dst = src XOR keystream (counters
        inc32(J0), ...), and the ciphertext (src when decrypting, dst when
        encrypting) is absorbed into y. Eight blocks per group, so the AES
        and carry-less-multiply instructions run side by side. dst may equal
        src: each block is read before it is written."""
        var src = Pointer[UInt8, MutAnyOrigin](unsafe_from_address=src_addr)
        var dst = Pointer[UInt8, MutAnyOrigin](unsafe_from_address=dst_addr)
        var c0 = (UInt32(j0[12]) << 24) | (UInt32(j0[13]) << 16) | (UInt32(j0[14]) << 8) | UInt32(j0[15])
        var ctr = c0 + 1
        var off = 0
        var ks = InlineArray[V16, 8](fill=V16(0))
        var rk = self.k.rk.copy()   # local copy: no aliasing with dst, so kept in registers
        var nr = self.k.nr
        # Encrypting: the GHASH of each group depends on that group's AES
        # output, so it is deferred one group (software pipelining) and runs
        # while the next group's AES does. Decrypting needs no deferral.
        var prev = InlineArray[U64x2, 8](fill=U64x2(0))
        var have_prev = False
        while off + 128 <= n:
            comptime for i in range(8):
                ks[i] = _counter_block(j0, ctr + UInt32(i))
            _encrypt8(rk, nr, ks)
            comptime if DECRYPT:
                var lo = U64x2(0)
                var hi = U64x2(0)
                var mid = U64x2(0)
                comptime for i in range(8):
                    var inb = src.unsafe_offset(off + 16 * i).unsafe_load[width=16]()
                    dst.unsafe_offset(off + 16 * i).unsafe_store(0, inb ^ ks[i])
                    var x = _to_field(inb)
                    comptime if i == 0:
                        x ^= y
                    _acc_mul(lo, hi, mid, x, self.hp[7 - i], self.hk[7 - i])
                y = _acc_reduce(lo, hi, mid)
            else:
                if have_prev:
                    y = self._absorb8(y, prev)
                comptime for i in range(8):
                    var outb = src.unsafe_offset(off + 16 * i).unsafe_load[width=16]() ^ ks[i]
                    dst.unsafe_offset(off + 16 * i).unsafe_store(0, outb)
                    prev[i] = _to_field(outb)
                have_prev = True
            ctr += 8
            off += 128
        comptime if not DECRYPT:
            if have_prev:
                y = self._absorb8(y, prev)
        while off + 16 <= n:
            var inb = src.unsafe_offset(off).unsafe_load[width=16]()
            var outb = inb ^ _encrypt_block(self.k, _counter_block(j0, ctr))
            dst.unsafe_offset(off).unsafe_store(0, outb)
            comptime if DECRYPT:
                y = self._mul1(y ^ _to_field(inb))
            else:
                y = self._mul1(y ^ _to_field(outb))
            ctr += 1
            off += 16
        if off < n:
            var ksb = _encrypt_block(self.k, _counter_block(j0, ctr))
            var ct = V16(0)
            for i in range(n - off):
                var b = src[unsafe_offset=off + i]
                var o = b ^ ksb[i]
                dst[unsafe_offset=off + i] = o
                comptime if DECRYPT:
                    ct[i] = b
                else:
                    ct[i] = o
            y = self._mul1(y ^ _to_field(ct))

    def _j0(self, iv: List[UInt8]) -> V16:
        var j0 = V16(0)
        if len(iv) == 12:
            for i in range(12):
                j0[i] = iv[i]
            j0[15] = 1
            return j0
        var y = U64x2(0)
        self._ghash(y, Int(iv.unsafe_ptr()), len(iv))
        y = self._mul1(y ^ _to_field(_len_block(0, len(iv))))
        return _from_field(y)

    def seal_into(self, iv: List[UInt8], aad_addr: Int, aad_len: Int, src: Int, dst: Int, n: Int) -> V16:
        """Encrypt n bytes from src to dst (may be equal); returns the tag."""
        var j0 = self._j0(iv)
        var y = U64x2(0)
        self._ghash(y, aad_addr, aad_len)
        self._crypt[False](j0, y, src, dst, n)
        y = self._mul1(y ^ _to_field(_len_block(aad_len, n)))
        return _from_field(y) ^ _encrypt_block(self.k, j0)

    def open_into(
        self, iv: List[UInt8], aad_addr: Int, aad_len: Int, src: Int, dst: Int, n: Int, tag_addr: Int
    ) -> Bool:
        """Decrypt n bytes from src to dst (may be equal) and check the tag in
        constant time. On a mismatch the written plaintext is zeroed and False
        is returned: no unauthenticated plaintext stays visible."""
        var j0 = self._j0(iv)
        var y = U64x2(0)
        self._ghash(y, aad_addr, aad_len)
        self._crypt[True](j0, y, src, dst, n)
        y = self._mul1(y ^ _to_field(_len_block(aad_len, n)))
        var expect = _from_field(y) ^ _encrypt_block(self.k, j0)
        var given = Pointer[UInt8, MutAnyOrigin](unsafe_from_address=tag_addr).unsafe_load[width=16]()
        if (expect ^ given).reduce_or() == 0:
            return True
        var out = Pointer[UInt8, MutAnyOrigin](unsafe_from_address=dst)
        var off = 0
        while off + 16 <= n:
            out.unsafe_offset(off).unsafe_store(0, V16(0))
            off += 16
        while off < n:
            out[unsafe_offset=off] = 0
            off += 1
        return False

    def seal(
        self, iv: List[UInt8], plaintext: List[UInt8], aad: List[UInt8]
    ) raises -> Tuple[List[UInt8], List[UInt8]]:
        var n = len(plaintext)
        var ct = List[UInt8](unsafe_uninit_length=n)
        var t = self.seal_into(iv, Int(aad.unsafe_ptr()), len(aad), Int(plaintext.unsafe_ptr()), Int(ct.unsafe_ptr()), n)
        var tag = List[UInt8](capacity=16)
        for i in range(16):
            tag.append(t[i])
        return (ct^, tag^)

    def open(
        self, iv: List[UInt8], ciphertext: List[UInt8], tag: List[UInt8], aad: List[UInt8]
    ) raises -> List[UInt8]:
        if len(tag) != 16:
            raise Error("GCM tag must be 16 bytes")
        var n = len(ciphertext)
        var pt = List[UInt8](unsafe_uninit_length=n)
        if not self.open_into(iv, Int(aad.unsafe_ptr()), len(aad), Int(ciphertext.unsafe_ptr()), Int(pt.unsafe_ptr()), n, Int(tag.unsafe_ptr())):
            raise Error("authentication failed")
        return pt^


@always_inline
def _counter_block(j0: V16, ctr: UInt32) -> V16:
    """J0 with its last 32 bits (big-endian) replaced by ctr."""
    var w = bitcast[DType.uint32, 4](j0)
    w[3] = byte_swap(ctr)
    return bitcast[DType.uint8, 16](w)


def _len_block(aad_len: Int, ct_len: Int) -> V16:
    """[len(A) in bits]_64 || [len(C) in bits]_64, big-endian."""
    var b = V16(0)
    var a = UInt64(aad_len) * 8
    var c = UInt64(ct_len) * 8
    for i in range(8):
        b[7 - i] = UInt8((a >> UInt64(8 * i)) & 0xFF)
        b[15 - i] = UInt8((c >> UInt64(8 * i)) & 0xFF)
    return b
