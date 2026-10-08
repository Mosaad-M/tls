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

from std.memory import bitcast
from std.sys import get_defined_bool
from std.sys.info import CompilationTarget
from std.sys.intrinsics import llvm_intrinsic
from crypto.aes import expand_key_words
from crypto.hmac import hmac_equal

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
def _encrypt8(k: _RoundKeys, mut b: InlineArray[V16, 8]):
    """Eight blocks with the rounds interleaved, so the AES units pipeline."""
    comptime if _HW_X86:
        var s = InlineArray[U64x2, 8](fill=U64x2(0))
        comptime for i in range(8):
            s[i] = bitcast[DType.uint64, 2](b[i] ^ k.rk[0])
        for r in range(1, k.nr):
            var rk = bitcast[DType.uint64, 2](k.rk[r])
            comptime for i in range(8):
                s[i] = llvm_intrinsic["llvm.x86.aesni.aesenc", U64x2, has_side_effect=False](s[i], rk)
        var last = bitcast[DType.uint64, 2](k.rk[k.nr])
        comptime for i in range(8):
            b[i] = bitcast[DType.uint8, 16](
                llvm_intrinsic["llvm.x86.aesni.aesenclast", U64x2, has_side_effect=False](s[i], last)
            )
    else:
        for r in range(k.nr - 1):
            var rk = k.rk[r]
            comptime for i in range(8):
                b[i] = llvm_intrinsic["llvm.aarch64.crypto.aesmc", V16, has_side_effect=False](
                    llvm_intrinsic["llvm.aarch64.crypto.aese", V16, has_side_effect=False](b[i], rk)
                )
        var pen = k.rk[k.nr - 1]
        var last = k.rk[k.nr]
        comptime for i in range(8):
            b[i] = llvm_intrinsic["llvm.aarch64.crypto.aese", V16, has_side_effect=False](b[i], pen) ^ last


# ── GF(2^128) in bit-reversed (ordinary polynomial) form ────────────────────

@always_inline
def _to_field(block: V16) -> U64x2:
    return bitcast[DType.uint64, 2](_bitrev_bytes(block))


@always_inline
def _from_field(x: U64x2) -> V16:
    return _bitrev_bytes(bitcast[DType.uint8, 16](x))


@always_inline
def _mul_wide(x: U64x2, h: U64x2) -> SIMD[DType.uint64, 4]:
    """Unreduced 256-bit product (Karatsuba: three carry-less multiplies)."""
    var lo = _clmul(x[0], h[0])
    var hi = _clmul(x[1], h[1])
    var mid = _clmul(x[0] ^ x[1], h[0] ^ h[1]) ^ lo ^ hi
    return SIMD[DType.uint64, 4](lo[0], lo[1] ^ mid[0], hi[0] ^ mid[1], hi[1])


@always_inline
def _reduce(w: SIMD[DType.uint64, 4]) -> U64x2:
    """Reduce modulo x^128 + x^7 + x^2 + x + 1 (x^128 = 0x87)."""
    var a = _clmul(w[3], 0x87)          # w3 * x^192 = w3 * x^64 * 0x87
    var w1 = w[1] ^ a[0]
    var w2 = w[2] ^ a[1]
    var b = _clmul(w2, 0x87)            # w2 * x^128 = w2 * 0x87
    return U64x2(w[0] ^ b[0], w1 ^ b[1])


@always_inline
def _gmul(x: U64x2, h: U64x2) -> U64x2:
    return _reduce(_mul_wide(x, h))


# ── GCM ─────────────────────────────────────────────────────────────────────

struct HwGcmKey(Copyable, Movable):
    """An AES key prepared for hardware GCM: round keys and H, H^2, H^3, H^4."""
    var k: _RoundKeys
    var h1: U64x2
    var h2: U64x2
    var h3: U64x2
    var h4: U64x2

    def __init__(out self, key: List[UInt8]) raises:
        self.k = _RoundKeys(key)
        self.h1 = _to_field(_encrypt_block(self.k, V16(0)))
        self.h2 = _gmul(self.h1, self.h1)
        self.h3 = _gmul(self.h2, self.h1)
        self.h4 = _gmul(self.h3, self.h1)

    def __init__(out self, *, copy: Self):
        self.k = _RoundKeys(copy=copy.k)
        self.h1 = copy.h1
        self.h2 = copy.h2
        self.h3 = copy.h3
        self.h4 = copy.h4

    def _ghash(self, mut y: U64x2, p: Int, n: Int):
        """Absorb n bytes at address p (the last block zero-padded)."""
        var src = Pointer[UInt8, MutAnyOrigin](unsafe_from_address=p)
        var off = 0
        while off + 64 <= n:
            var x0 = _to_field((src + off).load[width=16]()) ^ y
            var acc = _mul_wide(x0, self.h4)
            acc ^= _mul_wide(_to_field((src + off + 16).load[width=16]()), self.h3)
            acc ^= _mul_wide(_to_field((src + off + 32).load[width=16]()), self.h2)
            acc ^= _mul_wide(_to_field((src + off + 48).load[width=16]()), self.h1)
            y = _reduce(acc)
            off += 64
        while off + 16 <= n:
            y = _gmul(y ^ _to_field((src + off).load[width=16]()), self.h1)
            off += 16
        if off < n:
            var last = V16(0)
            for i in range(n - off):
                last[i] = src[off + i]
            y = _gmul(y ^ _to_field(last), self.h1)

    def _j0(self, iv: List[UInt8]) -> V16:
        var j0 = V16(0)
        if len(iv) == 12:
            for i in range(12):
                j0[i] = iv[i]
            j0[15] = 1
            return j0
        var y = U64x2(0)
        self._ghash(y, Int(iv.unsafe_ptr()), len(iv))
        y = _gmul(y ^ _to_field(_len_block(0, len(iv))), self.h1)
        return _from_field(y)

    def _ctr(self, j0: V16, src_addr: Int, dst_addr: Int, n: Int):
        """dst = src XOR keystream, counters inc32(J0), inc32^2(J0), ..."""
        var src = Pointer[UInt8, MutAnyOrigin](unsafe_from_address=src_addr)
        var dst = Pointer[UInt8, MutAnyOrigin](unsafe_from_address=dst_addr)
        var c0 = (UInt32(j0[12]) << 24) | (UInt32(j0[13]) << 16) | (UInt32(j0[14]) << 8) | UInt32(j0[15])
        var ctr = c0 + 1
        var off = 0
        var blocks = InlineArray[V16, 8](fill=V16(0))
        while off + 128 <= n:
            comptime for i in range(8):
                blocks[i] = _counter_block(j0, ctr + UInt32(i))
            _encrypt8(self.k, blocks)
            comptime for i in range(8):
                (dst + off + 16 * i).store(0, (src + off + 16 * i).load[width=16]() ^ blocks[i])
            ctr += 8
            off += 128
        while off + 16 <= n:
            var ks = _encrypt_block(self.k, _counter_block(j0, ctr))
            (dst + off).store(0, (src + off).load[width=16]() ^ ks)
            ctr += 1
            off += 16
        if off < n:
            var ks = _encrypt_block(self.k, _counter_block(j0, ctr))
            for i in range(n - off):
                dst[off + i] = src[off + i] ^ ks[i]

    def _tag(self, j0: V16, aad: List[UInt8], ct_addr: Int, ct_len: Int) -> List[UInt8]:
        var y = U64x2(0)
        self._ghash(y, Int(aad.unsafe_ptr()), len(aad))
        self._ghash(y, ct_addr, ct_len)
        y = _gmul(y ^ _to_field(_len_block(len(aad), ct_len)), self.h1)
        var t = _from_field(y) ^ _encrypt_block(self.k, j0)
        var out = List[UInt8](capacity=16)
        for i in range(16):
            out.append(t[i])
        return out^

    def seal(
        self, iv: List[UInt8], plaintext: List[UInt8], aad: List[UInt8]
    ) raises -> Tuple[List[UInt8], List[UInt8]]:
        var j0 = self._j0(iv)
        var n = len(plaintext)
        var ct = List[UInt8](unsafe_uninit_length=n)
        self._ctr(j0, Int(plaintext.unsafe_ptr()), Int(ct.unsafe_ptr()), n)
        var tag = self._tag(j0, aad, Int(ct.unsafe_ptr()), n)
        return (ct^, tag^)

    def open(
        self, iv: List[UInt8], ciphertext: List[UInt8], tag: List[UInt8], aad: List[UInt8]
    ) raises -> List[UInt8]:
        """Verify the tag (constant-time comparison) before decrypting."""
        var j0 = self._j0(iv)
        var n = len(ciphertext)
        var expect = self._tag(j0, aad, Int(ciphertext.unsafe_ptr()), n)
        if not hmac_equal(expect, tag):
            raise Error("authentication failed")
        var pt = List[UInt8](unsafe_uninit_length=n)
        self._ctr(j0, Int(ciphertext.unsafe_ptr()), Int(pt.unsafe_ptr()), n)
        return pt^


@always_inline
def _counter_block(j0: V16, ctr: UInt32) -> V16:
    var b = j0
    b[12] = UInt8((ctr >> 24) & 0xFF)
    b[13] = UInt8((ctr >> 16) & 0xFF)
    b[14] = UInt8((ctr >> 8) & 0xFF)
    b[15] = UInt8(ctr & 0xFF)
    return b


def _len_block(aad_len: Int, ct_len: Int) -> V16:
    """[len(A) in bits]_64 || [len(C) in bits]_64, big-endian."""
    var b = V16(0)
    var a = UInt64(aad_len) * 8
    var c = UInt64(ct_len) * 8
    for i in range(8):
        b[7 - i] = UInt8((a >> UInt64(8 * i)) & 0xFF)
        b[15 - i] = UInt8((c >> UInt64(8 * i)) & 0xFF)
    return b
