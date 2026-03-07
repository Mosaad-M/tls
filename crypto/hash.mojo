# ============================================================================
# crypto/hash.mojo — SHA-256 and SHA-384 (FIPS 180-4)
# ============================================================================
#
# SHA-256: 32-byte digest, 64-byte blocks, UInt32 words, 64 rounds
# SHA-384: 48-byte digest, 128-byte blocks, UInt64 words, 80 rounds
#
# No side-channel concerns: hash functions have no secret-dependent branches.
# ============================================================================

from collections import InlineArray


# ============================================================================
# SHA-256
# ============================================================================


@always_inline
fn _rotr32(x: UInt32, n: UInt32) -> UInt32:
    return (x >> n) | (x << (32 - n))


@always_inline
fn _ch32(e: UInt32, f: UInt32, g: UInt32) -> UInt32:
    return (e & f) ^ (~e & g)


@always_inline
fn _maj32(a: UInt32, b: UInt32, c: UInt32) -> UInt32:
    return (a & b) ^ (a & c) ^ (b & c)


@always_inline
fn _Sigma0_32(x: UInt32) -> UInt32:
    return _rotr32(x, 2) ^ _rotr32(x, 13) ^ _rotr32(x, 22)


@always_inline
fn _Sigma1_32(x: UInt32) -> UInt32:
    return _rotr32(x, 6) ^ _rotr32(x, 11) ^ _rotr32(x, 25)


@always_inline
fn _sigma0_32(x: UInt32) -> UInt32:
    return _rotr32(x, 7) ^ _rotr32(x, 18) ^ (x >> 3)


@always_inline
fn _sigma1_32(x: UInt32) -> UInt32:
    return _rotr32(x, 17) ^ _rotr32(x, 19) ^ (x >> 10)


fn _compress256(mut h: InlineArray[UInt32, 8], block: List[UInt8]):
    """Run the SHA-256 compression function on one 64-byte block."""
    # Round constants: first 32 bits of fractional cube roots of first 64 primes
    var k = InlineArray[UInt32, 64](fill=UInt32(0))
    k[0]  = 0x428A2F98; k[1]  = 0x71374491; k[2]  = 0xB5C0FBCF; k[3]  = 0xE9B5DBA5
    k[4]  = 0x3956C25B; k[5]  = 0x59F111F1; k[6]  = 0x923F82A4; k[7]  = 0xAB1C5ED5
    k[8]  = 0xD807AA98; k[9]  = 0x12835B01; k[10] = 0x243185BE; k[11] = 0x550C7DC3
    k[12] = 0x72BE5D74; k[13] = 0x80DEB1FE; k[14] = 0x9BDC06A7; k[15] = 0xC19BF174
    k[16] = 0xE49B69C1; k[17] = 0xEFBE4786; k[18] = 0x0FC19DC6; k[19] = 0x240CA1CC
    k[20] = 0x2DE92C6F; k[21] = 0x4A7484AA; k[22] = 0x5CB0A9DC; k[23] = 0x76F988DA
    k[24] = 0x983E5152; k[25] = 0xA831C66D; k[26] = 0xB00327C8; k[27] = 0xBF597FC7
    k[28] = 0xC6E00BF3; k[29] = 0xD5A79147; k[30] = 0x06CA6351; k[31] = 0x14292967
    k[32] = 0x27B70A85; k[33] = 0x2E1B2138; k[34] = 0x4D2C6DFC; k[35] = 0x53380D13
    k[36] = 0x650A7354; k[37] = 0x766A0ABB; k[38] = 0x81C2C92E; k[39] = 0x92722C85
    k[40] = 0xA2BFE8A1; k[41] = 0xA81A664B; k[42] = 0xC24B8B70; k[43] = 0xC76C51A3
    k[44] = 0xD192E819; k[45] = 0xD6990624; k[46] = 0xF40E3585; k[47] = 0x106AA070
    k[48] = 0x19A4C116; k[49] = 0x1E376C08; k[50] = 0x2748774C; k[51] = 0x34B0BCB5
    k[52] = 0x391C0CB3; k[53] = 0x4ED8AA4A; k[54] = 0x5B9CCA4F; k[55] = 0x682E6FF3
    k[56] = 0x748F82EE; k[57] = 0x78A5636F; k[58] = 0x84C87814; k[59] = 0x8CC70208
    k[60] = 0x90BEFFFA; k[61] = 0xA4506CEB; k[62] = 0xBEF9A3F7; k[63] = 0xC67178F2

    # Build message schedule
    var w = InlineArray[UInt32, 64](fill=UInt32(0))
    for i in range(16):
        var j = i * 4
        w[i] = (
            (UInt32(block[j]) << 24)
            | (UInt32(block[j + 1]) << 16)
            | (UInt32(block[j + 2]) << 8)
            | UInt32(block[j + 3])
        )
    for i in range(16, 64):
        w[i] = _sigma1_32(w[i - 2]) + w[i - 7] + _sigma0_32(w[i - 15]) + w[i - 16]

    var a = h[0]; var b = h[1]; var c = h[2]; var d = h[3]
    var e = h[4]; var f = h[5]; var g = h[6]; var hh = h[7]

    for i in range(64):
        var t1 = hh + _Sigma1_32(e) + _ch32(e, f, g) + k[i] + w[i]
        var t2 = _Sigma0_32(a) + _maj32(a, b, c)
        hh = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2

    h[0] = h[0] + a; h[1] = h[1] + b; h[2] = h[2] + c; h[3] = h[3] + d
    h[4] = h[4] + e; h[5] = h[5] + f; h[6] = h[6] + g; h[7] = h[7] + hh


struct SHA256(Copyable, Movable):
    """Streaming SHA-256 hash (FIPS 180-4).

    Usage:
        var h = SHA256()
        h.update(chunk1)
        h.update(chunk2)
        var digest = h.finalize()   # 32 bytes; h is consumed after this
    """

    var _h: InlineArray[UInt32, 8]
    var _buf: List[UInt8]
    var _total: UInt64

    fn __init__(out self):
        self._h = InlineArray[UInt32, 8](fill=UInt32(0))
        self._h[0] = 0x6A09E667; self._h[1] = 0xBB67AE85
        self._h[2] = 0x3C6EF372; self._h[3] = 0xA54FF53A
        self._h[4] = 0x510E527F; self._h[5] = 0x9B05688C
        self._h[6] = 0x1F83D9AB; self._h[7] = 0x5BE0CD19
        self._buf = List[UInt8](capacity=64)
        self._total = 0

    fn __copyinit__(out self, copy: Self):
        self._h = copy._h.copy()
        self._buf = copy._buf.copy()
        self._total = copy._total

    fn __moveinit__(out self, deinit take: Self):
        self._h = take._h^
        self._buf = take._buf^
        self._total = take._total

    fn update(mut self, data: List[UInt8]):
        """Feed bytes into the hash."""
        self._total += UInt64(len(data))
        var pos = 0
        var remaining = len(data)

        if len(self._buf) > 0:
            var need = 64 - len(self._buf)
            var take_n = need if remaining >= need else remaining
            for i in range(take_n):
                self._buf.append(data[pos + i])
            pos += take_n
            remaining -= take_n
            if len(self._buf) == 64:
                var blk = self._buf.copy()
                self._buf.clear()
                _compress256(self._h, blk)

        while remaining >= 64:
            var block = List[UInt8](capacity=64)
            for i in range(64):
                block.append(data[pos + i])
            _compress256(self._h, block)
            pos += 64
            remaining -= 64

        for i in range(remaining):
            self._buf.append(data[pos + i])

    fn finalize(mut self) -> List[UInt8]:
        """Pad, compress, and return 32-byte digest. State is consumed."""
        var bit_len = self._total * 8

        self._buf.append(0x80)
        while len(self._buf) % 64 != 56:
            self._buf.append(0x00)
        for i in range(7, -1, -1):
            self._buf.append(UInt8((bit_len >> (UInt64(i) * 8)) & 0xFF))

        var n_blocks = len(self._buf) // 64
        for b in range(n_blocks):
            var block = List[UInt8](capacity=64)
            for i in range(64):
                block.append(self._buf[b * 64 + i])
            _compress256(self._h, block)

        var out = List[UInt8](capacity=32)
        for i in range(8):
            var word = self._h[i]
            out.append(UInt8(word >> 24))
            out.append(UInt8((word >> 16) & 0xFF))
            out.append(UInt8((word >> 8) & 0xFF))
            out.append(UInt8(word & 0xFF))
        return out^


fn sha256(data: List[UInt8]) -> List[UInt8]:
    """One-shot SHA-256. Returns 32-byte digest."""
    var h = SHA256()
    h.update(data)
    return h.finalize()


# ============================================================================
# SHA-384
# ============================================================================


@always_inline
fn _rotr64(x: UInt64, n: UInt64) -> UInt64:
    return (x >> n) | (x << (64 - n))


@always_inline
fn _ch64(e: UInt64, f: UInt64, g: UInt64) -> UInt64:
    return (e & f) ^ (~e & g)


@always_inline
fn _maj64(a: UInt64, b: UInt64, c: UInt64) -> UInt64:
    return (a & b) ^ (a & c) ^ (b & c)


@always_inline
fn _Sigma0_64(x: UInt64) -> UInt64:
    return _rotr64(x, 28) ^ _rotr64(x, 34) ^ _rotr64(x, 39)


@always_inline
fn _Sigma1_64(x: UInt64) -> UInt64:
    return _rotr64(x, 14) ^ _rotr64(x, 18) ^ _rotr64(x, 41)


@always_inline
fn _sigma0_64(x: UInt64) -> UInt64:
    return _rotr64(x, 1) ^ _rotr64(x, 8) ^ (x >> 7)


@always_inline
fn _sigma1_64(x: UInt64) -> UInt64:
    return _rotr64(x, 19) ^ _rotr64(x, 61) ^ (x >> 6)


fn _compress384(mut h: InlineArray[UInt64, 8], block: List[UInt8]):
    """Run the SHA-384/512 compression function on one 128-byte block."""
    # Round constants: first 64 bits of fractional cube roots of first 80 primes
    var k = InlineArray[UInt64, 80](fill=UInt64(0))
    k[0]  = 0x428A2F98D728AE22; k[1]  = 0x7137449123EF65CD
    k[2]  = 0xB5C0FBCFEC4D3B2F; k[3]  = 0xE9B5DBA58189DBBC
    k[4]  = 0x3956C25BF348B538; k[5]  = 0x59F111F1B605D019
    k[6]  = 0x923F82A4AF194F9B; k[7]  = 0xAB1C5ED5DA6D8118
    k[8]  = 0xD807AA98A3030242; k[9]  = 0x12835B0145706FBE
    k[10] = 0x243185BE4EE4B28C; k[11] = 0x550C7DC3D5FFB4E2
    k[12] = 0x72BE5D74F27B896F; k[13] = 0x80DEB1FE3B1696B1
    k[14] = 0x9BDC06A725C71235; k[15] = 0xC19BF174CF692694
    k[16] = 0xE49B69C19EF14AD2; k[17] = 0xEFBE4786384F25E3
    k[18] = 0x0FC19DC68B8CD5B5; k[19] = 0x240CA1CC77AC9C65
    k[20] = 0x2DE92C6F592B0275; k[21] = 0x4A7484AA6EA6E483
    k[22] = 0x5CB0A9DCBD41FBD4; k[23] = 0x76F988DA831153B5
    k[24] = 0x983E5152EE66DFAB; k[25] = 0xA831C66D2DB43210
    k[26] = 0xB00327C898FB213F; k[27] = 0xBF597FC7BEEF0EE4
    k[28] = 0xC6E00BF33DA88FC2; k[29] = 0xD5A79147930AA725
    k[30] = 0x06CA6351E003826F; k[31] = 0x142929670A0E6E70
    k[32] = 0x27B70A8546D22FFC; k[33] = 0x2E1B21385C26C926
    k[34] = 0x4D2C6DFC5AC42AED; k[35] = 0x53380D139D95B3DF
    k[36] = 0x650A73548BAF63DE; k[37] = 0x766A0ABB3C77B2A8
    k[38] = 0x81C2C92E47EDAEE6; k[39] = 0x92722C851482353B
    k[40] = 0xA2BFE8A14CF10364; k[41] = 0xA81A664BBC423001
    k[42] = 0xC24B8B70D0F89791; k[43] = 0xC76C51A30654BE30
    k[44] = 0xD192E819D6EF5218; k[45] = 0xD69906245565A910
    k[46] = 0xF40E35855771202A; k[47] = 0x106AA07032BBD1B8
    k[48] = 0x19A4C116B8D2D0C8; k[49] = 0x1E376C085141AB53
    k[50] = 0x2748774CDF8EEB99; k[51] = 0x34B0BCB5E19B48A8
    k[52] = 0x391C0CB3C5C95A63; k[53] = 0x4ED8AA4AE3418ACB
    k[54] = 0x5B9CCA4F7763E373; k[55] = 0x682E6FF3D6B2B8A3
    k[56] = 0x748F82EE5DEFB2FC; k[57] = 0x78A5636F43172F60
    k[58] = 0x84C87814A1F0AB72; k[59] = 0x8CC702081A6439EC
    k[60] = 0x90BEFFFA23631E28; k[61] = 0xA4506CEBDE82BDE9
    k[62] = 0xBEF9A3F7B2C67915; k[63] = 0xC67178F2E372532B
    k[64] = 0xCA273ECEEA26619C; k[65] = 0xD186B8C721C0C207
    k[66] = 0xEADA7DD6CDE0EB1E; k[67] = 0xF57D4F7FEE6ED178
    k[68] = 0x06F067AA72176FBA; k[69] = 0x0A637DC5A2C898A6
    k[70] = 0x113F9804BEF90DAE; k[71] = 0x1B710B35131C471B
    k[72] = 0x28DB77F523047D84; k[73] = 0x32CAAB7B40C72493
    k[74] = 0x3C9EBE0A15C9BEBC; k[75] = 0x431D67C49C100D4C
    k[76] = 0x4CC5D4BECB3E42B6; k[77] = 0x597F299CFC657E2A
    k[78] = 0x5FCB6FAB3AD6FAEC; k[79] = 0x6C44198C4A475817

    # Build message schedule
    var w = InlineArray[UInt64, 80](fill=UInt64(0))
    for i in range(16):
        var j = i * 8
        w[i] = (
            (UInt64(block[j]) << 56)
            | (UInt64(block[j + 1]) << 48)
            | (UInt64(block[j + 2]) << 40)
            | (UInt64(block[j + 3]) << 32)
            | (UInt64(block[j + 4]) << 24)
            | (UInt64(block[j + 5]) << 16)
            | (UInt64(block[j + 6]) << 8)
            | UInt64(block[j + 7])
        )
    for i in range(16, 80):
        w[i] = _sigma1_64(w[i - 2]) + w[i - 7] + _sigma0_64(w[i - 15]) + w[i - 16]

    var a = h[0]; var b = h[1]; var c = h[2]; var d = h[3]
    var e = h[4]; var f = h[5]; var g = h[6]; var hh = h[7]

    for i in range(80):
        var t1 = hh + _Sigma1_64(e) + _ch64(e, f, g) + k[i] + w[i]
        var t2 = _Sigma0_64(a) + _maj64(a, b, c)
        hh = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2

    h[0] = h[0] + a; h[1] = h[1] + b; h[2] = h[2] + c; h[3] = h[3] + d
    h[4] = h[4] + e; h[5] = h[5] + f; h[6] = h[6] + g; h[7] = h[7] + hh


struct SHA384(Copyable, Movable):
    """Streaming SHA-384 hash (FIPS 180-4).

    Usage:
        var h = SHA384()
        h.update(chunk1)
        var digest = h.finalize()   # 48 bytes; h is consumed after this
    """

    var _h: InlineArray[UInt64, 8]
    var _buf: List[UInt8]
    var _total: UInt64

    fn __init__(out self):
        self._h = InlineArray[UInt64, 8](fill=UInt64(0))
        self._h[0] = 0xCBBB9D5DC1059ED8; self._h[1] = 0x629A292A367CD507
        self._h[2] = 0x9159015A3070DD17; self._h[3] = 0x152FECD8F70E5939
        self._h[4] = 0x67332667FFC00B31; self._h[5] = 0x8EB44A8768581511
        self._h[6] = 0xDB0C2E0D64F98FA7; self._h[7] = 0x47B5481DBEFA4FA4
        self._buf = List[UInt8](capacity=128)
        self._total = 0

    fn __copyinit__(out self, copy: Self):
        self._h = copy._h.copy()
        self._buf = copy._buf.copy()
        self._total = copy._total

    fn __moveinit__(out self, deinit take: Self):
        self._h = take._h^
        self._buf = take._buf^
        self._total = take._total

    fn update(mut self, data: List[UInt8]):
        """Feed bytes into the hash."""
        self._total += UInt64(len(data))
        var pos = 0
        var remaining = len(data)

        if len(self._buf) > 0:
            var need = 128 - len(self._buf)
            var take_n = need if remaining >= need else remaining
            for i in range(take_n):
                self._buf.append(data[pos + i])
            pos += take_n
            remaining -= take_n
            if len(self._buf) == 128:
                var blk = self._buf.copy()
                self._buf.clear()
                _compress384(self._h, blk)

        while remaining >= 128:
            var block = List[UInt8](capacity=128)
            for i in range(128):
                block.append(data[pos + i])
            _compress384(self._h, block)
            pos += 128
            remaining -= 128

        for i in range(remaining):
            self._buf.append(data[pos + i])

    fn finalize(mut self) -> List[UInt8]:
        """Pad, compress, and return 48-byte digest. State is consumed."""
        var bit_len = self._total * 8

        self._buf.append(0x80)
        while len(self._buf) % 128 != 112:
            self._buf.append(0x00)

        # 128-bit big-endian length (high 64 bits always 0 for <2^64 byte messages)
        for _ in range(8):
            self._buf.append(0x00)
        for i in range(7, -1, -1):
            self._buf.append(UInt8((bit_len >> (UInt64(i) * 8)) & 0xFF))

        var n_blocks = len(self._buf) // 128
        for b in range(n_blocks):
            var block = List[UInt8](capacity=128)
            for i in range(128):
                block.append(self._buf[b * 128 + i])
            _compress384(self._h, block)

        # SHA-384 outputs first 6 of 8 words (48 bytes)
        var out = List[UInt8](capacity=48)
        for i in range(6):
            var word = self._h[i]
            out.append(UInt8(word >> 56))
            out.append(UInt8((word >> 48) & 0xFF))
            out.append(UInt8((word >> 40) & 0xFF))
            out.append(UInt8((word >> 32) & 0xFF))
            out.append(UInt8((word >> 24) & 0xFF))
            out.append(UInt8((word >> 16) & 0xFF))
            out.append(UInt8((word >> 8) & 0xFF))
            out.append(UInt8(word & 0xFF))
        return out^


fn sha384(data: List[UInt8]) -> List[UInt8]:
    """One-shot SHA-384. Returns 48-byte digest."""
    var h = SHA384()
    h.update(data)
    return h.finalize()
