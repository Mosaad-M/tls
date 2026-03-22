# ============================================================================
# crypto/sha1.mojo — SHA-1 (FIPS 180-4)
# ============================================================================
#
# SHA-1: 20-byte digest, 64-byte blocks, UInt32 words, 80 rounds.
#
# SHA-1 is cryptographically broken for collision resistance but is still
# required by RFC 6455 (WebSocket) for the handshake accept key derivation,
# where it is used as a non-security-critical integrity check (not for
# authentication). No secret-dependent branches.
# ============================================================================

from collections import InlineArray


@always_inline
def _rotl32(x: UInt32, n: UInt32) -> UInt32:
    return (x << n) | (x >> (32 - n))


@always_inline
def _sha1_ch(b: UInt32, c: UInt32, d: UInt32) -> UInt32:
    return (b & c) | (~b & d)


@always_inline
def _sha1_parity(b: UInt32, c: UInt32, d: UInt32) -> UInt32:
    return b ^ c ^ d


@always_inline
def _sha1_maj(b: UInt32, c: UInt32, d: UInt32) -> UInt32:
    return (b & c) | (b & d) | (c & d)


def _compress1(mut h: InlineArray[UInt32, 5], block: List[UInt8]):
    """Run the SHA-1 compression function on one 64-byte block."""
    # Round constants
    var K0: UInt32 = 0x5A827999  # rounds  0-19
    var K1: UInt32 = 0x6ED9EBA1  # rounds 20-39
    var K2: UInt32 = 0x8F1BBCDC  # rounds 40-59
    var K3: UInt32 = 0xCA62C1D6  # rounds 60-79

    # Build message schedule W[0..79]
    var w = InlineArray[UInt32, 80](fill=UInt32(0))
    for i in range(16):
        var j = i * 4
        w[i] = (
            (UInt32(block[j]) << 24)
            | (UInt32(block[j + 1]) << 16)
            | (UInt32(block[j + 2]) << 8)
            | UInt32(block[j + 3])
        )
    for i in range(16, 80):
        w[i] = _rotl32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1)

    var a = h[0]; var b = h[1]; var c = h[2]; var d = h[3]; var e = h[4]

    # Rounds 0-19: f = Ch(b,c,d), k = K0
    for i in range(20):
        var t = _rotl32(a, 5) + _sha1_ch(b, c, d) + e + K0 + w[i]
        e = d; d = c; c = _rotl32(b, 30); b = a; a = t

    # Rounds 20-39: f = Parity(b,c,d), k = K1
    for i in range(20, 40):
        var t = _rotl32(a, 5) + _sha1_parity(b, c, d) + e + K1 + w[i]
        e = d; d = c; c = _rotl32(b, 30); b = a; a = t

    # Rounds 40-59: f = Maj(b,c,d), k = K2
    for i in range(40, 60):
        var t = _rotl32(a, 5) + _sha1_maj(b, c, d) + e + K2 + w[i]
        e = d; d = c; c = _rotl32(b, 30); b = a; a = t

    # Rounds 60-79: f = Parity(b,c,d), k = K3
    for i in range(60, 80):
        var t = _rotl32(a, 5) + _sha1_parity(b, c, d) + e + K3 + w[i]
        e = d; d = c; c = _rotl32(b, 30); b = a; a = t

    h[0] = h[0] + a; h[1] = h[1] + b; h[2] = h[2] + c
    h[3] = h[3] + d; h[4] = h[4] + e


struct SHA1(Copyable, Movable):
    """Streaming SHA-1 hash (FIPS 180-4).

    Usage:
        var h = SHA1()
        h.update(chunk1)
        h.update(chunk2)
        var digest = h.finalize()   # 20 bytes; h is consumed after this
    """

    var _h: InlineArray[UInt32, 5]
    var _buf: List[UInt8]
    var _total: UInt64

    def __init__(out self):
        self._h = InlineArray[UInt32, 5](fill=UInt32(0))
        self._h[0] = 0x67452301
        self._h[1] = 0xEFCDAB89
        self._h[2] = 0x98BADCFE
        self._h[3] = 0x10325476
        self._h[4] = 0xC3D2E1F0
        self._buf = List[UInt8](capacity=64)
        self._total = 0

    def __copyinit__(out self, copy: Self):
        self._h = copy._h.copy()
        self._buf = copy._buf.copy()
        self._total = copy._total

    def __moveinit__(out self, deinit take: Self):
        self._h = take._h^
        self._buf = take._buf^
        self._total = take._total

    def update(mut self, data: List[UInt8]):
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
                _compress1(self._h, blk)

        while remaining >= 64:
            var block = List[UInt8](capacity=64)
            for i in range(64):
                block.append(data[pos + i])
            _compress1(self._h, block)
            pos += 64
            remaining -= 64

        for i in range(remaining):
            self._buf.append(data[pos + i])

    def finalize(mut self) -> List[UInt8]:
        """Pad, compress, and return 20-byte digest. State is consumed."""
        var bit_len = self._total * 8

        self._buf.append(0x80)
        while len(self._buf) % 64 != 56:
            self._buf.append(0x00)
        # 64-bit big-endian bit length
        for i in range(7, -1, -1):
            self._buf.append(UInt8((bit_len >> (UInt64(i) * 8)) & 0xFF))

        var n_blocks = len(self._buf) // 64
        for b in range(n_blocks):
            var block = List[UInt8](capacity=64)
            for i in range(64):
                block.append(self._buf[b * 64 + i])
            _compress1(self._h, block)

        var out = List[UInt8](capacity=20)
        for i in range(5):
            var word = self._h[i]
            out.append(UInt8(word >> 24))
            out.append(UInt8((word >> 16) & 0xFF))
            out.append(UInt8((word >> 8) & 0xFF))
            out.append(UInt8(word & 0xFF))
        return out^


def sha1(data: List[UInt8]) -> List[UInt8]:
    """One-shot SHA-1. Returns 20-byte digest."""
    var h = SHA1()
    h.update(data)
    return h.finalize()
