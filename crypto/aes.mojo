# ============================================================================
# crypto/aes.mojo — AES-128/256 block cipher (FIPS 197), constant time
# ============================================================================
#
# Implements:
#   AES struct — key schedule + encrypt_block / encrypt_blocks4 (used by GCM)
#   Key sizes: 128-bit (Nr=10) and 256-bit (Nr=14)
#
# Constant time: a 64-bit bitsliced implementation, ported from BearSSL's
# aes_ct64 (Thomas Pornin, MIT licence). The S-box is the Boyar-Peralta
# boolean circuit, so there are no table lookups and no branches on key or
# data. Four blocks are processed in parallel; CTR mode uses that directly.
#
# Bitsliced layout: q[0..7] hold four blocks. Bit i of every byte of every
# block goes to q[i]; ortho() converts between this and the plain layout.
# ============================================================================

from std.collections import InlineArray


comptime _Q = InlineArray[UInt64, 8]


# ============================================================================
# Bitsliced S-box (Boyar-Peralta circuit, https://eprint.iacr.org/2009/191)
# ============================================================================

def _sbox(mut q: _Q):
    """Apply the AES S-box to all 32 bytes held in q (x0 is the high bit)."""
    var x0 = q[7]
    var x1 = q[6]
    var x2 = q[5]
    var x3 = q[4]
    var x4 = q[3]
    var x5 = q[2]
    var x6 = q[1]
    var x7 = q[0]

    # Top linear transformation
    var y14 = x3 ^ x5
    var y13 = x0 ^ x6
    var y9 = x0 ^ x3
    var y8 = x0 ^ x5
    var t0 = x1 ^ x2
    var y1 = t0 ^ x7
    var y4 = y1 ^ x3
    var y12 = y13 ^ y14
    var y2 = y1 ^ x0
    var y5 = y1 ^ x6
    var y3 = y5 ^ y8
    var t1 = x4 ^ y12
    var y15 = t1 ^ x5
    var y20 = t1 ^ x1
    var y6 = y15 ^ x7
    var y10 = y15 ^ t0
    var y11 = y20 ^ y9
    var y7 = x7 ^ y11
    var y17 = y10 ^ y11
    var y19 = y10 ^ y8
    var y16 = t0 ^ y11
    var y21 = y13 ^ y16
    var y18 = x0 ^ y16

    # Non-linear section
    var t2 = y12 & y15
    var t3 = y3 & y6
    var t4 = t3 ^ t2
    var t5 = y4 & x7
    var t6 = t5 ^ t2
    var t7 = y13 & y16
    var t8 = y5 & y1
    var t9 = t8 ^ t7
    var t10 = y2 & y7
    var t11 = t10 ^ t7
    var t12 = y9 & y11
    var t13 = y14 & y17
    var t14 = t13 ^ t12
    var t15 = y8 & y10
    var t16 = t15 ^ t12
    var t17 = t4 ^ t14
    var t18 = t6 ^ t16
    var t19 = t9 ^ t14
    var t20 = t11 ^ t16
    var t21 = t17 ^ y20
    var t22 = t18 ^ y19
    var t23 = t19 ^ y21
    var t24 = t20 ^ y18

    var t25 = t21 ^ t22
    var t26 = t21 & t23
    var t27 = t24 ^ t26
    var t28 = t25 & t27
    var t29 = t28 ^ t22
    var t30 = t23 ^ t24
    var t31 = t22 ^ t26
    var t32 = t31 & t30
    var t33 = t32 ^ t24
    var t34 = t23 ^ t33
    var t35 = t27 ^ t33
    var t36 = t24 & t35
    var t37 = t36 ^ t34
    var t38 = t27 ^ t36
    var t39 = t29 & t38
    var t40 = t25 ^ t39

    var t41 = t40 ^ t37
    var t42 = t29 ^ t33
    var t43 = t29 ^ t40
    var t44 = t33 ^ t37
    var t45 = t42 ^ t41
    var z0 = t44 & y15
    var z1 = t37 & y6
    var z2 = t33 & x7
    var z3 = t43 & y16
    var z4 = t40 & y1
    var z5 = t29 & y7
    var z6 = t42 & y11
    var z7 = t45 & y17
    var z8 = t41 & y10
    var z9 = t44 & y12
    var z10 = t37 & y3
    var z11 = t33 & y4
    var z12 = t43 & y13
    var z13 = t40 & y5
    var z14 = t29 & y2
    var z15 = t42 & y9
    var z16 = t45 & y14
    var z17 = t41 & y8

    # Bottom linear transformation
    var t46 = z15 ^ z16
    var t47 = z10 ^ z11
    var t48 = z5 ^ z13
    var t49 = z9 ^ z10
    var t50 = z2 ^ z12
    var t51 = z2 ^ z5
    var t52 = z7 ^ z8
    var t53 = z0 ^ z3
    var t54 = z6 ^ z7
    var t55 = z16 ^ z17
    var t56 = z12 ^ t48
    var t57 = t50 ^ t53
    var t58 = z4 ^ t46
    var t59 = z3 ^ t54
    var t60 = t46 ^ t57
    var t61 = z14 ^ t57
    var t62 = t52 ^ t58
    var t63 = t49 ^ t58
    var t64 = z4 ^ t59
    var t65 = t61 ^ t62
    var t66 = z1 ^ t63
    var s0 = t59 ^ t63
    var s6 = t56 ^ ~t62
    var s7 = t48 ^ ~t60
    var t67 = t64 ^ t65
    var s3 = t53 ^ t66
    var s4 = t51 ^ t66
    var s5 = t47 ^ t65
    var s1 = t64 ^ ~s3
    var s2 = t55 ^ ~t67

    q[7] = s0
    q[6] = s1
    q[5] = s2
    q[4] = s3
    q[3] = s4
    q[2] = s5
    q[1] = s6
    q[0] = s7


# ============================================================================
# Layout conversion
# ============================================================================

@always_inline
def _swapn(mut q: _Q, i: Int, j: Int, cl: UInt64, ch: UInt64, s: UInt64):
    var a = q[i]
    var b = q[j]
    q[i] = (a & cl) | ((b & cl) << s)
    q[j] = ((a & ch) >> s) | (b & ch)


def _ortho(mut q: _Q):
    """Transpose between the plain and bitsliced representations (self-inverse)."""
    comptime C2 = UInt64(0x5555555555555555)
    comptime H2 = UInt64(0xAAAAAAAAAAAAAAAA)
    comptime C4 = UInt64(0x3333333333333333)
    comptime H4 = UInt64(0xCCCCCCCCCCCCCCCC)
    comptime C8 = UInt64(0x0F0F0F0F0F0F0F0F)
    comptime H8 = UInt64(0xF0F0F0F0F0F0F0F0)
    _swapn(q, 0, 1, C2, H2, 1)
    _swapn(q, 2, 3, C2, H2, 1)
    _swapn(q, 4, 5, C2, H2, 1)
    _swapn(q, 6, 7, C2, H2, 1)
    _swapn(q, 0, 2, C4, H4, 2)
    _swapn(q, 1, 3, C4, H4, 2)
    _swapn(q, 4, 6, C4, H4, 2)
    _swapn(q, 5, 7, C4, H4, 2)
    _swapn(q, 0, 4, C8, H8, 4)
    _swapn(q, 1, 5, C8, H8, 4)
    _swapn(q, 2, 6, C8, H8, 4)
    _swapn(q, 3, 7, C8, H8, 4)


def _interleave_in(w0: UInt32, w1: UInt32, w2: UInt32, w3: UInt32) -> Tuple[UInt64, UInt64]:
    """Spread one block (four little-endian words) over two 64-bit words."""
    comptime M16 = UInt64(0x0000FFFF0000FFFF)
    comptime M8 = UInt64(0x00FF00FF00FF00FF)
    var x0 = UInt64(w0)
    var x1 = UInt64(w1)
    var x2 = UInt64(w2)
    var x3 = UInt64(w3)
    x0 = (x0 | (x0 << 16)) & M16
    x1 = (x1 | (x1 << 16)) & M16
    x2 = (x2 | (x2 << 16)) & M16
    x3 = (x3 | (x3 << 16)) & M16
    x0 = (x0 | (x0 << 8)) & M8
    x1 = (x1 | (x1 << 8)) & M8
    x2 = (x2 | (x2 << 8)) & M8
    x3 = (x3 | (x3 << 8)) & M8
    return (x0 | (x2 << 8), x1 | (x3 << 8))


def _interleave_out(q0: UInt64, q1: UInt64) -> InlineArray[UInt32, 4]:
    """Inverse of _interleave_in: two 64-bit words back to four block words."""
    comptime M16 = UInt64(0x0000FFFF0000FFFF)
    comptime M8 = UInt64(0x00FF00FF00FF00FF)
    var x0 = q0 & M8
    var x1 = q1 & M8
    var x2 = (q0 >> 8) & M8
    var x3 = (q1 >> 8) & M8
    x0 = (x0 | (x0 >> 8)) & M16
    x1 = (x1 | (x1 >> 8)) & M16
    x2 = (x2 | (x2 >> 8)) & M16
    x3 = (x3 | (x3 >> 8)) & M16
    var w = InlineArray[UInt32, 4](fill=0)
    w[0] = UInt32(x0 & 0xFFFFFFFF) | UInt32(x0 >> 16)
    w[1] = UInt32(x1 & 0xFFFFFFFF) | UInt32(x1 >> 16)
    w[2] = UInt32(x2 & 0xFFFFFFFF) | UInt32(x2 >> 16)
    w[3] = UInt32(x3 & 0xFFFFFFFF) | UInt32(x3 >> 16)
    return w^


# ============================================================================
# Round functions (bitsliced)
# ============================================================================

def _shift_rows(mut q: _Q):
    for i in range(8):
        var x = q[i]
        q[i] = (
            (x & UInt64(0x000000000000FFFF))
            | ((x & UInt64(0x00000000FFF00000)) >> 4)
            | ((x & UInt64(0x00000000000F0000)) << 12)
            | ((x & UInt64(0x0000FF0000000000)) >> 8)
            | ((x & UInt64(0x000000FF00000000)) << 8)
            | ((x & UInt64(0xF000000000000000)) >> 12)
            | ((x & UInt64(0x0FFF000000000000)) << 4)
        )


@always_inline
def _rotr32(x: UInt64) -> UInt64:
    return (x << 32) | (x >> 32)


def _mix_columns(mut q: _Q):
    var q0 = q[0]
    var q1 = q[1]
    var q2 = q[2]
    var q3 = q[3]
    var q4 = q[4]
    var q5 = q[5]
    var q6 = q[6]
    var q7 = q[7]
    var r0 = (q0 >> 16) | (q0 << 48)
    var r1 = (q1 >> 16) | (q1 << 48)
    var r2 = (q2 >> 16) | (q2 << 48)
    var r3 = (q3 >> 16) | (q3 << 48)
    var r4 = (q4 >> 16) | (q4 << 48)
    var r5 = (q5 >> 16) | (q5 << 48)
    var r6 = (q6 >> 16) | (q6 << 48)
    var r7 = (q7 >> 16) | (q7 << 48)
    q[0] = q7 ^ r7 ^ r0 ^ _rotr32(q0 ^ r0)
    q[1] = q0 ^ r0 ^ q7 ^ r7 ^ r1 ^ _rotr32(q1 ^ r1)
    q[2] = q1 ^ r1 ^ r2 ^ _rotr32(q2 ^ r2)
    q[3] = q2 ^ r2 ^ q7 ^ r7 ^ r3 ^ _rotr32(q3 ^ r3)
    q[4] = q3 ^ r3 ^ q7 ^ r7 ^ r4 ^ _rotr32(q4 ^ r4)
    q[5] = q4 ^ r4 ^ r5 ^ _rotr32(q5 ^ r5)
    q[6] = q5 ^ r5 ^ r6 ^ _rotr32(q6 ^ r6)
    q[7] = q6 ^ r6 ^ r7 ^ _rotr32(q7 ^ r7)


@always_inline
def _add_round_key(mut q: _Q, sk: List[UInt64], rnd: Int):
    var base = rnd * 8
    for i in range(8):
        q[i] ^= sk[base + i]


# ============================================================================
# Key schedule
# ============================================================================

def _sub_word(x: UInt32) -> UInt32:
    """SubWord through the bitsliced S-box (no table lookups)."""
    var q = _Q(fill=0)
    q[0] = UInt64(x)
    _ortho(q)
    _sbox(q)
    _ortho(q)
    return UInt32(q[0] & 0xFFFFFFFF)


@always_inline
def _load32le(b: List[UInt8], off: Int) -> UInt32:
    return (
        UInt32(b[off]) | (UInt32(b[off + 1]) << 8)
        | (UInt32(b[off + 2]) << 16) | (UInt32(b[off + 3]) << 24)
    )


def expand_key_words(key: List[UInt8]) raises -> List[UInt32]:
    """FIPS 197 key expansion on little-endian words (BearSSL convention):
    4 * (Nr + 1) words; round key r is words 4r..4r+3, whose little-endian
    bytes are the round key's bytes in order. SubWord goes through the
    bitsliced S-box, so the secret key never indexes a table."""
    if len(key) != 16 and len(key) != 32:
        raise Error("AES key must be 16 or 32 bytes")
    var nk = len(key) // 4
    var nkf = (6 + nk + 1) * 4
    var w = List[UInt32](capacity=nkf)
    for i in range(nk):
        w.append(_load32le(key, i * 4))
    var rcon: List[UInt32] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]
    var tmp = w[nk - 1]
    var j = 0
    var k = 0
    for i in range(nk, nkf):
        if j == 0:
            tmp = (tmp << 24) | (tmp >> 8)
            tmp = _sub_word(tmp) ^ rcon[k]
        elif nk > 6 and j == 4:
            tmp = _sub_word(tmp)
        tmp ^= w[i - nk]
        w.append(tmp)
        j += 1
        if j == nk:
            j = 0
            k += 1
    return w^


# ============================================================================
# AES struct — supports 128-bit (Nr=10) and 256-bit (Nr=14)
# ============================================================================

struct AES(Copyable, Movable):
    """AES block cipher. Accepts 16-byte (AES-128) or 32-byte (AES-256) keys.

    Usage:
        var aes = AES(key)                   # key: List[UInt8], 16 or 32 bytes
        var ct  = aes.encrypt_block(pt)      # pt: 16-byte List[UInt8]
        var ct4 = aes.encrypt_blocks4(pt64)  # four blocks at once (64 bytes)
    """
    var _nr: Int             # number of rounds (10 or 14)
    var _sk: List[UInt64]    # bitsliced round keys, 8 words per round

    def __init__(out self, key: List[UInt8]) raises:
        var w = expand_key_words(key)
        self._nr = len(w) // 4 - 1
        var nkf = len(w)

        # Bitslice each round key, replicated for the four parallel blocks
        self._sk = List[UInt64](capacity=nkf * 2)
        for i in range(0, nkf, 4):
            var q = _Q(fill=0)
            var p = _interleave_in(w[i], w[i + 1], w[i + 2], w[i + 3])
            q[0] = p[0]
            q[1] = p[0]
            q[2] = p[0]
            q[3] = p[0]
            q[4] = p[1]
            q[5] = p[1]
            q[6] = p[1]
            q[7] = p[1]
            _ortho(q)
            for b in range(8):
                self._sk.append(q[b])

    def __copyinit__(out self, copy: Self):
        self._nr = copy._nr
        self._sk = copy._sk.copy()

    def __moveinit__(out self, deinit take: Self):
        self._nr = take._nr
        self._sk = take._sk^

    def _encrypt_q(self, mut q: _Q):
        _add_round_key(q, self._sk, 0)
        for rnd in range(1, self._nr):
            _sbox(q)
            _shift_rows(q)
            _mix_columns(q)
            _add_round_key(q, self._sk, rnd)
        _sbox(q)
        _shift_rows(q)
        _add_round_key(q, self._sk, self._nr)

    def encrypt_blocks4(self, blocks: List[UInt8]) raises -> List[UInt8]:
        """Encrypt four consecutive 16-byte blocks (64 bytes) in one pass."""
        if len(blocks) != 64:
            raise Error("AES encrypt_blocks4 needs 64 bytes")
        var q = _Q(fill=0)
        for i in range(4):
            var off = i * 16
            var p = _interleave_in(
                _load32le(blocks, off), _load32le(blocks, off + 4),
                _load32le(blocks, off + 8), _load32le(blocks, off + 12),
            )
            q[i] = p[0]
            q[i + 4] = p[1]
        _ortho(q)
        self._encrypt_q(q)
        _ortho(q)
        var out = List[UInt8](capacity=64)
        for i in range(4):
            var w = _interleave_out(q[i], q[i + 4])
            for k in range(4):
                var v = w[k]
                out.append(UInt8(v & 0xFF))
                out.append(UInt8((v >> 8) & 0xFF))
                out.append(UInt8((v >> 16) & 0xFF))
                out.append(UInt8((v >> 24) & 0xFF))
        return out^

    def encrypt_block(self, block: List[UInt8]) raises -> List[UInt8]:
        """Encrypt a single 16-byte block (AES-ECB)."""
        if len(block) != 16:
            raise Error("AES block must be 16 bytes")
        var four = List[UInt8](capacity=64)
        for i in range(16):
            four.append(block[i])
        for _ in range(48):
            four.append(0)
        var enc = self.encrypt_blocks4(four)
        var out = List[UInt8](capacity=16)
        for i in range(16):
            out.append(enc[i])
        return out^
