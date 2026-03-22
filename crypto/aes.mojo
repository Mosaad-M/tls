# ============================================================================
# crypto/aes.mojo — AES-128/256 block cipher (FIPS 197)
# ============================================================================
#
# Implements:
#   AES struct — key schedule + encrypt_block (ECB, used by GCM internally)
#   Key sizes: 128-bit (Nk=4, Nr=10) and 256-bit (Nk=8, Nr=14)
#
# Security note: Uses table-lookup S-box. This is theoretically vulnerable
# to cache-timing attacks if the attacker can observe cache behaviour.
# For production hardening, replace with AES-NI instructions or a bitsliced
# implementation. Documented limitation — out of scope for initial version.
# ============================================================================

from std.collections import InlineArray


# ============================================================================
# S-box and inverse S-box (FIPS 197 Figure 7)
# ============================================================================

def _sbox() -> InlineArray[UInt8, 256]:
    var s = InlineArray[UInt8, 256](fill=UInt8(0))
    s[0]=0x63;s[1]=0x7c;s[2]=0x77;s[3]=0x7b;s[4]=0xf2;s[5]=0x6b;s[6]=0x6f;s[7]=0xc5
    s[8]=0x30;s[9]=0x01;s[10]=0x67;s[11]=0x2b;s[12]=0xfe;s[13]=0xd7;s[14]=0xab;s[15]=0x76
    s[16]=0xca;s[17]=0x82;s[18]=0xc9;s[19]=0x7d;s[20]=0xfa;s[21]=0x59;s[22]=0x47;s[23]=0xf0
    s[24]=0xad;s[25]=0xd4;s[26]=0xa2;s[27]=0xaf;s[28]=0x9c;s[29]=0xa4;s[30]=0x72;s[31]=0xc0
    s[32]=0xb7;s[33]=0xfd;s[34]=0x93;s[35]=0x26;s[36]=0x36;s[37]=0x3f;s[38]=0xf7;s[39]=0xcc
    s[40]=0x34;s[41]=0xa5;s[42]=0xe5;s[43]=0xf1;s[44]=0x71;s[45]=0xd8;s[46]=0x31;s[47]=0x15
    s[48]=0x04;s[49]=0xc7;s[50]=0x23;s[51]=0xc3;s[52]=0x18;s[53]=0x96;s[54]=0x05;s[55]=0x9a
    s[56]=0x07;s[57]=0x12;s[58]=0x80;s[59]=0xe2;s[60]=0xeb;s[61]=0x27;s[62]=0xb2;s[63]=0x75
    s[64]=0x09;s[65]=0x83;s[66]=0x2c;s[67]=0x1a;s[68]=0x1b;s[69]=0x6e;s[70]=0x5a;s[71]=0xa0
    s[72]=0x52;s[73]=0x3b;s[74]=0xd6;s[75]=0xb3;s[76]=0x29;s[77]=0xe3;s[78]=0x2f;s[79]=0x84
    s[80]=0x53;s[81]=0xd1;s[82]=0x00;s[83]=0xed;s[84]=0x20;s[85]=0xfc;s[86]=0xb1;s[87]=0x5b
    s[88]=0x6a;s[89]=0xcb;s[90]=0xbe;s[91]=0x39;s[92]=0x4a;s[93]=0x4c;s[94]=0x58;s[95]=0xcf
    s[96]=0xd0;s[97]=0xef;s[98]=0xaa;s[99]=0xfb;s[100]=0x43;s[101]=0x4d;s[102]=0x33;s[103]=0x85
    s[104]=0x45;s[105]=0xf9;s[106]=0x02;s[107]=0x7f;s[108]=0x50;s[109]=0x3c;s[110]=0x9f;s[111]=0xa8
    s[112]=0x51;s[113]=0xa3;s[114]=0x40;s[115]=0x8f;s[116]=0x92;s[117]=0x9d;s[118]=0x38;s[119]=0xf5
    s[120]=0xbc;s[121]=0xb6;s[122]=0xda;s[123]=0x21;s[124]=0x10;s[125]=0xff;s[126]=0xf3;s[127]=0xd2
    s[128]=0xcd;s[129]=0x0c;s[130]=0x13;s[131]=0xec;s[132]=0x5f;s[133]=0x97;s[134]=0x44;s[135]=0x17
    s[136]=0xc4;s[137]=0xa7;s[138]=0x7e;s[139]=0x3d;s[140]=0x64;s[141]=0x5d;s[142]=0x19;s[143]=0x73
    s[144]=0x60;s[145]=0x81;s[146]=0x4f;s[147]=0xdc;s[148]=0x22;s[149]=0x2a;s[150]=0x90;s[151]=0x88
    s[152]=0x46;s[153]=0xee;s[154]=0xb8;s[155]=0x14;s[156]=0xde;s[157]=0x5e;s[158]=0x0b;s[159]=0xdb
    s[160]=0xe0;s[161]=0x32;s[162]=0x3a;s[163]=0x0a;s[164]=0x49;s[165]=0x06;s[166]=0x24;s[167]=0x5c
    s[168]=0xc2;s[169]=0xd3;s[170]=0xac;s[171]=0x62;s[172]=0x91;s[173]=0x95;s[174]=0xe4;s[175]=0x79
    s[176]=0xe7;s[177]=0xc8;s[178]=0x37;s[179]=0x6d;s[180]=0x8d;s[181]=0xd5;s[182]=0x4e;s[183]=0xa9
    s[184]=0x6c;s[185]=0x56;s[186]=0xf4;s[187]=0xea;s[188]=0x65;s[189]=0x7a;s[190]=0xae;s[191]=0x08
    s[192]=0xba;s[193]=0x78;s[194]=0x25;s[195]=0x2e;s[196]=0x1c;s[197]=0xa6;s[198]=0xb4;s[199]=0xc6
    s[200]=0xe8;s[201]=0xdd;s[202]=0x74;s[203]=0x1f;s[204]=0x4b;s[205]=0xbd;s[206]=0x8b;s[207]=0x8a
    s[208]=0x70;s[209]=0x3e;s[210]=0xb5;s[211]=0x66;s[212]=0x48;s[213]=0x03;s[214]=0xf6;s[215]=0x0e
    s[216]=0x61;s[217]=0x35;s[218]=0x57;s[219]=0xb9;s[220]=0x86;s[221]=0xc1;s[222]=0x1d;s[223]=0x9e
    s[224]=0xe1;s[225]=0xf8;s[226]=0x98;s[227]=0x11;s[228]=0x69;s[229]=0xd9;s[230]=0x8e;s[231]=0x94
    s[232]=0x9b;s[233]=0x1e;s[234]=0x87;s[235]=0xe9;s[236]=0xce;s[237]=0x55;s[238]=0x28;s[239]=0xdf
    s[240]=0x8c;s[241]=0xa1;s[242]=0x89;s[243]=0x0d;s[244]=0xbf;s[245]=0xe6;s[246]=0x42;s[247]=0x68
    s[248]=0x41;s[249]=0x99;s[250]=0x2d;s[251]=0x0f;s[252]=0xb0;s[253]=0x54;s[254]=0xbb;s[255]=0x16
    return s^


# ============================================================================
# GF(2^8) multiplication helpers (for MixColumns and key schedule)
# ============================================================================

def _xtime(a: UInt8) -> UInt8:
    """Multiply by x (i.e., 2) in GF(2^8) with reduction poly x^8+x^4+x^3+x+1."""
    return ((a << 1) ^ (UInt8(0x1B) & (a >> 7) * UInt8(0xFF)))


def _gmul(a: UInt8, b: UInt8) -> UInt8:
    """Multiply two elements of GF(2^8) using Russian peasant algorithm."""
    var p: UInt8 = 0
    var aa = a
    var bb = b
    for _ in range(8):
        if (bb & 1) != 0:
            p ^= aa
        var hi: UInt8 = aa & 0x80
        aa <<= 1
        if hi != 0:
            aa ^= 0x1B
        bb >>= 1
    return p


# ============================================================================
# AES key schedule round constants
# ============================================================================

def _rcon(i: Int) -> UInt8:
    """Return Rcon[i] — power of x in GF(2^8), i starting at 1."""
    var rc: UInt8 = 1
    for _ in range(i - 1):
        rc = _xtime(rc)
    return rc


# ============================================================================
# AES struct — supports 128-bit (Nr=10) and 256-bit (Nr=14) keys
# ============================================================================

struct AES(Copyable, Movable):
    """AES block cipher. Accepts 16-byte (AES-128) or 32-byte (AES-256) keys.

    Usage:
        var aes = AES(key)              # key: List[UInt8], 16 or 32 bytes
        var ct  = aes.encrypt_block(pt) # pt: 16-byte List[UInt8]
    """
    var _nr: Int                        # number of rounds (10 or 14)
    var _rk: List[UInt32]              # expanded round key words
    var _sb: InlineArray[UInt8, 256]   # S-box cached at init (avoids rebuilding per block)

    def __init__(out self, key: List[UInt8]) raises:
        var nk = len(key) // 4  # words in key (4 or 8)
        if len(key) != 16 and len(key) != 32:
            raise Error("AES key must be 16 or 32 bytes")
        self._nr = 6 + nk  # 10 or 14
        var total_words = 4 * (self._nr + 1)
        self._rk = List[UInt32](capacity=total_words)

        # Load key into first Nk words
        for i in range(nk):
            var j = i * 4
            self._rk.append(
                (UInt32(key[j]) << 24) |
                (UInt32(key[j+1]) << 16) |
                (UInt32(key[j+2]) << 8) |
                UInt32(key[j+3])
            )

        # Expand key schedule — build S-box once and reuse
        var sbox = _sbox()
        for i in range(nk, total_words):
            var temp = self._rk[i - 1]
            if i % nk == 0:
                # RotWord then SubWord then XOR Rcon
                var rotated = (temp << 8) | (temp >> 24)
                var b0 = UInt8((rotated >> 24) & 0xFF)
                var b1 = UInt8((rotated >> 16) & 0xFF)
                var b2 = UInt8((rotated >> 8)  & 0xFF)
                var b3 = UInt8(rotated & 0xFF)
                var subbed = (UInt32(sbox[Int(b0)]) << 24) | (UInt32(sbox[Int(b1)]) << 16) | (UInt32(sbox[Int(b2)]) << 8) | UInt32(sbox[Int(b3)])
                temp = subbed ^ (UInt32(_rcon(i // nk)) << 24)
            elif nk > 6 and i % nk == 4:
                # AES-256 extra SubWord at position 4
                var b0 = UInt8((temp >> 24) & 0xFF)
                var b1 = UInt8((temp >> 16) & 0xFF)
                var b2 = UInt8((temp >> 8)  & 0xFF)
                var b3 = UInt8(temp & 0xFF)
                temp = (UInt32(sbox[Int(b0)]) << 24) | (UInt32(sbox[Int(b1)]) << 16) | (UInt32(sbox[Int(b2)]) << 8) | UInt32(sbox[Int(b3)])
            self._rk.append(self._rk[i - nk] ^ temp)
        self._sb = sbox^

    def __copyinit__(out self, copy: Self):
        self._nr = copy._nr
        self._rk = copy._rk.copy()
        self._sb = copy._sb.copy()

    def __moveinit__(out self, deinit take: Self):
        self._nr = take._nr
        self._rk = take._rk^
        self._sb = take._sb^

    def encrypt_block(self, block: List[UInt8]) raises -> List[UInt8]:
        """Encrypt a single 16-byte block (AES-ECB)."""
        if len(block) != 16:
            raise Error("AES block must be 16 bytes")

        # Load block into 4×4 state (column-major: state[col][row])
        # state[c][r] = block[r + 4*c]
        var s = InlineArray[UInt8, 16](fill=UInt8(0))
        for i in range(16):
            s[i] = block[i]

        # Initial round key addition
        _add_round_key(s, self._rk, 0)

        # Main rounds
        for rnd in range(1, self._nr):
            _sub_bytes(s, self._sb)
            _shift_rows(s)
            _mix_columns(s)
            _add_round_key(s, self._rk, rnd)

        # Final round (no MixColumns)
        _sub_bytes(s, self._sb)
        _shift_rows(s)
        _add_round_key(s, self._rk, self._nr)

        # Extract result
        var out = List[UInt8](capacity=16)
        for i in range(16):
            out.append(s[i])
        return out^


# ============================================================================
# AES round functions — operate on flat 16-byte state (column-major order)
# state layout: [col0_row0, col0_row1, col0_row2, col0_row3, col1_row0, ...]
# i.e. state[4*col + row]
# ============================================================================

def _add_round_key(mut s: InlineArray[UInt8, 16], rk: List[UInt32], rnd: Int):
    """XOR state with round key words."""
    for col in range(4):
        var w = rk[rnd * 4 + col]
        s[col * 4 + 0] ^= UInt8((w >> 24) & 0xFF)
        s[col * 4 + 1] ^= UInt8((w >> 16) & 0xFF)
        s[col * 4 + 2] ^= UInt8((w >> 8)  & 0xFF)
        s[col * 4 + 3] ^= UInt8(w & 0xFF)


def _sub_bytes(mut s: InlineArray[UInt8, 16], sbox: InlineArray[UInt8, 256]):
    """Apply S-box substitution to each byte."""
    for i in range(16):
        s[i] = sbox[Int(s[i])]


def _shift_rows(mut s: InlineArray[UInt8, 16]):
    """Cyclically shift rows left: row 0 by 0, row 1 by 1, row 2 by 2, row 3 by 3.

    State is column-major: s[4*col + row].
    Row r contains: s[r], s[4+r], s[8+r], s[12+r].
    """
    # Row 1: shift left 1
    var t = s[0 * 4 + 1]
    s[0 * 4 + 1] = s[1 * 4 + 1]
    s[1 * 4 + 1] = s[2 * 4 + 1]
    s[2 * 4 + 1] = s[3 * 4 + 1]
    s[3 * 4 + 1] = t

    # Row 2: shift left 2
    var t0 = s[0 * 4 + 2]
    var t1 = s[1 * 4 + 2]
    s[0 * 4 + 2] = s[2 * 4 + 2]
    s[1 * 4 + 2] = s[3 * 4 + 2]
    s[2 * 4 + 2] = t0
    s[3 * 4 + 2] = t1

    # Row 3: shift left 3 (= shift right 1)
    var t2 = s[3 * 4 + 3]
    s[3 * 4 + 3] = s[2 * 4 + 3]
    s[2 * 4 + 3] = s[1 * 4 + 3]
    s[1 * 4 + 3] = s[0 * 4 + 3]
    s[0 * 4 + 3] = t2


def _mix_columns(mut s: InlineArray[UInt8, 16]):
    """Mix each column using GF(2^8) arithmetic (FIPS 197 §5.1.3).

    Uses _xtime (single shift+XOR) instead of _gmul for speed:
      gmul(0x02, a) == _xtime(a)
      gmul(0x03, a) == _xtime(a) ^ a
    """
    for col in range(4):
        var i = col * 4
        var a0 = s[i + 0]
        var a1 = s[i + 1]
        var a2 = s[i + 2]
        var a3 = s[i + 3]
        s[i + 0] = _xtime(a0) ^ (_xtime(a1) ^ a1) ^ a2 ^ a3
        s[i + 1] = a0 ^ _xtime(a1) ^ (_xtime(a2) ^ a2) ^ a3
        s[i + 2] = a0 ^ a1 ^ _xtime(a2) ^ (_xtime(a3) ^ a3)
        s[i + 3] = (_xtime(a0) ^ a0) ^ a1 ^ a2 ^ _xtime(a3)
