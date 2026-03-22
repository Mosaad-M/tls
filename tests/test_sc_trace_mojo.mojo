"""Trace _scalar_reduce intermediate values to find bug."""

def load3(b: List[UInt8], off: Int) -> Int64:
    return Int64(UInt64(b[off]) | (UInt64(b[off+1]) << 8) | (UInt64(b[off+2]) << 16))

def load4(b: List[UInt8], off: Int) -> Int64:
    return Int64(UInt64(b[off]) | (UInt64(b[off+1]) << 8) | (UInt64(b[off+2]) << 16) | (UInt64(b[off+3]) << 24))


def main() raises:
    # r_hash for Vec1
    var inp = List[UInt8](capacity=64)
    inp.append(0xb6); inp.append(0xb1); inp.append(0x9c); inp.append(0xd8)
    inp.append(0xe0); inp.append(0x42); inp.append(0x6f); inp.append(0x59)
    inp.append(0x83); inp.append(0xfa); inp.append(0x11); inp.append(0x2d)
    inp.append(0x89); inp.append(0xa1); inp.append(0x43); inp.append(0xaa)
    inp.append(0x97); inp.append(0xda); inp.append(0xb8); inp.append(0xbc)
    inp.append(0x5d); inp.append(0xeb); inp.append(0x8d); inp.append(0x5b)
    inp.append(0x62); inp.append(0x53); inp.append(0xc9); inp.append(0x28)
    inp.append(0xb6); inp.append(0x52); inp.append(0x72); inp.append(0xf4)
    inp.append(0x04); inp.append(0x40); inp.append(0x98); inp.append(0xc2)
    inp.append(0xa9); inp.append(0x90); inp.append(0x03); inp.append(0x9c)
    inp.append(0xde); inp.append(0x5b); inp.append(0x6a); inp.append(0x48)
    inp.append(0x18); inp.append(0xdf); inp.append(0x0b); inp.append(0xfb)
    inp.append(0x6e); inp.append(0x40); inp.append(0xdc); inp.append(0x5d)
    inp.append(0xee); inp.append(0x54); inp.append(0x24); inp.append(0x80)
    inp.append(0x32); inp.append(0x96); inp.append(0x23); inp.append(0x23)
    inp.append(0xe7); inp.append(0x01); inp.append(0x35); inp.append(0x2d)

    var sb = inp.copy()

    # Extract limbs
    var s0:  Int64 = Int64( UInt64(sb[0])  | (UInt64(sb[1]) << 8) | (UInt64(sb[2]) << 16)) & Int64(0x1FFFFF)
    var s1:  Int64 = (Int64(UInt64(sb[2]) >> 5) | Int64(UInt64(sb[3]) << 3) | Int64(UInt64(sb[4]) << 11) | Int64(UInt64(sb[5]) << 19)) & Int64(0x1FFFFF)
    var s2:  Int64 = (Int64(UInt64(sb[5]) >> 2) | Int64(UInt64(sb[6]) << 6) | Int64(UInt64(sb[7]) << 14)) & Int64(0x1FFFFF)
    var s3:  Int64 = (Int64(UInt64(sb[7]) >> 7) | Int64(UInt64(sb[8]) << 1) | Int64(UInt64(sb[9]) << 9) | Int64(UInt64(sb[10]) << 17)) & Int64(0x1FFFFF)
    var s4:  Int64 = (Int64(UInt64(sb[10]) >> 4) | Int64(UInt64(sb[11]) << 4) | Int64(UInt64(sb[12]) << 12) | Int64(UInt64(sb[13]) << 20)) & Int64(0x1FFFFF)
    var s5:  Int64 = (Int64(UInt64(sb[13]) >> 1) | Int64(UInt64(sb[14]) << 7) | Int64(UInt64(sb[15]) << 15)) & Int64(0x1FFFFF)
    var s6:  Int64 = (Int64(UInt64(sb[15]) >> 6) | Int64(UInt64(sb[16]) << 2) | Int64(UInt64(sb[17]) << 10) | Int64(UInt64(sb[18]) << 18)) & Int64(0x1FFFFF)
    var s7:  Int64 = (Int64(UInt64(sb[18]) >> 3) | Int64(UInt64(sb[19]) << 5) | Int64(UInt64(sb[20]) << 13)) & Int64(0x1FFFFF)
    var s8:  Int64 = Int64(UInt64(sb[21]) | (UInt64(sb[22]) << 8) | (UInt64(sb[23]) << 16)) & Int64(0x1FFFFF)
    var s9:  Int64 = (Int64(UInt64(sb[23]) >> 5) | Int64(UInt64(sb[24]) << 3) | Int64(UInt64(sb[25]) << 11) | Int64(UInt64(sb[26]) << 19)) & Int64(0x1FFFFF)
    var s10: Int64 = (Int64(UInt64(sb[26]) >> 2) | Int64(UInt64(sb[27]) << 6) | Int64(UInt64(sb[28]) << 14)) & Int64(0x1FFFFF)
    var s11: Int64 = (Int64(UInt64(sb[28]) >> 7) | Int64(UInt64(sb[29]) << 1) | Int64(UInt64(sb[30]) << 9) | Int64(UInt64(sb[31]) << 17)) & Int64(0x1FFFFF)
    var s12: Int64 = (Int64(UInt64(sb[31]) >> 4) | Int64(UInt64(sb[32]) << 4) | Int64(UInt64(sb[33]) << 12) | Int64(UInt64(sb[34]) << 20)) & Int64(0x1FFFFF)
    var s13: Int64 = (Int64(UInt64(sb[34]) >> 1) | Int64(UInt64(sb[35]) << 7) | Int64(UInt64(sb[36]) << 15)) & Int64(0x1FFFFF)
    var s14: Int64 = (Int64(UInt64(sb[36]) >> 6) | Int64(UInt64(sb[37]) << 2) | Int64(UInt64(sb[38]) << 10) | Int64(UInt64(sb[39]) << 18)) & Int64(0x1FFFFF)
    var s15: Int64 = (Int64(UInt64(sb[39]) >> 3) | Int64(UInt64(sb[40]) << 5) | Int64(UInt64(sb[41]) << 13)) & Int64(0x1FFFFF)
    var s16: Int64 = Int64(UInt64(sb[42]) | (UInt64(sb[43]) << 8) | (UInt64(sb[44]) << 16)) & Int64(0x1FFFFF)
    var s17: Int64 = (Int64(UInt64(sb[44]) >> 5) | Int64(UInt64(sb[45]) << 3) | Int64(UInt64(sb[46]) << 11) | Int64(UInt64(sb[47]) << 19)) & Int64(0x1FFFFF)
    var s18: Int64 = (Int64(UInt64(sb[47]) >> 2) | Int64(UInt64(sb[48]) << 6) | Int64(UInt64(sb[49]) << 14)) & Int64(0x1FFFFF)
    var s19: Int64 = (Int64(UInt64(sb[49]) >> 7) | Int64(UInt64(sb[50]) << 1) | Int64(UInt64(sb[51]) << 9) | Int64(UInt64(sb[52]) << 17)) & Int64(0x1FFFFF)
    var s20: Int64 = (Int64(UInt64(sb[52]) >> 4) | Int64(UInt64(sb[53]) << 4) | Int64(UInt64(sb[54]) << 12) | Int64(UInt64(sb[55]) << 20)) & Int64(0x1FFFFF)
    var s21: Int64 = (Int64(UInt64(sb[55]) >> 1) | Int64(UInt64(sb[56]) << 7) | Int64(UInt64(sb[57]) << 15)) & Int64(0x1FFFFF)
    var s22: Int64 = (Int64(UInt64(sb[57]) >> 6) | Int64(UInt64(sb[58]) << 2) | Int64(UInt64(sb[59]) << 10) | Int64(UInt64(sb[60]) << 18)) & Int64(0x1FFFFF)
    var s23: Int64 = Int64(UInt64(sb[60]) >> 3) | Int64(UInt64(sb[61]) << 5) | Int64(UInt64(sb[62]) << 13) | Int64(UInt64(sb[63]) << 21)

    print("Initial s12..s17:", s12, s13, s14, s15, s16, s17)
    print("s18 s23:", s18, s23)

    # Phase 1: fold s23..s18
    s11 += s23 * Int64(666643); s12 += s23 * Int64(470296); s13 += s23 * Int64(654183)
    s14 -= s23 * Int64(997805); s15 += s23 * Int64(136657); s16 -= s23 * Int64(683901)
    s10 += s22 * Int64(666643); s11 += s22 * Int64(470296); s12 += s22 * Int64(654183)
    s13 -= s22 * Int64(997805); s14 += s22 * Int64(136657); s15 -= s22 * Int64(683901)
    s9  += s21 * Int64(666643); s10 += s21 * Int64(470296); s11 += s21 * Int64(654183)
    s12 -= s21 * Int64(997805); s13 += s21 * Int64(136657); s14 -= s21 * Int64(683901)
    s8  += s20 * Int64(666643); s9  += s20 * Int64(470296); s10 += s20 * Int64(654183)
    s11 -= s20 * Int64(997805); s12 += s20 * Int64(136657); s13 -= s20 * Int64(683901)
    s7  += s19 * Int64(666643); s8  += s19 * Int64(470296); s9  += s19 * Int64(654183)
    s10 -= s19 * Int64(997805); s11 += s19 * Int64(136657); s12 -= s19 * Int64(683901)
    s6  += s18 * Int64(666643); s7  += s18 * Int64(470296); s8  += s18 * Int64(654183)
    s9  -= s18 * Int64(997805); s10 += s18 * Int64(136657); s11 -= s18 * Int64(683901)
    s18 = 0

    print("After Phase1 fold - s12:", s12, " s13:", s13, " s17:", s17)
    print("  Expected: s12=43817632109223 s13=60151266199460 s17=1597176")

    # Phase 1 carry: s6..s11→s12 (original, just 6)
    var carry6  = (s6  + Int64(1 << 20)) >> 21; s7  += carry6;  s6  -= carry6  << 21
    var carry7  = (s7  + Int64(1 << 20)) >> 21; s8  += carry7;  s7  -= carry7  << 21
    var carry8  = (s8  + Int64(1 << 20)) >> 21; s9  += carry8;  s8  -= carry8  << 21
    var carry9  = (s9  + Int64(1 << 20)) >> 21; s10 += carry9;  s9  -= carry9  << 21
    var carry10 = (s10 + Int64(1 << 20)) >> 21; s11 += carry10; s10 -= carry10 << 21
    var carry11 = (s11 + Int64(1 << 20)) >> 21; s12 += carry11; s11 -= carry11 << 21

    print("After Phase1 carry s6..s11 - s12:", s12)
    print("  Expected: s12=43817662600299")

    # Extended carry s12..s17→s18
    var carry12 = (s12 + Int64(1 << 20)) >> 21; s13 += carry12; s12 -= carry12 << 21
    var carry13 = (s13 + Int64(1 << 20)) >> 21; s14 += carry13; s13 -= carry13 << 21
    var carry14 = (s14 + Int64(1 << 20)) >> 21; s15 += carry14; s14 -= carry14 << 21
    var carry15 = (s15 + Int64(1 << 20)) >> 21; s16 += carry15; s15 -= carry15 << 21
    var carry16 = (s16 + Int64(1 << 20)) >> 21; s17 += carry16; s16 -= carry16 << 21
    var carry17 = (s17 + Int64(1 << 20)) >> 21; s18 += carry17; s17 -= carry17 << 21

    print("After extended carry s12..s17 - s12:", s12, " s17:", s17, " s18:", s18)
    print("  Expected: s12..s17=[600981, 419738, 943077, 984895, 66581, 40154] s18=-14")

    # Phase 2: Fold s18..s12
    s6  += s18 * Int64(666643); s7  += s18 * Int64(470296); s8  += s18 * Int64(654183)
    s9  -= s18 * Int64(997805); s10 += s18 * Int64(136657); s11 -= s18 * Int64(683901)
    s18 = 0

    s5  += s17 * Int64(666643); s6  += s17 * Int64(470296); s7  += s17 * Int64(654183)
    s8  -= s17 * Int64(997805); s9  += s17 * Int64(136657); s10 -= s17 * Int64(683901)
    s17 = 0

    s4  += s16 * Int64(666643); s5  += s16 * Int64(470296); s6  += s16 * Int64(654183)
    s7  -= s16 * Int64(997805); s8  += s16 * Int64(136657); s9  -= s16 * Int64(683901)
    s16 = 0

    s3  += s15 * Int64(666643); s4  += s15 * Int64(470296); s5  += s15 * Int64(654183)
    s6  -= s15 * Int64(997805); s7  += s15 * Int64(136657); s8  -= s15 * Int64(683901)
    s15 = 0

    s2  += s14 * Int64(666643); s3  += s14 * Int64(470296); s4  += s14 * Int64(654183)
    s5  -= s14 * Int64(997805); s6  += s14 * Int64(136657); s7  -= s14 * Int64(683901)
    s14 = 0

    s1  += s13 * Int64(666643); s2  += s13 * Int64(470296); s3  += s13 * Int64(654183)
    s4  -= s13 * Int64(997805); s5  += s13 * Int64(136657); s6  -= s13 * Int64(683901)
    s13 = 0

    s0  += s12 * Int64(666643); s1  += s12 * Int64(470296); s2  += s12 * Int64(654183)
    s3  -= s12 * Int64(997805); s4  += s12 * Int64(136657); s5  -= s12 * Int64(683901)
    s12 = 0

    print("After Phase2 fold - s0..s5:", s0, s1, s2, s3, s4, s5)
    print("  Expected: [-75353, 1027359, -876091, 880793, -855915, -137268] (approx)")
