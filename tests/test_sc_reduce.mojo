"""Quick test for _scalar_reduce in isolation."""
from crypto.ed25519 import _scalar_reduce


def bytes_equal(a: List[UInt8], b: List[UInt8]) -> Bool:
    if len(a) != len(b):
        return False
    for i in range(len(a)):
        if a[i] != b[i]:
            return False
    return True


def hex_bytes(s: List[UInt8]) -> String:
    var result = String()
    for i in range(len(s)):
        var b = Int(s[i])
        var hi = b >> 4
        var lo = b & 0xF
        result += String(chr(hi + 48 if hi < 10 else hi + 87))
        result += String(chr(lo + 48 if lo < 10 else lo + 87))
    return result


def main() raises:
    # Test 1: sc_reduce(0) == 0
    var zero = List[UInt8](capacity=64)
    for _ in range(64):
        zero.append(0)
    var r0 = _scalar_reduce(zero)
    var z32 = List[UInt8](capacity=32)
    for _ in range(32):
        z32.append(0)
    print("sc_reduce(0)==0:", "PASS" if bytes_equal(r0, z32) else "FAIL  got=" + hex_bytes(r0))

    # Test 2: sc_reduce(L) == 0
    # L = 2^252 + 27742317777372353535851937790883648493
    # L in little-endian 32 bytes:
    # ed d3 f5 5c 1a 63 12 58 d6 9c f7 a2 de f9 de 14 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 10
    var L_bytes = List[UInt8](capacity=64)
    L_bytes.append(0xed); L_bytes.append(0xd3); L_bytes.append(0xf5); L_bytes.append(0x5c)
    L_bytes.append(0x1a); L_bytes.append(0x63); L_bytes.append(0x12); L_bytes.append(0x58)
    L_bytes.append(0xd6); L_bytes.append(0x9c); L_bytes.append(0xf7); L_bytes.append(0xa2)
    L_bytes.append(0xde); L_bytes.append(0xf9); L_bytes.append(0xde); L_bytes.append(0x14)
    for _ in range(15):
        L_bytes.append(0)
    L_bytes.append(0x10)
    for _ in range(32):
        L_bytes.append(0)
    var rL = _scalar_reduce(L_bytes)
    print("sc_reduce(L)==0:", "PASS" if bytes_equal(rL, z32) else "FAIL  got=" + hex_bytes(rL))

    # Test 3: sc_reduce(L+1) == 1
    var L1_bytes = List[UInt8](capacity=64)
    L1_bytes.append(0xee); L1_bytes.append(0xd3); L1_bytes.append(0xf5); L1_bytes.append(0x5c)
    L1_bytes.append(0x1a); L1_bytes.append(0x63); L1_bytes.append(0x12); L1_bytes.append(0x58)
    L1_bytes.append(0xd6); L1_bytes.append(0x9c); L1_bytes.append(0xf7); L1_bytes.append(0xa2)
    L1_bytes.append(0xde); L1_bytes.append(0xf9); L1_bytes.append(0xde); L1_bytes.append(0x14)
    for _ in range(15):
        L1_bytes.append(0)
    L1_bytes.append(0x10)
    for _ in range(32):
        L1_bytes.append(0)
    var rL1 = _scalar_reduce(L1_bytes)
    var one32 = List[UInt8](capacity=32)
    one32.append(1)
    for _ in range(31):
        one32.append(0)
    print("sc_reduce(L+1)==1:", "PASS" if bytes_equal(rL1, one32) else "FAIL  got=" + hex_bytes(rL1))

    # Test 4: Vec1 r_hash from RFC 8032
    # sk = 9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60
    # h = sha512(sk), r_hash = sha512(h[32:64])
    # r_hash (from Python): need to precompute this
    # expected r_scalar = (int.from_bytes(r_hash,'little') % L).to_bytes(32,'little')
    # For now, let's just print whether sc_reduce is functioning
    print("Basic sc_reduce tests done")
