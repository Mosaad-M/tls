"""Test _scalar_reduce with actual r_hash from Vec1."""
from crypto.ed25519 import _scalar_reduce


fn hex_bytes(s: List[UInt8]) -> String:
    var result = String()
    for i in range(len(s)):
        var b = Int(s[i])
        var hi = b >> 4
        var lo = b & 0xF
        result += String(chr(hi + 48 if hi < 10 else hi + 87))
        result += String(chr(lo + 48 if lo < 10 else lo + 87))
    return result


fn main() raises:
    # r_hash = sha512(h[32:64]) for Vec1
    # = b6b19cd8e0426f5983fa112d89a143aa97dab8bc5deb8d5b6253c928b65272f
    #   4044098c2a990039cde5b6a4818df0bfb6e40dc5dee54248032962323e701352d
    var r = List[UInt8](capacity=64)
    r.append(0xb6);    r.append(0xb1);    r.append(0x9c);    r.append(0xd8);
    r.append(0xe0);    r.append(0x42);    r.append(0x6f);    r.append(0x59);
    r.append(0x83);    r.append(0xfa);    r.append(0x11);    r.append(0x2d);
    r.append(0x89);    r.append(0xa1);    r.append(0x43);    r.append(0xaa);
    r.append(0x97);    r.append(0xda);    r.append(0xb8);    r.append(0xbc);
    r.append(0x5d);    r.append(0xeb);    r.append(0x8d);    r.append(0x5b);
    r.append(0x62);    r.append(0x53);    r.append(0xc9);    r.append(0x28);
    r.append(0xb6);    r.append(0x52);    r.append(0x72);    r.append(0xf4);
    r.append(0x04);    r.append(0x40);    r.append(0x98);    r.append(0xc2);
    r.append(0xa9);    r.append(0x90);    r.append(0x03);    r.append(0x9c);
    r.append(0xde);    r.append(0x5b);    r.append(0x6a);    r.append(0x48);
    r.append(0x18);    r.append(0xdf);    r.append(0x0b);    r.append(0xfb);
    r.append(0x6e);    r.append(0x40);    r.append(0xdc);    r.append(0x5d);
    r.append(0xee);    r.append(0x54);    r.append(0x24);    r.append(0x80);
    r.append(0x32);    r.append(0x96);    r.append(0x23);    r.append(0x23);
    r.append(0xe7);    r.append(0x01);    r.append(0x35);    r.append(0x2d);

    var result = _scalar_reduce(r)
    var expected = "f38907308c893deaf244787db4af53682249107418afc2edc58f75ac58a07404"
    var got = hex_bytes(result)
    print("sc_reduce(r_hash):")
    print("  got:", got)
    print("  exp:", expected)
    print("  PASS" if got == expected else "  FAIL")
