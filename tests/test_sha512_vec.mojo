"""Test sha512 for Ed25519 Vec1 nonce computation."""
from crypto.hash import sha512


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
    # Vec1 from RFC 8032:
    # sk = 9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60
    # h = sha512(sk)
    # h[32:64] = 9b4f0afe280b746a778684e75442502057b7473a03f08f96f5a38e9287e01f8f
    # r_hash = sha512(h[32:64]) should be:
    # b6b19cd8e0426f5983fa112d89a143aa97dab8bc5deb8d5b6253c928b65272f4044098c2a990039cde5b6a4818df0bfb6e40dc5dee54248032962323e701352d

    # Test sha512 of h[32:64]
    var h_prefix = List[UInt8](capacity=32)
    h_prefix.append(0x9b); h_prefix.append(0x4f); h_prefix.append(0x0a); h_prefix.append(0xfe)
    h_prefix.append(0x28); h_prefix.append(0x0b); h_prefix.append(0x74); h_prefix.append(0x6a)
    h_prefix.append(0x77); h_prefix.append(0x86); h_prefix.append(0x84); h_prefix.append(0xe7)
    h_prefix.append(0x54); h_prefix.append(0x42); h_prefix.append(0x50); h_prefix.append(0x20)
    h_prefix.append(0x57); h_prefix.append(0xb7); h_prefix.append(0x47); h_prefix.append(0x3a)
    h_prefix.append(0x03); h_prefix.append(0xf0); h_prefix.append(0x8f); h_prefix.append(0x96)
    h_prefix.append(0xf5); h_prefix.append(0xa3); h_prefix.append(0x8e); h_prefix.append(0x92)
    h_prefix.append(0x87); h_prefix.append(0xe0); h_prefix.append(0x1f); h_prefix.append(0x8f)

    var r_hash = sha512(h_prefix)
    var expected = "b6b19cd8e0426f5983fa112d89a143aa97dab8bc5deb8d5b6253c928b65272f4044098c2a990039cde5b6a4818df0bfb6e40dc5dee54248032962323e701352d"
    var got = hex_bytes(r_hash)
    print("sha512(h[32:64]) == expected:", "PASS" if got == expected else "FAIL")
    if got != expected:
        print("  got:", got)
        print("  exp:", expected)

    # Also verify sha512(sk) first 64 bytes:
    # h = 357c83864f2833cb427a2ef1c00a013cfdff2768d980c0a3a520f006904de90f9b4f0afe280b746a778684e75442502057b7473a03f08f96f5a38e9287e01f8f
    var sk = List[UInt8](capacity=32)
    sk.append(0x9d); sk.append(0x61); sk.append(0xb1); sk.append(0x9d)
    sk.append(0xef); sk.append(0xfd); sk.append(0x5a); sk.append(0x60)
    sk.append(0xba); sk.append(0x84); sk.append(0x4a); sk.append(0xf4)
    sk.append(0x92); sk.append(0xec); sk.append(0x2c); sk.append(0xc4)
    sk.append(0x44); sk.append(0x49); sk.append(0xc5); sk.append(0x69)
    sk.append(0x7b); sk.append(0x32); sk.append(0x69); sk.append(0x19)
    sk.append(0x70); sk.append(0x3b); sk.append(0xac); sk.append(0x03)
    sk.append(0x1c); sk.append(0xae); sk.append(0x7f); sk.append(0x60)

    var h = sha512(sk)
    var h_expected = "357c83864f2833cb427a2ef1c00a013cfdff2768d980c0a3a520f006904de90f9b4f0afe280b746a778684e75442502057b7473a03f08f96f5a38e9287e01f8f"
    var h_got = hex_bytes(h)
    print("sha512(sk) == expected:", "PASS" if h_got == h_expected else "FAIL")
    if h_got != h_expected:
        print("  got:", h_got)
        print("  exp:", h_expected)

    # Verify h[32:64] == h_prefix
    var h_suffix_match = True
    for i in range(32):
        if h[32 + i] != h_prefix[i]:
            h_suffix_match = False
    print("h[32:64] matches h_prefix:", "PASS" if h_suffix_match else "FAIL")
