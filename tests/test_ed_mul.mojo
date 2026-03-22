"""Test _ed_base_mul with known nonce scalar from RFC 8032 Vec1."""
from crypto.ed25519 import _ed_base_mul, _ed_compress


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
    # Vec1 nonce scalar = f38907308c893deaf244787db4af53682249107418afc2edc58f75ac58a07404
    # Expected R (from RFC) = e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155
    var nonce = List[UInt8](capacity=32)
    nonce.append(0xf3); nonce.append(0x89); nonce.append(0x07); nonce.append(0x30)
    nonce.append(0x8c); nonce.append(0x89); nonce.append(0x3d); nonce.append(0xea)
    nonce.append(0xf2); nonce.append(0x44); nonce.append(0x78); nonce.append(0x7d)
    nonce.append(0xb4); nonce.append(0xaf); nonce.append(0x53); nonce.append(0x68)
    nonce.append(0x22); nonce.append(0x49); nonce.append(0x10); nonce.append(0x74)
    nonce.append(0x18); nonce.append(0xaf); nonce.append(0xc2); nonce.append(0xed)
    nonce.append(0xc5); nonce.append(0x8f); nonce.append(0x75); nonce.append(0xac)
    nonce.append(0x58); nonce.append(0xa0); nonce.append(0x74); nonce.append(0x04)

    var R_point = _ed_base_mul(nonce)
    var R_bytes = _ed_compress(R_point)

    var expected = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
    var got = hex_bytes(R_bytes)

    print("R = nonce * G:")
    print("  got:", got)
    print("  exp:", expected)
    print("  PASS" if got == expected else "  FAIL")

    # Also test with the clamped private key scalar (should give pk)
    # pk = d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511
    # clamped_scalar = 307c83864f2833cb427a2ef1c00a013cfdff2768d980c0a3a520f006904de94f
    var clamped = List[UInt8](capacity=32)
    clamped.append(0x30); clamped.append(0x7c); clamped.append(0x83); clamped.append(0x86)
    clamped.append(0x4f); clamped.append(0x28); clamped.append(0x33); clamped.append(0xcb)
    clamped.append(0x42); clamped.append(0x7a); clamped.append(0x2e); clamped.append(0xf1)
    clamped.append(0xc0); clamped.append(0x0a); clamped.append(0x01); clamped.append(0x3c)
    clamped.append(0xfd); clamped.append(0xff); clamped.append(0x27); clamped.append(0x68)
    clamped.append(0xd9); clamped.append(0x80); clamped.append(0xc0); clamped.append(0xa3)
    clamped.append(0xa5); clamped.append(0x20); clamped.append(0xf0); clamped.append(0x06)
    clamped.append(0x90); clamped.append(0x4d); clamped.append(0xe9); clamped.append(0x4f)

    var pk_point = _ed_base_mul(clamped)
    var pk_bytes = _ed_compress(pk_point)

    var pk_expected = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511"
    var pk_got = hex_bytes(pk_bytes)

    print("pk = clamped_scalar * G:")
    print("  got:", pk_got)
    print("  exp:", pk_expected)
    print("  PASS" if pk_got == pk_expected else "  FAIL")
