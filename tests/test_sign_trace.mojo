"""Trace ed25519_sign step by step for Vec1."""
from crypto.hash import sha512
from crypto.ed25519 import _scalar_reduce, _ed_base_mul, _ed_compress, ed25519_public_key, ed25519_sign


def hex_bytes(s: List[UInt8]) -> String:
    var result = String()
    for i in range(len(s)):
        var b = Int(s[i])
        var hi = b >> 4
        var lo = b & 0xF
        result += String(chr(hi + 48 if hi < 10 else hi + 87))
        result += String(chr(lo + 48 if lo < 10 else lo + 87))
    return result


def clamp(h: List[UInt8]) -> List[UInt8]:
    var scalar = List[UInt8](capacity=32)
    for i in range(32):
        scalar.append(h[i])
    scalar[0] &= 248
    scalar[31] &= 127
    scalar[31] |= 64
    return scalar^


def main() raises:
    # Vec1: sk = 9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60
    var sk = List[UInt8](capacity=32)
    sk.append(0x9d); sk.append(0x61); sk.append(0xb1); sk.append(0x9d)
    sk.append(0xef); sk.append(0xfd); sk.append(0x5a); sk.append(0x60)
    sk.append(0xba); sk.append(0x84); sk.append(0x4a); sk.append(0xf4)
    sk.append(0x92); sk.append(0xec); sk.append(0x2c); sk.append(0xc4)
    sk.append(0x44); sk.append(0x49); sk.append(0xc5); sk.append(0x69)
    sk.append(0x7b); sk.append(0x32); sk.append(0x69); sk.append(0x19)
    sk.append(0x70); sk.append(0x3b); sk.append(0xac); sk.append(0x03)
    sk.append(0x1c); sk.append(0xae); sk.append(0x7f); sk.append(0x60)

    # Step 1: h = sha512(sk)
    var h = sha512(sk)
    print("h =", hex_bytes(h))
    print("h expected = 357c83864f2833cb427a2ef1c00a013cfdff2768d980c0a3a520f006904de90f9b4f0afe280b746a778684e75442502057b7473a03f08f96f5a38e9287e01f8f")

    # Step 2: nonce_input = h[32:64]
    var nonce_input = List[UInt8](capacity=32)
    for i in range(32, 64):
        nonce_input.append(h[i])
    print("nonce_input =", hex_bytes(nonce_input))
    print("expected    = 9b4f0afe280b746a778684e75442502057b7473a03f08f96f5a38e9287e01f8f")

    # Step 3: r_hash = sha512(nonce_input)
    var r_hash = sha512(nonce_input)
    print("r_hash =", hex_bytes(r_hash))
    print("expected = b6b19cd8e0426f5983fa112d89a143aa97dab8bc5deb8d5b6253c928b65272f4044098c2a990039cde5b6a4818df0bfb6e40dc5dee54248032962323e701352d")

    # Step 4: r_scalar = reduce(r_hash)
    var r_scalar = _scalar_reduce(r_hash)
    print("r_scalar =", hex_bytes(r_scalar))
    print("expected = f38907308c893deaf244787db4af53682249107418afc2edc58f75ac58a07404")

    # Step 5: R = r_scalar * G
    var R_point = _ed_base_mul(r_scalar)
    var R_bytes = _ed_compress(R_point)
    print("R =      ", hex_bytes(R_bytes))
    print("expected = e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155")

    # Step 6: A = ed25519_public_key(sk)
    var A_bytes = ed25519_public_key(sk)
    print("A =      ", hex_bytes(A_bytes))
    print("expected = d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")

    # Step 7: k = sha512(R || A || msg)
    var k_input = List[UInt8](capacity=64)
    for i in range(32):
        k_input.append(R_bytes[i])
    for i in range(32):
        k_input.append(A_bytes[i])
    var k_hash = sha512(k_input)
    var k_scalar = _scalar_reduce(k_hash)
    print("k_scalar =", hex_bytes(k_scalar))

    # Also try the full sign
    var sig = ed25519_sign(sk, List[UInt8]())
    print("sig full =", hex_bytes(sig))
    print("expected = e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
