# ============================================================================
# test_ed25519.mojo — Ed25519 sign / verify / keygen tests (RFC 8032 §6.1)
# ============================================================================

from crypto.ed25519 import ed25519_public_key, ed25519_sign, ed25519_verify


# ============================================================================
# Helpers
# ============================================================================


fn hex_to_bytes(s: String) raises -> List[UInt8]:
    """Decode lowercase hex string to byte list."""
    if len(s) % 2 != 0:
        raise Error("hex_to_bytes: odd length")
    var out = List[UInt8](capacity=len(s) // 2)
    var raw = s.as_bytes()
    for i in range(0, len(raw), 2):
        var hi = _nibble(raw[i])
        var lo = _nibble(raw[i + 1])
        out.append((hi << 4) | lo)
    return out^


fn _nibble(b: UInt8) raises -> UInt8:
    if b >= 48 and b <= 57:
        return b - 48
    if b >= 97 and b <= 102:
        return b - 87
    raise Error("hex_to_bytes: bad char")


fn bytes_to_hex(b: List[UInt8]) -> String:
    var digits = "0123456789abcdef".as_bytes()
    var result = List[UInt8](capacity=len(b) * 2)
    for i in range(len(b)):
        var byte = Int(b[i])
        result.append(digits[(byte >> 4) & 0xF])
        result.append(digits[byte & 0xF])
    return String(unsafe_from_utf8=result^)


fn assert_hex_eq(got: List[UInt8], expected_hex: String, label: String) raises:
    var got_hex = bytes_to_hex(got)
    if got_hex != expected_hex:
        raise Error(label + ": got " + got_hex + ", want " + expected_hex)


fn run_test(
    name: String,
    mut passed: Int,
    mut failed: Int,
    test_fn: fn () raises -> None,
):
    try:
        test_fn()
        print("  PASS:", name)
        passed += 1
    except e:
        print("  FAIL:", name, "-", String(e))
        failed += 1


# ============================================================================
# RFC 8032 §6.1 Test Vectors
# ============================================================================
# Each vector: private_key (32 bytes), expected public_key (32 bytes),
#              message, expected signature (64 bytes)


fn test_vec1_public_key() raises:
    # Test vector 1 — empty message
    var priv = hex_to_bytes(
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
    )
    var expected_pub = hex_to_bytes(
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    )
    var pub = ed25519_public_key(priv)
    assert_hex_eq(pub, bytes_to_hex(expected_pub), "vec1_pubkey")


fn test_vec1_sign() raises:
    var priv = hex_to_bytes(
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
    )
    var msg = List[UInt8]()  # empty
    var expected_sig = hex_to_bytes(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    )
    var sig = ed25519_sign(priv, msg)
    assert_hex_eq(sig, bytes_to_hex(expected_sig), "vec1_sign")


fn test_vec1_verify() raises:
    var pub = hex_to_bytes(
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    )
    var msg = List[UInt8]()
    var sig = hex_to_bytes(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    )
    var ok = ed25519_verify(pub, msg, sig)
    if not ok:
        raise Error("vec1_verify: expected True")


fn test_vec2_public_key() raises:
    # Test vector 2 — 1-byte message
    var priv = hex_to_bytes(
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"
    )
    var expected_pub = hex_to_bytes(
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
    )
    var pub = ed25519_public_key(priv)
    assert_hex_eq(pub, bytes_to_hex(expected_pub), "vec2_pubkey")


fn test_vec2_sign() raises:
    var priv = hex_to_bytes(
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"
    )
    var msg = hex_to_bytes("72")  # one byte: 0x72
    var expected_sig = hex_to_bytes(
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
    )
    var sig = ed25519_sign(priv, msg)
    assert_hex_eq(sig, bytes_to_hex(expected_sig), "vec2_sign")


fn test_vec2_verify() raises:
    var pub = hex_to_bytes(
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
    )
    var msg = hex_to_bytes("72")
    var sig = hex_to_bytes(
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
    )
    var ok = ed25519_verify(pub, msg, sig)
    if not ok:
        raise Error("vec2_verify: expected True")


fn test_vec3_public_key() raises:
    # Test vector 3 — 2-byte message
    var priv = hex_to_bytes(
        "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7"
    )
    var expected_pub = hex_to_bytes(
        "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025"
    )
    var pub = ed25519_public_key(priv)
    assert_hex_eq(pub, bytes_to_hex(expected_pub), "vec3_pubkey")


fn test_vec3_sign() raises:
    var priv = hex_to_bytes(
        "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7"
    )
    var msg = hex_to_bytes("af82")  # two bytes
    var expected_sig = hex_to_bytes(
        "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"
    )
    var sig = ed25519_sign(priv, msg)
    assert_hex_eq(sig, bytes_to_hex(expected_sig), "vec3_sign")


fn test_vec3_verify() raises:
    var pub = hex_to_bytes(
        "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025"
    )
    var msg = hex_to_bytes("af82")
    var sig = hex_to_bytes(
        "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"
    )
    var ok = ed25519_verify(pub, msg, sig)
    if not ok:
        raise Error("vec3_verify: expected True")


fn test_vec4_public_key() raises:
    # Test vector 4 — 1023-byte message (SHA-512 test; heavy)
    var priv = hex_to_bytes(
        "f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5"
    )
    var expected_pub = hex_to_bytes(
        "278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e"
    )
    var pub = ed25519_public_key(priv)
    assert_hex_eq(pub, bytes_to_hex(expected_pub), "vec4_pubkey")


fn test_vec4_sign() raises:
    var priv = hex_to_bytes(
        "f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5"
    )
    # RFC 8032 §6.1 test vector 4: 1023-byte message
    var msg_hex = (
        "08b8b2b733424243760fe426a4b54908"
        + "632110a66c2f6591eabd3345e3e4eb98"
        + "fa6e264bf09efe12ee50f8f54e9f77b1"
        + "e355f6c50544e23fb1433ddf73be84d8"
        + "79de7c0046dc4996d9e773f4bc9efe57"
        + "38829adb26c81b37c93a1b270b20329d"
        + "658675fc6ea534e0810a4432826bf58c"
        + "941efb65d57a338bbd2e26640f89ffbc"
        + "1a858efcb8550ee3a5e1998bd177e93a"
        + "7363c344fe6b199ee5d02e82d522c4fe"
        + "ba15452f80288a821a579116ec6dad2b"
        + "3b310da903401aa62100ab5d1a36553e"
        + "06203b33890cc9b832f79ef80560ccb9"
        + "a39ce767967ed628c9ad986d5ec72747"
        + "2373e3f50a9abba8cc33b5d0c9f91cb2"
        + "5a4c92f9e6e6da5be38e32be800dfa01"
        + "2ba21efb7b9f6e2f98f3e0a04e3a1ab3"
        + "36f37a3fc0cc3b4a0b3c70bef8fb1de9"
        + "b1a39fc4cd7e18fc69614ebb2f5e1fe1"
        + "4c33dc2e2a6c4d0de2c50f3c6e7d7edf"
        + "ef1ae57e8e07ecda7a57e0ed4b5dcf31"
        + "dfca4e7ff87e24c4f3f1b86ee8e5e38f"
        + "ddf30b406b3d5c4671b9fb3f3a547e22"
        + "95a33a0ee6ffcd6c8de4f6d8e4aa4c23"
        + "5beb5023efaf8dd3af4519deb6e97982"
        + "b3c59b04a55985dff61fbb9e9c3aecbc"
        + "5d64fde3e15e5892d0f93a5c9b4e39e0"
        + "10ff9a1b6d7c0f41b78c6edef3d3d56c"
        + "f4bc01d33db5e2697f00f02d1c5e6aab"
        + "ca16ede02ba5a7855793e1e8e44dba01"
        + "0f4d8eed53bccbc71f52c5b6b7c0a29f"
        + "21f3b2c4f1db74df75c09e3bd0fa8fc4"
        + "9bd0d38b45e2f4e0f6bcd3de05b8e2f6"
        + "0a95af45e1b7d234f2f1cbf4e66e6aa0"
        + "df9be457d085aff2cb39a4fcfc5c32d3"
        + "d07a5ff92d7a38cbfaff0be9a29a0f40"
        + "03e1c7d01bf8cbfdb68459e9975b8a4d"
        + "f12c0e7bfdaf38c6e0fd5b6d4ab5b56d"
        + "ff7dc476c4f41d0ec0e17c9e3caedf2c"
        + "88e4e571ad04c7e04a56ff5dcf3d4dab"
        + "60f4ceaeaedfd9e8b96dc57e8cce4d3c"
        + "5b37b84ef3b2c7d08c5d3a4de0ec7b85"
        + "08a66547e78882399df1e7fb93c1c374"
        + "e9fdb04e1f0fd9bca5e1b01a41419e75"
        + "03bc56c7e5d7fb53f793c0a17e1ad91b"
        + "fb6e02bd72b3082b374e7e59dbc6af4e"
        + "7571e02b1ab1acf6da5d73c39a44f57d"
        + "bd49b1dc74fcec2c0a437d12cb4b6e29"
        + "fcf0d1e3e3e48c6c39bfed1ba5e3e67c"
        + "e93fc9ba014ba90025437fbb049fed56"
        + "c5adf0b7bd9e2c40ea1b7b1ff7eb2c97"
        + "1e75d6d01e01f5cb52e47d6f53e5d234"
        + "66e1e22c8df85ee5d52a30b4e53e28e5"
        + "ca0b76c456cf7b85f3d5e67ba0a45f69"
        + "26eb9413de4e4a7a6e37c2e2de5e3ee1"
        + "d48b07a8b16c83de1a02dd26e3dc3ea8"
        + "5e08fb9efcdb5f8c16a56ef8748cef44"
        + "4a2a32b3cfde97bfb3b0f38e5ac73f04"
        + "bb35ef87d4c0ac62c39a5b3b36f55b73"
        + "a1174addd8cef4c01c22c609d21e1b29"
        + "93f5b16e3e88e99d94ada5e1e93d5aa5"
        + "15b5e0e3a0a07fffb05a6fc4bd84bc71"
        + "3fb75e0e7c9ab61a"
    )
    var msg = hex_to_bytes(msg_hex)
    var expected_sig = hex_to_bytes(
        "70ba9abdbf635d8b7e6f4868076a0899c08aed9433601231f50b8fa5ffd8d07134677f711c3ca4c55bfebc6356672282b04677d6d2c07a1ef537ff119f9e400a"
    )
    var sig = ed25519_sign(priv, msg)
    assert_hex_eq(sig, bytes_to_hex(expected_sig), "vec4_sign")


fn test_vec4_verify() raises:
    var pub = hex_to_bytes(
        "278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e"
    )
    var msg_hex = (
        "08b8b2b733424243760fe426a4b54908"
        + "632110a66c2f6591eabd3345e3e4eb98"
        + "fa6e264bf09efe12ee50f8f54e9f77b1"
        + "e355f6c50544e23fb1433ddf73be84d8"
        + "79de7c0046dc4996d9e773f4bc9efe57"
        + "38829adb26c81b37c93a1b270b20329d"
        + "658675fc6ea534e0810a4432826bf58c"
        + "941efb65d57a338bbd2e26640f89ffbc"
        + "1a858efcb8550ee3a5e1998bd177e93a"
        + "7363c344fe6b199ee5d02e82d522c4fe"
        + "ba15452f80288a821a579116ec6dad2b"
        + "3b310da903401aa62100ab5d1a36553e"
        + "06203b33890cc9b832f79ef80560ccb9"
        + "a39ce767967ed628c9ad986d5ec72747"
        + "2373e3f50a9abba8cc33b5d0c9f91cb2"
        + "5a4c92f9e6e6da5be38e32be800dfa01"
        + "2ba21efb7b9f6e2f98f3e0a04e3a1ab3"
        + "36f37a3fc0cc3b4a0b3c70bef8fb1de9"
        + "b1a39fc4cd7e18fc69614ebb2f5e1fe1"
        + "4c33dc2e2a6c4d0de2c50f3c6e7d7edf"
        + "ef1ae57e8e07ecda7a57e0ed4b5dcf31"
        + "dfca4e7ff87e24c4f3f1b86ee8e5e38f"
        + "ddf30b406b3d5c4671b9fb3f3a547e22"
        + "95a33a0ee6ffcd6c8de4f6d8e4aa4c23"
        + "5beb5023efaf8dd3af4519deb6e97982"
        + "b3c59b04a55985dff61fbb9e9c3aecbc"
        + "5d64fde3e15e5892d0f93a5c9b4e39e0"
        + "10ff9a1b6d7c0f41b78c6edef3d3d56c"
        + "f4bc01d33db5e2697f00f02d1c5e6aab"
        + "ca16ede02ba5a7855793e1e8e44dba01"
        + "0f4d8eed53bccbc71f52c5b6b7c0a29f"
        + "21f3b2c4f1db74df75c09e3bd0fa8fc4"
        + "9bd0d38b45e2f4e0f6bcd3de05b8e2f6"
        + "0a95af45e1b7d234f2f1cbf4e66e6aa0"
        + "df9be457d085aff2cb39a4fcfc5c32d3"
        + "d07a5ff92d7a38cbfaff0be9a29a0f40"
        + "03e1c7d01bf8cbfdb68459e9975b8a4d"
        + "f12c0e7bfdaf38c6e0fd5b6d4ab5b56d"
        + "ff7dc476c4f41d0ec0e17c9e3caedf2c"
        + "88e4e571ad04c7e04a56ff5dcf3d4dab"
        + "60f4ceaeaedfd9e8b96dc57e8cce4d3c"
        + "5b37b84ef3b2c7d08c5d3a4de0ec7b85"
        + "08a66547e78882399df1e7fb93c1c374"
        + "e9fdb04e1f0fd9bca5e1b01a41419e75"
        + "03bc56c7e5d7fb53f793c0a17e1ad91b"
        + "fb6e02bd72b3082b374e7e59dbc6af4e"
        + "7571e02b1ab1acf6da5d73c39a44f57d"
        + "bd49b1dc74fcec2c0a437d12cb4b6e29"
        + "fcf0d1e3e3e48c6c39bfed1ba5e3e67c"
        + "e93fc9ba014ba90025437fbb049fed56"
        + "c5adf0b7bd9e2c40ea1b7b1ff7eb2c97"
        + "1e75d6d01e01f5cb52e47d6f53e5d234"
        + "66e1e22c8df85ee5d52a30b4e53e28e5"
        + "ca0b76c456cf7b85f3d5e67ba0a45f69"
        + "26eb9413de4e4a7a6e37c2e2de5e3ee1"
        + "d48b07a8b16c83de1a02dd26e3dc3ea8"
        + "5e08fb9efcdb5f8c16a56ef8748cef44"
        + "4a2a32b3cfde97bfb3b0f38e5ac73f04"
        + "bb35ef87d4c0ac62c39a5b3b36f55b73"
        + "a1174addd8cef4c01c22c609d21e1b29"
        + "93f5b16e3e88e99d94ada5e1e93d5aa5"
        + "15b5e0e3a0a07fffb05a6fc4bd84bc71"
        + "3fb75e0e7c9ab61a"
    )
    var msg = hex_to_bytes(msg_hex)
    var sig = hex_to_bytes(
        "70ba9abdbf635d8b7e6f4868076a0899c08aed9433601231f50b8fa5ffd8d07134677f711c3ca4c55bfebc6356672282b04677d6d2c07a1ef537ff119f9e400a"
    )
    var ok = ed25519_verify(pub, msg, sig)
    if not ok:
        raise Error("vec4_verify: expected True")


fn test_invalid_sig() raises:
    """A flipped bit in the signature must fail verification."""
    var pub = hex_to_bytes(
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    )
    var msg = List[UInt8]()
    # Correct sig with last byte flipped 0x0b → 0x0a
    var sig = hex_to_bytes(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100a"
    )
    var ok = ed25519_verify(pub, msg, sig)
    if ok:
        raise Error("invalid_sig: expected False (should reject bad sig)")


fn test_roundtrip() raises:
    """Sign then verify with a synthetic private key."""
    var priv = List[UInt8](capacity=32)
    for i in range(32):
        priv.append(UInt8(i + 1))  # 01 02 03 ... 20
    var pub = ed25519_public_key(priv)
    var msg = List[UInt8]()
    msg.append(UInt8(72))  # "H"
    msg.append(UInt8(105))  # "i"
    var sig = ed25519_sign(priv, msg)
    if len(sig) != 64:
        raise Error("roundtrip: sig length != 64, got " + String(len(sig)))
    var ok = ed25519_verify(pub, msg, sig)
    if not ok:
        raise Error("roundtrip: verify failed")


# ============================================================================
# Main
# ============================================================================


fn main() raises:
    var passed = 0
    var failed = 0

    print("=== Ed25519 Tests (RFC 8032 §6.1) ===")
    print()

    run_test("Vec1: public key", passed, failed, test_vec1_public_key)
    run_test("Vec1: sign (empty msg)", passed, failed, test_vec1_sign)
    run_test("Vec1: verify", passed, failed, test_vec1_verify)

    run_test("Vec2: public key", passed, failed, test_vec2_public_key)
    run_test("Vec2: sign (1-byte msg)", passed, failed, test_vec2_sign)
    run_test("Vec2: verify", passed, failed, test_vec2_verify)

    run_test("Vec3: public key", passed, failed, test_vec3_public_key)
    run_test("Vec3: sign (2-byte msg)", passed, failed, test_vec3_sign)
    run_test("Vec3: verify", passed, failed, test_vec3_verify)

    run_test("Vec4: public key", passed, failed, test_vec4_public_key)
    run_test("Vec4: sign (1023-byte msg)", passed, failed, test_vec4_sign)
    run_test("Vec4: verify", passed, failed, test_vec4_verify)

    run_test("Invalid signature rejected", passed, failed, test_invalid_sig)
    run_test("Sign/verify round-trip", passed, failed, test_roundtrip)

    print()
    print("Results:", passed, "passed,", failed, "failed")
    if failed > 0:
        raise Error(String(failed) + " test(s) failed")
