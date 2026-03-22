# ============================================================================
# test_prf.mojo — Unit tests for crypto/prf.mojo (TLS 1.2 PRF)
# ============================================================================
# Test vectors generated with Python:
#
#   import hmac, hashlib
#   def p_hash(H, secret, seed, length):
#       result, A = b"", seed
#       while len(result) < length:
#           A = hmac.new(secret, A, H).digest()
#           result += hmac.new(secret, A + seed, H).digest()
#       return result[:length]
#   def prf_sha256(secret, label, seed, length):
#       return p_hash(hashlib.sha256, secret, label.encode() + seed, length)
# ============================================================================

from crypto.prf import (
    p_hash_sha256, p_hash_sha384,
    prf_sha256, prf_sha384,
    tls12_master_secret, tls12_key_block, tls12_verify_data,
)


def hex_to_bytes(h: String) -> List[UInt8]:
    var raw = h.as_bytes()
    var n = len(raw) // 2
    var out = List[UInt8](capacity=n)
    for i in range(n):
        var hi = raw[i * 2]
        var lo = raw[i * 2 + 1]
        var h_val: UInt8 = (hi - 48) if hi <= 57 else (hi - 87)
        var l_val: UInt8 = (lo - 48) if lo <= 57 else (lo - 87)
        out.append((h_val << 4) | l_val)
    return out^


def make_bytes(value: UInt8, count: Int) -> List[UInt8]:
    var out = List[UInt8](capacity=count)
    for i in range(count):
        out.append(value)
    return out^


def run_test(
    name: String,
    mut passed: Int,
    mut failed: Int,
    test_fn: def () raises -> None,
):
    try:
        test_fn()
        print("  PASS:", name)
        passed += 1
    except e:
        print("  FAIL:", name, "-", String(e))
        failed += 1


# ── Tests ──────────────────────────────────────────────────────────────────

def test_p_hash_sha256_48() raises:
    """p_hash_sha256: secret=0x01*32, seed=0x02*32 → 48 bytes."""
    var secret = make_bytes(0x01, 32)
    var seed   = make_bytes(0x02, 32)
    var expected = hex_to_bytes(
        "1527f340fedb6d9f3251774048f758793ea011545c7474da22bf42a8d87d5794e"
        "b6f380ba1d01a0fc6a2efdd05789ac1"
    )
    var got = p_hash_sha256(secret, seed, 48)
    if len(got) != 48:
        raise Error("expected 48 bytes, got " + String(len(got)))
    for i in range(48):
        if got[i] != expected[i]:
            raise Error("mismatch at byte " + String(i))


def test_p_hash_sha384_48() raises:
    """p_hash_sha384: secret=0x01*32, seed=0x02*32 → 48 bytes."""
    var secret = make_bytes(0x01, 32)
    var seed   = make_bytes(0x02, 32)
    var expected = hex_to_bytes(
        "7a7fa79d62a0ebce5e2371a8c3578ff9fa40cc3a444dad9c5dcbcb6a5c5681ae"
        "cd2529adacf971cbcaab8dc4c28a6103"
    )
    var got = p_hash_sha384(secret, seed, 48)
    if len(got) != 48:
        raise Error("expected 48 bytes, got " + String(len(got)))
    for i in range(48):
        if got[i] != expected[i]:
            raise Error("mismatch at byte " + String(i))


def test_prf_sha256_100() raises:
    """prf_sha256: label='test label', secret=0x01*32, seed=0x02*32 → 100 bytes."""
    var secret = make_bytes(0x01, 32)
    var seed   = make_bytes(0x02, 32)
    var expected = hex_to_bytes(
        "4252a6803b031c46ac831ddc10c7cf4f4e007bd4e619252c368cd3cfb38344bab"
        "4cc9129b525f6766043bc4abf9e3425a7ae1769c594ab8b32858755886c027c0d"
        "1e8c0b59836a869f2cabb0f579978428d83458eea88fac86b3e2c9e1c4487daba"
        "1224c"
    )
    var got = prf_sha256(secret, "test label", seed, 100)
    if len(got) != 100:
        raise Error("expected 100 bytes, got " + String(len(got)))
    for i in range(100):
        if got[i] != expected[i]:
            raise Error("mismatch at byte " + String(i))


def test_tls12_master_secret() raises:
    """tls12_master_secret: pre_master=0x03*48, randoms=0x04*32 || 0x05*32."""
    var pre_master     = make_bytes(0x03, 48)
    var client_random  = make_bytes(0x04, 32)
    var server_random  = make_bytes(0x05, 32)
    var expected = hex_to_bytes(
        "205567dfa721bd0611364d0057e780492e7c805bab695049420da0fe5963f0ad6"
        "b01a2906df9d8d735d51b2c37b4991f"
    )
    var got = tls12_master_secret(pre_master, client_random, server_random)
    if len(got) != 48:
        raise Error("expected 48 bytes, got " + String(len(got)))
    for i in range(48):
        if got[i] != expected[i]:
            raise Error("mismatch at byte " + String(i))


def test_tls12_key_block() raises:
    """tls12_key_block: 40 bytes of key material."""
    # Use master secret derived in test above
    var pre_master     = make_bytes(0x03, 48)
    var client_random  = make_bytes(0x04, 32)
    var server_random  = make_bytes(0x05, 32)
    var master = tls12_master_secret(pre_master, client_random, server_random)
    var expected = hex_to_bytes(
        "749f1f26bf41a114eab5b0a3970d47d2350c096a8842d8273ce5d7ba9d3f5b4e4"
        "b8c9982fa9ddefd"
    )
    var got = tls12_key_block(master, server_random, client_random, 40)
    if len(got) != 40:
        raise Error("expected 40 bytes, got " + String(len(got)))
    for i in range(40):
        if got[i] != expected[i]:
            raise Error("mismatch at byte " + String(i))


def test_tls12_verify_data_client() raises:
    """tls12_verify_data 'client finished' → 12 bytes."""
    var pre_master     = make_bytes(0x03, 48)
    var client_random  = make_bytes(0x04, 32)
    var server_random  = make_bytes(0x05, 32)
    var master = tls12_master_secret(pre_master, client_random, server_random)
    var hash   = make_bytes(0x06, 32)
    var expected = hex_to_bytes("dec9a5d8595eb456a781388e")
    var got = tls12_verify_data(master, "client finished", hash)
    if len(got) != 12:
        raise Error("expected 12 bytes, got " + String(len(got)))
    for i in range(12):
        if got[i] != expected[i]:
            raise Error("mismatch at byte " + String(i))


def test_tls12_verify_data_server() raises:
    """tls12_verify_data 'server finished' → 12 bytes."""
    var pre_master     = make_bytes(0x03, 48)
    var client_random  = make_bytes(0x04, 32)
    var server_random  = make_bytes(0x05, 32)
    var master = tls12_master_secret(pre_master, client_random, server_random)
    var hash   = make_bytes(0x06, 32)
    var expected = hex_to_bytes("240ea20bf7fb3e467f32e89a")
    var got = tls12_verify_data(master, "server finished", hash)
    if len(got) != 12:
        raise Error("expected 12 bytes, got " + String(len(got)))
    for i in range(12):
        if got[i] != expected[i]:
            raise Error("mismatch at byte " + String(i))


def test_prf_sha384_100() raises:
    """prf_sha384: label='test label', secret=0x01*32, seed=0x02*32 → 100 bytes."""
    var secret = make_bytes(0x01, 32)
    var seed   = make_bytes(0x02, 32)
    var expected = hex_to_bytes(
        "8052e060dac8a8b951005ab603624950e3540146c7e054617ff3808fbcc6b719c"
        "58d35ecb550821e16656f974a2cd084caecb6044c5a8d2e6d5431d7fae0bbfa8b"
        "4c1a27c67acad704ee50dea2e5153a111661f28656de9355210132702f707931e7"
        "da64"
    )
    var got = prf_sha384(secret, "test label", seed, 100)
    if len(got) != 100:
        raise Error("expected 100 bytes, got " + String(len(got)))
    for i in range(100):
        if got[i] != expected[i]:
            raise Error("mismatch at byte " + String(i))


def main() raises:
    var passed = 0
    var failed = 0

    print("=== TLS 1.2 PRF Tests ===")
    print()

    run_test("p_hash_sha256: 48 bytes", passed, failed, test_p_hash_sha256_48)
    run_test("p_hash_sha384: 48 bytes", passed, failed, test_p_hash_sha384_48)
    run_test("prf_sha256: 100 bytes", passed, failed, test_prf_sha256_100)
    run_test("prf_sha384: 100 bytes", passed, failed, test_prf_sha384_100)
    run_test("tls12_master_secret: 48 bytes", passed, failed, test_tls12_master_secret)
    run_test("tls12_key_block: 40 bytes", passed, failed, test_tls12_key_block)
    run_test("tls12_verify_data client finished", passed, failed, test_tls12_verify_data_client)
    run_test("tls12_verify_data server finished", passed, failed, test_tls12_verify_data_server)

    print()
    print("Results:", passed, "passed,", failed, "failed")
    if failed > 0:
        raise Error(String(failed) + " test(s) failed")
