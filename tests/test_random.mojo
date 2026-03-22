# ============================================================================
# test_random.mojo — CSPRNG tests
# ============================================================================

from crypto.random import csprng_bytes


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


# ── Tests ─────────────────────────────────────────────────────────────────────

def test_16_bytes() raises:
    var b = csprng_bytes(16)
    if len(b) != 16:
        raise Error("expected 16 bytes, got " + String(len(b)))


def test_32_bytes() raises:
    var b = csprng_bytes(32)
    if len(b) != 32:
        raise Error("expected 32 bytes, got " + String(len(b)))


def test_64_bytes() raises:
    var b = csprng_bytes(64)
    if len(b) != 64:
        raise Error("expected 64 bytes, got " + String(len(b)))


def test_two_calls_differ() raises:
    var a = csprng_bytes(32)
    var b = csprng_bytes(32)
    var same = True
    for i in range(32):
        if a[i] != b[i]:
            same = False
            break
    if same:
        raise Error("two 32-byte random draws were identical (astronomically unlikely)")


def test_zero_bytes() raises:
    var b = csprng_bytes(0)
    if len(b) != 0:
        raise Error("expected empty list, got " + String(len(b)))


def main() raises:
    var passed = 0
    var failed = 0

    print("=== CSPRNG Tests ===")
    print()

    run_test("csprng_bytes(16) returns 16 bytes", passed, failed, test_16_bytes)
    run_test("csprng_bytes(32) returns 32 bytes", passed, failed, test_32_bytes)
    run_test("csprng_bytes(64) returns 64 bytes", passed, failed, test_64_bytes)
    run_test("two 32-byte calls differ", passed, failed, test_two_calls_differ)
    run_test("csprng_bytes(0) returns empty", passed, failed, test_zero_bytes)

    print()
    print("Results:", passed, "passed,", failed, "failed")
    if failed > 0:
        raise Error(String(failed) + " test(s) failed")
