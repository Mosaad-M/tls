# ============================================================================
# test_alert.mojo — TLS alert send/handle tests
# ============================================================================
# Tests tls_send_alert and tls_handle_incoming_alert.
# Output capture uses a temp file to avoid needing global mutable state.
# ============================================================================

from std.ffi import external_call
from std.memory.unsafe_pointer import alloc
from std.sys.info import CompilationTarget
from tls.connection import (
    tls_send_alert,
    tls_handle_incoming_alert,
    TlsKeys,
    ALERT_LEVEL_WARNING,
    ALERT_LEVEL_FATAL,
    ALERT_CLOSE_NOTIFY,
    ALERT_BAD_CERT,
)


# ── Temp-file capture helpers ──────────────────────────────────────────────
# These avoid needing module-level mutable state.

def _capture_reset() raises:
    """Truncate /tmp/mojo_alert_test.bin to zero bytes."""
    var path = String("/tmp/mojo_alert_test.bin")
    # O_WRONLY | O_CREAT | O_TRUNC: Linux 1|64|512=577, macOS 1|512|1024=1537
    comptime FLAGS_RESET = 1537 if CompilationTarget.is_macos() else 577
    var fd = external_call["open", Int32](path.unsafe_ptr(), Int32(FLAGS_RESET), Int32(420))
    if fd < 0:
        raise Error("capture_reset: open failed")
    _ = external_call["close", Int32](fd)
    # Mojo FFI does not reliably pass the variadic mode arg to open() on macOS;
    # use chmod to ensure the file is readable for _capture_read.
    _ = external_call["chmod", Int32](path.unsafe_ptr(), Int32(420))


def _capture_write(data: List[UInt8]) raises:
    """Append data to /tmp/mojo_alert_test.bin."""
    var path = String("/tmp/mojo_alert_test.bin")
    # O_WRONLY | O_CREAT | O_APPEND: Linux 1|64|1024=1089, macOS 1|512|8=521
    comptime FLAGS_WRITE = 521 if CompilationTarget.is_macos() else 1089
    var fd = external_call["open", Int32](path.unsafe_ptr(), Int32(FLAGS_WRITE), Int32(420))
    if fd < 0:
        raise Error("capture_write: open failed")
    var n = len(data)
    if n > 0:
        var buf = alloc[UInt8](n)
        for i in range(n):
            (buf + i)[] = data[i]
        _ = external_call["write", Int](Int(fd), buf, n)
        buf.free()
    _ = external_call["close", Int32](fd)


def _capture_read() raises -> List[UInt8]:
    """Read all bytes from /tmp/mojo_alert_test.bin."""
    var path = String("/tmp/mojo_alert_test.bin")
    var fd = external_call["open", Int32](path.unsafe_ptr(), Int32(0), Int32(0))  # O_RDONLY
    if fd < 0:
        raise Error("capture_read: open failed")
    var max_size = 4096
    var buf = alloc[UInt8](max_size)
    var n = external_call["read", Int](Int(fd), buf, max_size)
    _ = external_call["close", Int32](fd)
    var out = List[UInt8](capacity=Int(n))
    for i in range(Int(n)):
        out.append((buf + i)[])
    buf.free()
    return out^


# ── run_test helper ────────────────────────────────────────────────────────

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

def test_send_alert_warning_close_notify() raises:
    """tls_send_alert with empty keys sends 7-byte plaintext alert record."""
    _capture_reset()
    var empty_keys = TlsKeys()
    tls_send_alert(_capture_write, empty_keys, ALERT_LEVEL_WARNING, ALERT_CLOSE_NOTIFY)
    var captured = _capture_read()
    # Expected: [0x15, 0x03, 0x03, 0x00, 0x02, level, code]
    if len(captured) != 7:
        raise Error("expected 7 bytes, got " + String(len(captured)))
    if captured[0] != 0x15:
        raise Error("expected content_type 0x15")
    if captured[1] != 0x03 or captured[2] != 0x03:
        raise Error("expected legacy_version 0x0303")
    if captured[3] != 0x00 or captured[4] != 0x02:
        raise Error("expected length 0x0002")
    if captured[5] != ALERT_LEVEL_WARNING:
        raise Error("expected level=1 (warning)")
    if captured[6] != ALERT_CLOSE_NOTIFY:
        raise Error("expected code=0 (close_notify)")


def test_send_alert_fatal_bad_cert() raises:
    """tls_send_alert with FATAL + BAD_CERT produces correct bytes."""
    _capture_reset()
    var empty_keys = TlsKeys()
    tls_send_alert(_capture_write, empty_keys, ALERT_LEVEL_FATAL, ALERT_BAD_CERT)
    var captured = _capture_read()
    if len(captured) != 7:
        raise Error("expected 7 bytes, got " + String(len(captured)))
    if captured[5] != ALERT_LEVEL_FATAL:
        raise Error("expected level=2 (fatal)")
    if captured[6] != ALERT_BAD_CERT:
        raise Error("expected code=42 (bad_certificate)")


def test_handle_close_notify() raises:
    """tls_handle_incoming_alert raises for close_notify."""
    var alert = List[UInt8]()
    alert.append(1)  # warning
    alert.append(0)  # close_notify
    var raised = False
    try:
        tls_handle_incoming_alert(alert)
    except:
        raised = True
    if not raised:
        raise Error("expected raise for close_notify")


def test_handle_bad_certificate() raises:
    """tls_handle_incoming_alert raises for bad_certificate."""
    var alert = List[UInt8]()
    alert.append(2)   # fatal
    alert.append(42)  # bad_certificate
    var raised = False
    try:
        tls_handle_incoming_alert(alert)
    except:
        raised = True
    if not raised:
        raise Error("expected raise for bad_certificate")


def test_handle_malformed_alert() raises:
    """tls_handle_incoming_alert raises for empty (malformed) alert."""
    var empty = List[UInt8]()
    var raised = False
    try:
        tls_handle_incoming_alert(empty)
    except:
        raised = True
    if not raised:
        raise Error("expected raise for malformed alert")


def main() raises:
    var passed = 0
    var failed = 0

    print("=== TLS Alert Tests ===")
    print()

    run_test("tls_send_alert: warning/close_notify 7-byte record", passed, failed, test_send_alert_warning_close_notify)
    run_test("tls_send_alert: fatal/bad_certificate bytes", passed, failed, test_send_alert_fatal_bad_cert)
    run_test("tls_handle_incoming_alert: close_notify raises", passed, failed, test_handle_close_notify)
    run_test("tls_handle_incoming_alert: bad_certificate raises", passed, failed, test_handle_bad_certificate)
    run_test("tls_handle_incoming_alert: malformed raises", passed, failed, test_handle_malformed_alert)

    print()
    print("Results:", passed, "passed,", failed, "failed")
    if failed > 0:
        raise Error(String(failed) + " test(s) failed")
