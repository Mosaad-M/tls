# ============================================================================
# test_session_ticket.mojo — SessionTicket parser tests
# ============================================================================
# Tests parse_new_session_ticket() with valid inputs, boundary truncations,
# and edge cases. Valid byte sequence derived from RFC 8448 §2 trace.
# ============================================================================

from tls.message import parse_new_session_ticket, SessionTicket


# ============================================================================
# Helpers
# ============================================================================

def _hex_nibble(b: UInt8) raises -> UInt8:
    if b >= 48 and b <= 57: return b - 48
    if b >= 97 and b <= 102: return b - 87
    raise Error("bad hex char")


def hex_to_bytes(hex: String) raises -> List[UInt8]:
    var raw = hex.as_bytes()
    var n = len(raw)
    if n % 2 != 0: raise Error("odd hex length")
    var out = List[UInt8](capacity=n // 2)
    for i in range(0, n, 2):
        out.append((_hex_nibble(raw[i]) << 4) | _hex_nibble(raw[i + 1]))
    return out^


def bytes_to_hex(b: List[UInt8]) -> String:
    var digits = "0123456789abcdef".as_bytes()
    var result = List[UInt8](capacity=len(b) * 2)
    for i in range(len(b)):
        var byte = Int(b[i])
        result.append(digits[(byte >> 4) & 0xF])
        result.append(digits[byte & 0xF])
    return String(unsafe_from_utf8=result^)


def assert_eq(actual: Int, expected: Int, label: String) raises:
    if actual != expected:
        raise Error(label + ": got " + String(actual) + ", want " + String(expected))


def assert_hex_eq(got: List[UInt8], expected_hex: String, label: String) raises:
    var h = bytes_to_hex(got)
    if h != expected_hex:
        raise Error(label + ": got " + h + ", want " + expected_hex)


def assert_true(cond: Bool, label: String) raises:
    if not cond:
        raise Error(label + ": expected True")


def run_test(name: String, mut passed: Int, mut failed: Int, test_fn: def () raises -> None):
    try:
        test_fn()
        print("  PASS:", name)
        passed += 1
    except e:
        print("  FAIL:", name, "-", String(e))
        failed += 1


# ============================================================================
# Build a minimal valid NewSessionTicket body for testing
#
# ticket_lifetime = 0x0001C900  (7 hours, 28800 s — value from RFC 8448)
# ticket_age_add  = 0xADD115ED  (arbitrary)
# ticket_nonce    = []          (empty, as in RFC 8448 §2)
# ticket          = [0xAB, 0xCD, 0xEF]  (3-byte opaque identity)
# extensions      = []          (0-length extension list)
# ============================================================================

def _build_minimal_ticket_body() -> List[UInt8]:
    var b = List[UInt8]()
    # ticket_lifetime = 7 * 3600 = 25200 = 0x00006270
    b.append(0x00); b.append(0x00); b.append(0x62); b.append(0x70)
    # ticket_age_add = 0xADD115ED
    b.append(0xAD); b.append(0xD1); b.append(0x15); b.append(0xED)
    # ticket_nonce: len=0 (empty)
    b.append(0x00)
    # ticket: len=3
    b.append(0x00); b.append(0x03)
    b.append(0xAB); b.append(0xCD); b.append(0xEF)
    # extensions: len=0
    b.append(0x00); b.append(0x00)
    return b^


# ============================================================================
# Test 1 — Parse valid minimal ticket
# ============================================================================

def test_parse_valid_minimal() raises:
    var body = _build_minimal_ticket_body()
    var st = parse_new_session_ticket(body)
    assert_eq(Int(st.lifetime_secs), 0x6270, "lifetime_secs")
    assert_eq(Int(st.age_add), Int(0xADD115ED), "age_add")
    assert_eq(len(st.nonce), 0, "nonce empty")
    assert_hex_eq(st.ticket, "abcdef", "ticket bytes")


# ============================================================================
# Test 2 — Parse ticket with non-empty nonce
# ============================================================================

def test_parse_nonempty_nonce() raises:
    var b = List[UInt8]()
    # lifetime = 3600
    b.append(0x00); b.append(0x00); b.append(0x0E); b.append(0x10)
    # age_add = 0x11223344
    b.append(0x11); b.append(0x22); b.append(0x33); b.append(0x44)
    # nonce: len=2, bytes=[0xAA, 0xBB]
    b.append(0x02); b.append(0xAA); b.append(0xBB)
    # ticket: len=1, byte=[0xFF]
    b.append(0x00); b.append(0x01); b.append(0xFF)
    # extensions: len=0
    b.append(0x00); b.append(0x00)

    var st = parse_new_session_ticket(b)
    assert_eq(len(st.nonce), 2, "nonce length")
    assert_eq(Int(st.nonce[0]), 0xAA, "nonce[0]")
    assert_eq(Int(st.nonce[1]), 0xBB, "nonce[1]")
    assert_eq(len(st.ticket), 1, "ticket length")
    assert_eq(Int(st.ticket[0]), 0xFF, "ticket[0]")


# ============================================================================
# Test 3 — Truncation at ticket_lifetime raises
# ============================================================================

def test_truncated_at_lifetime() raises:
    var b = List[UInt8]()
    b.append(0x00); b.append(0x00)   # only 2 of 4 bytes
    var got_error = False
    try:
        _ = parse_new_session_ticket(b)
    except:
        got_error = True
    assert_true(got_error, "truncated at lifetime must raise")


# ============================================================================
# Test 4 — Truncation at ticket_age_add raises
# ============================================================================

def test_truncated_at_age_add() raises:
    var b = List[UInt8]()
    b.append(0x00); b.append(0x00); b.append(0x00); b.append(0x01)   # lifetime ok
    b.append(0x00); b.append(0x00)   # only 2 of 4 age_add bytes
    var got_error = False
    try:
        _ = parse_new_session_ticket(b)
    except:
        got_error = True
    assert_true(got_error, "truncated at age_add must raise")


# ============================================================================
# Test 5 — Truncation at nonce raises
# ============================================================================

def test_truncated_at_nonce() raises:
    var b = List[UInt8]()
    b.append(0x00); b.append(0x00); b.append(0x00); b.append(0x01)
    b.append(0x00); b.append(0x00); b.append(0x00); b.append(0x01)
    b.append(0x04)   # nonce len = 4 but no nonce bytes follow
    var got_error = False
    try:
        _ = parse_new_session_ticket(b)
    except:
        got_error = True
    assert_true(got_error, "truncated at nonce must raise")


# ============================================================================
# Test 6 — Truncation at ticket raises
# ============================================================================

def test_truncated_at_ticket() raises:
    var b = List[UInt8]()
    b.append(0x00); b.append(0x00); b.append(0x00); b.append(0x01)
    b.append(0x00); b.append(0x00); b.append(0x00); b.append(0x01)
    b.append(0x00)   # nonce len = 0
    b.append(0x00); b.append(0x10)   # ticket len = 16 but no bytes follow
    var got_error = False
    try:
        _ = parse_new_session_ticket(b)
    except:
        got_error = True
    assert_true(got_error, "truncated at ticket must raise")


# ============================================================================
# Test 7 — Zero-length ticket raises (ticket must be non-empty per RFC)
# ============================================================================

def test_zero_length_ticket_raises() raises:
    var b = List[UInt8]()
    b.append(0x00); b.append(0x00); b.append(0x00); b.append(0x01)
    b.append(0x00); b.append(0x00); b.append(0x00); b.append(0x01)
    b.append(0x00)   # nonce len = 0
    b.append(0x00); b.append(0x00)   # ticket len = 0 (invalid)
    b.append(0x00); b.append(0x00)   # extensions len = 0
    var got_error = False
    try:
        _ = parse_new_session_ticket(b)
    except:
        got_error = True
    assert_true(got_error, "zero-length ticket must raise")


# ============================================================================
# Test 8 — Ticket with extensions (extension data is skipped structurally)
# ============================================================================

def test_with_extensions() raises:
    var b = List[UInt8]()
    b.append(0x00); b.append(0x00); b.append(0x00); b.append(0x3C)  # lifetime = 60
    b.append(0x00); b.append(0x00); b.append(0x00); b.append(0x00)  # age_add = 0
    b.append(0x00)   # nonce len = 0
    # ticket: len=2, bytes=[0x01, 0x02]
    b.append(0x00); b.append(0x02); b.append(0x01); b.append(0x02)
    # extensions: len = 8 (one extension: type=0x0001, len=4, data=4 bytes)
    b.append(0x00); b.append(0x08)
    b.append(0x00); b.append(0x01)   # ext type
    b.append(0x00); b.append(0x04)   # ext len = 4
    b.append(0xAA); b.append(0xBB); b.append(0xCC); b.append(0xDD)

    var st = parse_new_session_ticket(b)
    assert_eq(len(st.ticket), 2, "ticket length")
    assert_eq(Int(st.lifetime_secs), 60, "lifetime")


# ============================================================================
# Test 9 — psk field is empty initially (set by connection layer)
# ============================================================================

def test_psk_initially_empty() raises:
    var body = _build_minimal_ticket_body()
    var st = parse_new_session_ticket(body)
    assert_eq(len(st.psk), 0, "psk initially empty")


# ============================================================================
# Test 10 — Large ticket (4 KB) parses without overflow
# ============================================================================

def test_large_ticket() raises:
    var big_ticket_len = 4096
    var b = List[UInt8]()
    b.append(0x00); b.append(0x01); b.append(0x51); b.append(0x80)  # lifetime = 86400
    b.append(0x00); b.append(0x00); b.append(0x00); b.append(0x00)  # age_add = 0
    b.append(0x00)   # nonce len = 0
    # ticket: 2-byte len + big_ticket_len bytes
    b.append(UInt8(big_ticket_len >> 8))
    b.append(UInt8(big_ticket_len & 0xFF))
    for i in range(big_ticket_len):
        b.append(UInt8(i & 0xFF))
    b.append(0x00); b.append(0x00)  # extensions len = 0

    var st = parse_new_session_ticket(b)
    assert_eq(len(st.ticket), big_ticket_len, "large ticket length")


# ============================================================================
# Main
# ============================================================================

def main() raises:
    var passed = 0
    var failed = 0

    print("=== Session Ticket Parser Tests ===")
    print()

    run_test("parse valid minimal ticket",       passed, failed, test_parse_valid_minimal)
    run_test("parse non-empty nonce",            passed, failed, test_parse_nonempty_nonce)
    run_test("truncated at lifetime",            passed, failed, test_truncated_at_lifetime)
    run_test("truncated at age_add",             passed, failed, test_truncated_at_age_add)
    run_test("truncated at nonce",               passed, failed, test_truncated_at_nonce)
    run_test("truncated at ticket",              passed, failed, test_truncated_at_ticket)
    run_test("zero-length ticket raises",        passed, failed, test_zero_length_ticket_raises)
    run_test("with extensions (skipped)",        passed, failed, test_with_extensions)
    run_test("psk initially empty",              passed, failed, test_psk_initially_empty)
    run_test("large ticket (4 KB)",              passed, failed, test_large_ticket)

    print()
    print("Results:", String(passed), "passed,", String(failed), "failed,", String(passed + failed), "total")
    if failed > 0:
        raise Error(String(failed) + " test(s) failed")
