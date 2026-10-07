# ============================================================================
# test_record_eof.mojo — post-handshake receive path: alerts and truncation
# ============================================================================
# Crafted records are sent through a socketpair whose other end then closes
# (end of stream = TCP close). TlsSocket gets known keys, so the
# tests drive the real _fill_buf / recv / recv_all code without a handshake.
# ============================================================================

from std.ffi import external_call
from crypto.record import (
    record_seal, record_seal_12, record_open,
    CIPHER_AES_128_GCM, CTYPE_ALERT, CTYPE_APPLICATION_DATA,
)
from tls.socket import TlsSocket
from sockpair import Pair, send_all



def run_test[test_fn: def() thin raises -> None](
    name: String,
    mut passed: Int,
    mut failed: Int,
):
    try:
        test_fn()
        print("  PASS:", name)
        passed += 1
    except e:
        print("  FAIL:", name, "-", String(e))
        failed += 1


# ── Stream helpers ──────────────────────────────────────────────────────────

def _stream_fd(data: List[UInt8]) raises -> Int32:
    """A socket that delivers data and then end of stream: the peer end of a
    socketpair sends it and closes (what tls then writes fails quietly)."""
    var p = Pair()
    send_all(p.peer, data)
    _ = external_call["close", Int32](p.peer)
    return p.mine


def _close_fd(fd: Int32):
    _ = external_call["close", Int32](fd)


def _bytes(s: String) -> List[UInt8]:
    var out = List[UInt8]()
    for b in s.as_bytes():
        out.append(b)
    return out^


def _filled(n: Int, v: UInt8) -> List[UInt8]:
    var out = List[UInt8](capacity=n)
    for _ in range(n):
        out.append(v)
    return out^


def _append(mut dst: List[UInt8], src: List[UInt8]):
    for i in range(len(src)):
        dst.append(src[i])


def _close_notify_body() -> List[UInt8]:
    var b = List[UInt8]()
    b.append(1)  # warning
    b.append(0)  # close_notify
    return b^


def _plain_record(ctype: UInt8, body: List[UInt8]) -> List[UInt8]:
    var r = List[UInt8]()
    r.append(ctype)
    r.append(0x03)
    r.append(0x03)
    r.append(UInt8((len(body) >> 8) & 0xFF))
    r.append(UInt8(len(body) & 0xFF))
    _append(r, body)
    return r^


# ── TLS 1.3 ─────────────────────────────────────────────────────────────────

def _key13() -> List[UInt8]:
    return _filled(16, 0x42)


def _iv13() -> List[UInt8]:
    return _filled(12, 0x24)


def _sock13(fd: Int32) -> TlsSocket:
    var s = TlsSocket(fd)
    s._keys.cipher = CIPHER_AES_128_GCM
    s._keys.server_write_key = _key13()
    s._keys.server_write_iv = _iv13()
    s._is12 = False
    return s^


def _rec13(seq: UInt64, ctype: UInt8, body: List[UInt8]) raises -> List[UInt8]:
    return record_seal(CIPHER_AES_128_GCM, _key13(), _iv13(), seq, ctype, body)


# ── TLS 1.2 ─────────────────────────────────────────────────────────────────

def _key12() -> List[UInt8]:
    return _filled(16, 0x51)


def _iv12() -> List[UInt8]:
    return _filled(4, 0x15)


def _sock12(fd: Int32) -> TlsSocket:
    var s = TlsSocket(fd)
    s._keys12.cipher = Int(CIPHER_AES_128_GCM)
    s._keys12.server_write_key = _key12()
    s._keys12.server_write_iv = _iv12()
    s._is12 = True
    return s^


def _rec12(seq: UInt64, ctype: UInt8, body: List[UInt8]) raises -> List[UInt8]:
    var payload = record_seal_12(CIPHER_AES_128_GCM, _key12(), _iv12(), seq, ctype, body)
    return _plain_record(ctype, payload)


# ── Assertions ──────────────────────────────────────────────────────────────

def _expect_bytes(got: List[UInt8], want: String) raises:
    var w = _bytes(want)
    if len(got) != len(w):
        raise Error("got " + String(len(got)) + " bytes, want " + String(len(w)))
    for i in range(len(w)):
        if got[i] != w[i]:
            raise Error("byte mismatch at " + String(i))


def _expect_recv_all_error(mut s: TlsSocket, why: String, allow_truncation: Bool = False) raises:
    var message = String()
    try:
        _ = s.recv_all(allow_truncation=allow_truncation)
    except e:
        message = String(e)
    if message.byte_length() == 0:
        raise Error("recv_all succeeded, expected error containing '" + why + "'")
    if message.find(why) < 0:
        raise Error("wrong error: '" + message + "' (expected '" + why + "')")


# ── Cases (each run for TLS 1.3 and TLS 1.2) ────────────────────────────────

def _stream(v12: Bool, records_after_data: List[UInt8]) raises -> List[UInt8]:
    var stream: List[UInt8]
    if v12:
        stream = _rec12(0, CTYPE_APPLICATION_DATA, _bytes("hello"))
    else:
        stream = _rec13(0, CTYPE_APPLICATION_DATA, _bytes("hello"))
    _append(stream, records_after_data)
    return stream^


def _sock(v12: Bool, fd: Int32) -> TlsSocket:
    if v12:
        return _sock12(fd)
    return _sock13(fd)


def _check_authenticated_close(v12: Bool) raises:
    var tail: List[UInt8]
    if v12:
        tail = _rec12(1, CTYPE_ALERT, _close_notify_body())
    else:
        tail = _rec13(1, CTYPE_ALERT, _close_notify_body())
    var fd = _stream_fd(_stream(v12, tail))
    var s = _sock(v12, fd)
    var got = s.recv_all()
    _close_fd(fd)
    _expect_bytes(got, "hello")
    if not s.close_notify_received():
        raise Error("close_notify_received() is False after an authenticated close_notify")


def _check_plaintext_close_rejected(v12: Bool) raises:
    var fd = _stream_fd(_stream(v12, _plain_record(CTYPE_ALERT, _close_notify_body())))
    var s = _sock(v12, fd)
    _expect_recv_all_error(s, "plaintext alert")
    _close_fd(fd)
    if s.close_notify_received():
        raise Error("close_notify_received() is True after a forged close_notify")


def _check_eof_without_close_notify(v12: Bool) raises:
    # recv_all: strict by default
    var fd = _stream_fd(_stream(v12, List[UInt8]()))
    var s = _sock(v12, fd)
    _expect_recv_all_error(s, "truncated")
    _close_fd(fd)
    # recv_all(allow_truncation=True): returns what arrived
    fd = _stream_fd(_stream(v12, List[UInt8]()))
    var s2 = _sock(v12, fd)
    var got = s2.recv_all(allow_truncation=True)
    _close_fd(fd)
    _expect_bytes(got, "hello")
    if s2.close_notify_received():
        raise Error("close_notify_received() is True after a bare EOF")
    # recv: the data, then an error that still says "connection closed"
    fd = _stream_fd(_stream(v12, List[UInt8]()))
    var s3 = _sock(v12, fd)
    _expect_bytes(s3.recv(100), "hello")
    var message = String()
    try:
        _ = s3.recv(100)
    except e:
        message = String(e)
    _close_fd(fd)
    if message.find("connection closed") < 0:
        raise Error("recv at EOF: '" + message + "' (expected 'connection closed')")


def _check_eof_mid_record(v12: Bool) raises:
    var next: List[UInt8]
    if v12:
        next = _rec12(1, CTYPE_APPLICATION_DATA, _bytes("world"))
    else:
        next = _rec13(1, CTYPE_APPLICATION_DATA, _bytes("world"))
    var cut = List[UInt8]()
    for i in range(len(next) - 3):
        cut.append(next[i])
    var fd = _stream_fd(_stream(v12, cut))
    var s = _sock(v12, fd)
    _expect_recv_all_error(s, "truncated record", allow_truncation=True)
    _close_fd(fd)


def test_13_authenticated_close() raises:
    _check_authenticated_close(False)


def test_12_authenticated_close() raises:
    _check_authenticated_close(True)


def test_13_plaintext_close_rejected() raises:
    _check_plaintext_close_rejected(False)


def test_12_plaintext_close_rejected() raises:
    _check_plaintext_close_rejected(True)


def test_13_eof_without_close_notify() raises:
    _check_eof_without_close_notify(False)


def test_12_eof_without_close_notify() raises:
    _check_eof_without_close_notify(True)


def test_13_eof_mid_record() raises:
    _check_eof_mid_record(False)


def test_12_eof_mid_record() raises:
    _check_eof_mid_record(True)


def test_12_corrupt_alert_is_bad_record_mac() raises:
    var alert = _rec12(1, CTYPE_ALERT, _close_notify_body())
    alert[len(alert) - 1] ^= 0x01  # flip a tag bit
    var fd = _stream_fd(_stream(True, alert))
    var s = _sock12(fd)
    _expect_recv_all_error(s, "bad_record_mac")
    _close_fd(fd)


def test_13_padded_record() raises:
    # inner plaintext = "hello" || 0x17 || 00 00 00 (RFC 8446 §5.4 padding)
    var body = _bytes("hello")
    body.append(CTYPE_APPLICATION_DATA)
    _append(body, _filled(3, 0))
    var stream = _rec13(0, 0x00, body)  # record_seal appends the final 0x00
    _append(stream, _rec13(1, CTYPE_ALERT, _close_notify_body()))
    var fd = _stream_fd(stream)
    var s = _sock13(fd)
    var got = s.recv_all()
    _close_fd(fd)
    _expect_bytes(got, "hello")


def test_13_all_zero_inner_plaintext() raises:
    var rec = _rec13(0, 0x00, _filled(4, 0))
    var raised = False
    try:
        _ = record_open(CIPHER_AES_128_GCM, _key13(), _iv13(), 0, rec)
    except:
        raised = True
    if not raised:
        raise Error("record_open accepted an inner plaintext with no content type")


def main() raises:
    var passed = 0
    var failed = 0

    print("=== Record Receive / Truncation Tests ===")
    print()

    run_test[test_13_authenticated_close]("1.3: encrypted close_notify ends recv_all", passed, failed)
    run_test[test_12_authenticated_close]("1.2: encrypted close_notify ends recv_all", passed, failed)
    run_test[test_13_plaintext_close_rejected]("1.3: plaintext close_notify rejected", passed, failed)
    run_test[test_12_plaintext_close_rejected]("1.2: plaintext close_notify rejected", passed, failed)
    run_test[test_13_eof_without_close_notify]("1.3: EOF without close_notify", passed, failed)
    run_test[test_12_eof_without_close_notify]("1.2: EOF without close_notify", passed, failed)
    run_test[test_13_eof_mid_record]("1.3: EOF mid-record", passed, failed)
    run_test[test_12_eof_mid_record]("1.2: EOF mid-record", passed, failed)
    run_test[test_12_corrupt_alert_is_bad_record_mac]("1.2: corrupt encrypted alert", passed, failed)
    run_test[test_13_padded_record]("1.3: padded record", passed, failed)
    run_test[test_13_all_zero_inner_plaintext]("1.3: all-zero inner plaintext", passed, failed)

    print()
    print("Results:", passed, "passed,", failed, "failed")
    if failed > 0:
        raise Error(String(failed) + " test(s) failed")
