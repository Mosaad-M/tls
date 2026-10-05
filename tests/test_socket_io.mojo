# ============================================================================
# test_socket_io.mojo — TLS 1.3 KeyUpdate and socket I/O robustness
# ============================================================================
# A socketpair(AF_UNIX, SOCK_STREAM) stands in for the TCP connection: the
# test plays the server on one end with crafted records and drives a
# TlsSocket with known keys on the other.
# ============================================================================

from std.ffi import external_call
from std.memory import alloc
from crypto.record import (
    record_seal, record_open,
    CIPHER_AES_128_GCM, CTYPE_ALERT, CTYPE_APPLICATION_DATA, CTYPE_HANDSHAKE,
)
from crypto.handshake import tls13_traffic_keys, tls13_next_traffic_secret
from tls.socket import TlsSocket


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


# ── socketpair plumbing ─────────────────────────────────────────────────────

struct Pair(Movable):
    var mine: Int32  # TlsSocket side
    var peer: Int32  # test "server" side

    def __init__(out self) raises:
        var fds = alloc[Int32](2)
        # AF_UNIX = 1, SOCK_STREAM = 1 on Linux and macOS
        var rc = external_call["socketpair", Int32](Int32(1), Int32(1), Int32(0), fds)
        if rc != 0:
            fds.unsafe_free()
            raise Error("socketpair failed")
        self.mine = fds[0]
        self.peer = fds[1]
        fds.unsafe_free()

    def close(self):
        _ = external_call["close", Int32](self.mine)
        _ = external_call["close", Int32](self.peer)


def _write(fd: Int32, data: List[UInt8]) raises:
    var n = len(data)
    var buf = alloc[UInt8](n)
    for i in range(n):
        buf[unsafe_offset=i] = data[i]
    var sent = external_call["write", Int](Int(fd), buf, n)
    buf.unsafe_free()
    if sent != n:
        raise Error("peer write failed")


def _read_exact(fd: Int32, n: Int) raises -> List[UInt8]:
    var buf = alloc[UInt8](n)
    var total = 0
    while total < n:
        var got = external_call["read", Int](fd, buf.unsafe_offset(total), n - total)
        if got <= 0:
            buf.unsafe_free()
            raise Error("peer read failed")
        total += got
    var out = List[UInt8](capacity=n)
    for i in range(n):
        out.append(buf[unsafe_offset=i])
    buf.unsafe_free()
    return out^


def _read_record(fd: Int32) raises -> List[UInt8]:
    var rec = _read_exact(fd, 5)
    var body = _read_exact(fd, (Int(rec[3]) << 8) | Int(rec[4]))
    for i in range(len(body)):
        rec.append(body[i])
    return rec^


# ── Keys ────────────────────────────────────────────────────────────────────

def _filled(n: Int, v: UInt8) -> List[UInt8]:
    var out = List[UInt8](capacity=n)
    for _ in range(n):
        out.append(v)
    return out^


def _bytes(s: String) -> List[UInt8]:
    var out = List[UInt8]()
    for b in s.as_bytes():
        out.append(b)
    return out^


def _server_secret() -> List[UInt8]:
    return _filled(32, 0x5A)


def _client_secret() -> List[UInt8]:
    return _filled(32, 0xC3)


struct Keys(Movable):
    var key: List[UInt8]
    var iv: List[UInt8]

    def __init__(out self, secret: List[UInt8]) raises:
        var kp = tls13_traffic_keys(secret, 16, 12)
        self.key = kp[0].copy()
        self.iv = kp[1].copy()


def _sock(fd: Int32) raises -> TlsSocket:
    var s = TlsSocket(fd)
    s._is12 = False
    s._keys.cipher = CIPHER_AES_128_GCM
    s._keys.use_sha384 = False
    s._keys.server_app_secret = _server_secret()
    s._keys.client_app_secret = _client_secret()
    var sk = Keys(_server_secret())
    var ck = Keys(_client_secret())
    s._keys.server_write_key = sk.key.copy()
    s._keys.server_write_iv = sk.iv.copy()
    s._keys.client_write_key = ck.key.copy()
    s._keys.client_write_iv = ck.iv.copy()
    return s^


def _key_update(request: UInt8) -> List[UInt8]:
    # HandshakeType key_update(24), uint24 length 1, KeyUpdateRequest
    var m: List[UInt8] = [24, 0, 0, 1]
    m.append(request)
    return m^


def _expect_error(mut s: TlsSocket, why: String) raises:
    var message = String()
    try:
        _ = s.recv(100)
    except e:
        message = String(e)
    if message.byte_length() == 0:
        raise Error("recv succeeded, expected error containing '" + why + "'")
    if message.find(why) < 0:
        raise Error("wrong error: '" + message + "' (expected '" + why + "')")


# ── KeyUpdate ───────────────────────────────────────────────────────────────

def test_key_update_not_requested() raises:
    var p = Pair()
    var s = _sock(p.mine)
    var old = Keys(_server_secret())
    var next_secret = tls13_next_traffic_secret(_server_secret(), False)
    var new = Keys(next_secret)
    _write(p.peer, record_seal(CIPHER_AES_128_GCM, old.key, old.iv, 0, CTYPE_APPLICATION_DATA, _bytes("before")))
    _write(p.peer, record_seal(CIPHER_AES_128_GCM, old.key, old.iv, 1, CTYPE_HANDSHAKE, _key_update(0)))
    # After the update the server's sequence number restarts at 0
    _write(p.peer, record_seal(CIPHER_AES_128_GCM, new.key, new.iv, 0, CTYPE_APPLICATION_DATA, _bytes("after")))
    var a = s.recv(100)
    var b = s.recv(100)
    p.close()
    if String(unsafe_from_utf8=a^) != "before":
        raise Error("first record wrong")
    if String(unsafe_from_utf8=b^) != "after":
        raise Error("record after KeyUpdate wrong")


def test_key_update_requested() raises:
    var p = Pair()
    var s = _sock(p.mine)
    var old = Keys(_server_secret())
    var new = Keys(tls13_next_traffic_secret(_server_secret(), False))
    _write(p.peer, record_seal(CIPHER_AES_128_GCM, old.key, old.iv, 0, CTYPE_HANDSHAKE, _key_update(1)))
    _write(p.peer, record_seal(CIPHER_AES_128_GCM, new.key, new.iv, 0, CTYPE_APPLICATION_DATA, _bytes("data")))
    var got = s.recv(100)
    if String(unsafe_from_utf8=got^) != "data":
        raise Error("record after KeyUpdate wrong")
    # The client must answer with KeyUpdate(update_not_requested) under its
    # old keys, then switch its own keys.
    var c_old = Keys(_client_secret())
    var reply = record_open(CIPHER_AES_128_GCM, c_old.key, c_old.iv, 0, _read_record(p.peer))
    if reply[0] != CTYPE_HANDSHAKE:
        raise Error("reply is not a handshake record")
    var want = _key_update(0)
    if len(reply[1]) != len(want):
        raise Error("reply is not a KeyUpdate")
    for i in range(len(want)):
        if reply[1][i] != want[i]:
            raise Error("reply is not KeyUpdate(update_not_requested)")
    _ = s.send(_bytes("hello"))
    var c_new = Keys(tls13_next_traffic_secret(_client_secret(), False))
    var sent = record_open(CIPHER_AES_128_GCM, c_new.key, c_new.iv, 0, _read_record(p.peer))
    p.close()
    if String(unsafe_from_utf8=sent[1].copy()) != "hello":
        raise Error("send after KeyUpdate not under the new client keys")


def test_key_update_bad_value() raises:
    var p = Pair()
    var s = _sock(p.mine)
    var old = Keys(_server_secret())
    _write(p.peer, record_seal(CIPHER_AES_128_GCM, old.key, old.iv, 0, CTYPE_HANDSHAKE, _key_update(2)))
    _expect_error(s, "illegal_parameter")
    p.close()


def test_key_update_bad_length() raises:
    var p = Pair()
    var s = _sock(p.mine)
    var old = Keys(_server_secret())
    var m: List[UInt8] = [24, 0, 0, 2, 0, 0]
    _write(p.peer, record_seal(CIPHER_AES_128_GCM, old.key, old.iv, 0, CTYPE_HANDSHAKE, m))
    _expect_error(s, "decode_error")
    p.close()


def test_key_update_not_last_in_record() raises:
    # Keys change at the record boundary, so nothing may follow KeyUpdate
    var p = Pair()
    var s = _sock(p.mine)
    var old = Keys(_server_secret())
    var m = _key_update(0)
    var extra = _key_update(0)
    for i in range(len(extra)):
        m.append(extra[i])
    _write(p.peer, record_seal(CIPHER_AES_128_GCM, old.key, old.iv, 0, CTYPE_HANDSHAKE, m))
    _expect_error(s, "unexpected_message")
    p.close()


# ── Timeouts and SIGPIPE ────────────────────────────────────────────────────

def test_read_timeout_is_resumable() raises:
    var p = Pair()
    var s = _sock(p.mine)
    s.set_timeout(1)
    var old = Keys(_server_secret())
    var rec = record_seal(CIPHER_AES_128_GCM, old.key, old.iv, 0, CTYPE_APPLICATION_DATA, _bytes("intact"))
    var first = List[UInt8]()
    var rest = List[UInt8]()
    for i in range(len(rec)):
        if i < 10:
            first.append(rec[i])
        else:
            rest.append(rec[i])
    _write(p.peer, first)
    _expect_error(s, "read timed out")
    _write(p.peer, rest)
    var got = s.recv(100)
    p.close()
    if String(unsafe_from_utf8=got^) != "intact":
        raise Error("record after a timeout was not reassembled")


def test_timeout_message_not_eof() raises:
    # requests treats "connection closed" as end of body; a timeout must not
    # look like that.
    var p = Pair()
    var s = _sock(p.mine)
    s.set_timeout(1)
    var message = String()
    try:
        _ = s.recv(100)
    except e:
        message = String(e)
    p.close()
    if message.find("timed out") < 0 or message.find("connection closed") >= 0:
        raise Error("timeout error: '" + message + "'")


def test_send_to_closed_peer_raises() raises:
    # Without SO_NOSIGPIPE / MSG_NOSIGNAL this write kills the process.
    var p = Pair()
    var s = _sock(p.mine)
    _ = external_call["close", Int32](p.peer)
    var message = String()
    try:
        for _ in range(4):
            _ = s.send(_bytes("x"))
    except e:
        message = String(e)
    _ = external_call["close", Int32](p.mine)
    if message.find("closed by peer") < 0:
        raise Error("send to a closed peer: '" + message + "'")
    # The socket is now unusable for writes
    var again = String()
    try:
        _ = s.send(_bytes("y"))
    except e:
        again = String(e)
    if again.find("broken") < 0:
        raise Error("send after a failed write: '" + again + "'")


def main() raises:
    var passed = 0
    var failed = 0

    print("=== Socket I/O / KeyUpdate Tests ===")
    print()

    run_test[test_key_update_not_requested]("KeyUpdate(update_not_requested)", passed, failed)
    run_test[test_key_update_requested]("KeyUpdate(update_requested) answered", passed, failed)
    run_test[test_key_update_bad_value]("KeyUpdate with request value 2", passed, failed)
    run_test[test_key_update_bad_length]("KeyUpdate with a 2-byte body", passed, failed)
    run_test[test_key_update_not_last_in_record]("KeyUpdate not last in its record", passed, failed)
    run_test[test_read_timeout_is_resumable]("read timeout mid-record is resumable", passed, failed)
    run_test[test_timeout_message_not_eof]("timeout is not reported as EOF", passed, failed)
    run_test[test_send_to_closed_peer_raises]("send to a closed peer raises (no SIGPIPE)", passed, failed)

    print()
    print("Results:", passed, "passed,", failed, "failed")
    if failed > 0:
        raise Error(String(failed) + " test(s) failed")
