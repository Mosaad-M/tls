# ============================================================================
# tls/socket.mojo — TlsSocket: TCP fd wrapper with TLS 1.3 + TLS 1.2 support
# ============================================================================
# API:
#   def load_system_ca_bundle() raises -> List[X509Cert]
#       Reads /etc/ssl/certs/ca-certificates.crt, parses all CERTIFICATE blocks.
#
#   struct TlsSocket(Movable):
#       def __init__(out self, tcp_fd: Int32 = 0)
#       def connect(mut self, hostname: String, trust_anchors: List[X509Cert]) raises
#           Auto-negotiates TLS 1.3 or TLS 1.2 based on server's ServerHello.
#       def send(mut self, data: List[UInt8]) raises -> Int
#       def recv(mut self, max_bytes: Int) raises -> List[UInt8]
#       def recv_all(mut self, max_size: Int = 16*1024*1024) raises -> List[UInt8]
#       def close(mut self) raises
# ============================================================================

from std.ffi import external_call
from std.memory.unsafe_pointer import alloc
from crypto.cert import X509Cert, cert_parse
from crypto.pem import pem_decode
from crypto.hash import SHA256, SHA384
from crypto.random import csprng_bytes
from crypto.curve25519 import x25519_public_key
from crypto.record import (
    record_seal, record_open,
    record_seal_12, record_open_12,
    CIPHER_AES_128_GCM, CIPHER_AES_256_GCM,
    CTYPE_APPLICATION_DATA, CTYPE_CHANGE_CIPHER_SPEC, CTYPE_ALERT, CTYPE_HANDSHAKE,
)
from tls.connection import (
    tls13_after_server_hello, tls_cipher_from_suite, TlsKeys,
    tls_tcp_read, tls_tcp_write,
    tls_handle_incoming_alert,
    ALERT_LEVEL_WARNING, ALERT_CLOSE_NOTIFY,
)
from tls.connection12 import (
    tls12_client_handshake, TlsKeys12,
)
from tls.message import (
    build_client_hello, parse_handshake_msg,
    parse_new_session_ticket, SessionTicket,
    HS_SERVER_HELLO, HS_NEW_SESSION_TICKET,
)
from crypto.handshake import tls13_psk_from_ticket
from tls.message12 import parse_server_hello_version


# ── Internal helpers ────────────────────────────────────────────────────────────

def _sock_append_bytes(mut out: List[UInt8], src: List[UInt8]):
    out.reserve(len(out) + len(src))
    for i in range(len(src)):
        out.append(src[i])


def _sock_contains(haystack: String, needle: String) -> Bool:
    """Check if haystack contains needle (simple byte search)."""
    var h = haystack.as_bytes()
    var n = needle.as_bytes()
    var h_len = len(h)
    var n_len = len(n)
    if n_len > h_len:
        return False
    for i in range(h_len - n_len + 1):
        var ok = True
        for j in range(n_len):
            if h[i + j] != n[j]:
                ok = False
                break
        if ok:
            return True
    return False


def _sock_wrap_hs_msg(msg_type: UInt8, body: List[UInt8]) -> List[UInt8]:
    """Wrap handshake body in type+length header for transcript."""
    var out = List[UInt8](capacity=4 + len(body))
    out.append(msg_type)
    var n = len(body)
    out.append(UInt8((n >> 16) & 0xFF))
    out.append(UInt8((n >> 8) & 0xFF))
    out.append(UInt8(n & 0xFF))
    for i in range(n):
        out.append(body[i])
    return out^


# ============================================================================
# load_system_ca_bundle
# ============================================================================

def load_system_ca_bundle() raises -> List[X509Cert]:
    """Load trusted CA certificates from the system CA bundle.

    Reads /etc/ssl/certs/ca-certificates.crt (Debian/Ubuntu/WSL),
    PEM-decodes all CERTIFICATE blocks, and cert_parses each one.
    Silently skips certs that fail to parse.
    """
    var path = String("/etc/ssl/certs/ca-certificates.crt")
    var O_RDONLY: Int32 = 0
    var fd = external_call["open", Int32](path.unsafe_ptr(), O_RDONLY)
    if fd < 0:
        raise Error("load_system_ca_bundle: cannot open " + path)

    # CA bundles are typically 200-400 KB; allocate 2 MB to be safe
    var buf_size = 2097152
    var buf = alloc[UInt8](buf_size)
    var total: Int = 0
    while total < buf_size:
        var got = external_call["read", Int](fd, buf + total, buf_size - total)
        if got <= 0:
            break
        total += got
    _ = external_call["close", Int32](fd)

    # Collect into List[UInt8], then convert to String
    var raw = List[UInt8](capacity=total)
    for i in range(total):
        raw.append((buf + i)[])
    buf.free()
    var content = String(unsafe_from_utf8=raw^)

    # Decode all PEM CERTIFICATE blocks
    var ders = pem_decode(content, "CERTIFICATE")

    var certs = List[X509Cert]()
    for i in range(len(ders)):
        try:
            certs.append(cert_parse(ders[i]))
        except:
            pass  # skip unparseable entries

    return certs^


# ============================================================================
# TlsSocket
# ============================================================================

struct TlsSocket(Movable):
    """TCP socket wrapper providing TLS 1.3 or TLS 1.2 record-layer send/recv.

    Auto-negotiates TLS version in connect(). Buffers decrypted application
    bytes across TLS records so that small reads work correctly.
    """

    var _fd:     Int32
    var _keys:   TlsKeys    # TLS 1.3 keying material (used when _is12=False)
    var _keys12: TlsKeys12  # TLS 1.2 keying material (used when _is12=True)
    var _buf:    List[UInt8] # buffered decrypted application bytes
    var _is12:   Bool        # True if TLS 1.2 was negotiated

    def __init__(out self, tcp_fd: Int32 = 0):
        self._fd     = tcp_fd
        self._keys   = TlsKeys()
        self._keys12 = TlsKeys12()
        self._buf    = List[UInt8]()
        self._is12   = False

    def __moveinit__(out self, deinit take: Self):
        self._fd     = take._fd
        self._keys   = take._keys^
        self._keys12 = take._keys12^
        self._buf    = take._buf^
        self._is12   = take._is12

    def connect(mut self, hostname: String, trust_anchors: List[X509Cert]) raises:
        """Perform TLS handshake, auto-negotiating TLS 1.3 or TLS 1.2."""

        # ── Generate ECDHE key pair + client_random ───────────────────────────
        var ecdhe_private = csprng_bytes(32)
        var key_share_pub = x25519_public_key(ecdhe_private)
        var client_random = csprng_bytes(32)

        # ── Build + send ClientHello (unified TLS 1.3 + 1.2 cipher suites) ───
        var ch_msg = build_client_hello(client_random, List[UInt8](), key_share_pub, hostname)

        # ClientHello record uses legacy version 0x0301 for compatibility
        var ch_n = len(ch_msg)
        var ch_record = List[UInt8](capacity=5 + ch_n)
        ch_record.append(0x16)  # content_type = Handshake
        ch_record.append(0x03)
        ch_record.append(0x01)  # legacy version
        ch_record.append(UInt8((ch_n >> 8) & 0xFF))
        ch_record.append(UInt8(ch_n & 0xFF))
        _sock_append_bytes(ch_record, ch_msg)
        tls_tcp_write(self._fd, ch_record)

        # Initialize both transcript hashers
        var th    = SHA256()
        var th384 = SHA384()
        th.update(ch_msg)
        th384.update(ch_msg)

        # ── Read ServerHello (skip any leading CCS) ───────────────────────────
        var sh_rec_type: UInt8
        var sh_rec_body: List[UInt8]

        while True:
            var header = tls_tcp_read(self._fd, 5)
            var rtype = header[0]
            var rlen = (Int(header[3]) << 8) | Int(header[4])
            var rbody = tls_tcp_read(self._fd, rlen)
            if rtype == CTYPE_CHANGE_CIPHER_SPEC:
                continue
            if rtype == CTYPE_ALERT:
                tls_handle_incoming_alert(rbody)
                raise Error("tls: alert before ServerHello")
            sh_rec_type = rtype
            sh_rec_body = rbody^
            break

        if sh_rec_type != CTYPE_HANDSHAKE:
            raise Error("tls: expected Handshake record for ServerHello, got "
                        + String(Int(sh_rec_type)))

        # ── Parse ServerHello handshake message ───────────────────────────────
        var sh_parse  = parse_handshake_msg(sh_rec_body, 0)
        var sh_msg    = sh_parse[0].copy()
        if sh_msg.msg_type != HS_SERVER_HELLO:
            raise Error("tls: expected ServerHello (0x02), got "
                        + String(Int(sh_msg.msg_type)))

        # Update transcript with the full ServerHello handshake message
        var sh_full = _sock_wrap_hs_msg(HS_SERVER_HELLO, sh_msg.body)
        th.update(sh_full)
        th384.update(sh_full)

        # ── Determine TLS version ─────────────────────────────────────────────
        var sv = parse_server_hello_version(sh_msg.body)
        var cipher_suite = sv[0]
        var server_random = sv[1].copy()
        var use_tls13 = sv[3]

        if use_tls13:
            # ── TLS 1.3 path ──────────────────────────────────────────────────
            try:
                self._keys = tls13_after_server_hello(
                    self._fd, hostname, trust_anchors,
                    ecdhe_private, sh_msg.body, th, th384,
                )
                self._is12 = False
            except e:
                self._is12 = False  # ensure flag is consistent on failure
                raise Error(String(e))
        else:
            # ── TLS 1.2 path ──────────────────────────────────────────────────
            var use_sha384 = (cipher_suite == 0xC030 or cipher_suite == 0xC02C)
            try:
                self._keys12 = tls12_client_handshake(
                    self._fd, hostname, trust_anchors,
                    client_random, server_random, cipher_suite,
                    th, th384, use_sha384,
                )
                self._is12 = True
            except e:
                self._is12 = False  # reset to safe state on handshake failure
                raise Error(String(e))

    def send(mut self, data: List[UInt8]) raises -> Int:
        """Encrypt data as a TLS ApplicationData record and write to socket."""
        if len(data) > 16384:
            raise Error("tls: send: plaintext exceeds TLS record limit (16384 bytes)")
        if self._is12:
            var payload = record_seal_12(
                UInt8(self._keys12.cipher),
                self._keys12.client_write_key,
                self._keys12.client_write_iv,
                self._keys12.client_seqno,
                CTYPE_APPLICATION_DATA,
                data,
            )
            # Build full TLS 1.2 record: 5-byte header + payload
            var record = List[UInt8](capacity=5 + len(payload))
            record.append(CTYPE_APPLICATION_DATA)
            record.append(0x03)
            record.append(0x03)
            record.append(UInt8((len(payload) >> 8) & 0xFF))
            record.append(UInt8(len(payload) & 0xFF))
            _sock_append_bytes(record, payload)
            tls_tcp_write(self._fd, record)
            if self._keys12.client_seqno >= UInt64(4611686018427387904):
                raise Error("tls: client sequence number overflow")
            self._keys12.client_seqno += 1
        else:
            var sealed = record_seal(
                self._keys.cipher,
                self._keys.client_write_key,
                self._keys.client_write_iv,
                self._keys.client_seqno,
                CTYPE_APPLICATION_DATA,
                data,
            )
            tls_tcp_write(self._fd, sealed)
            if self._keys.client_seqno >= (UInt64(1) << 62):
                raise Error("tls: client sequence number overflow")
            self._keys.client_seqno += 1
        return len(data)

    def _fill_buf_12(mut self) raises:
        """Read and decrypt one TLS 1.2 record, appending plaintext to _buf."""
        while True:
            var header = tls_tcp_read(self._fd, 5)
            var rtype = header[0]
            var rlen = (Int(header[3]) << 8) | Int(header[4])
            if rlen < 8 + 16:  # must have at least explicit_nonce + tag
                # Could be a short alert — read and handle
                var rbody = tls_tcp_read(self._fd, rlen)
                if rtype == CTYPE_CHANGE_CIPHER_SPEC:
                    continue
                if rtype == CTYPE_ALERT and rlen >= 2:
                    tls_handle_incoming_alert(rbody)
                raise Error("tls12_socket: record too short: " + String(rlen))
            if rlen > 16640:
                raise Error("tls12_socket: record too large: " + String(rlen))
            var rbody = tls_tcp_read(self._fd, rlen)

            if rtype == CTYPE_CHANGE_CIPHER_SPEC:
                continue

            if rtype == CTYPE_ALERT:
                # Post-handshake alerts are encrypted
                try:
                    var plain = record_open_12(
                        UInt8(self._keys12.cipher),
                        self._keys12.server_write_key,
                        self._keys12.server_write_iv,
                        self._keys12.server_seqno,
                        rtype, rbody,
                    )
                    self._keys12.server_seqno += 1
                    tls_handle_incoming_alert(plain)
                except e:
                    if _sock_contains(String(e), "close_notify"):
                        raise Error(String(e))
                    # Decryption failed — try as plaintext
                    tls_handle_incoming_alert(rbody)
                raise Error("tls12_socket: alert (unreachable)")

            if rtype != CTYPE_APPLICATION_DATA:
                continue  # skip unexpected record types

            var plain = record_open_12(
                UInt8(self._keys12.cipher),
                self._keys12.server_write_key,
                self._keys12.server_write_iv,
                self._keys12.server_seqno,
                rtype, rbody,
            )
            if self._keys12.server_seqno >= UInt64(4611686018427387904):
                raise Error("tls: server sequence number overflow")
            self._keys12.server_seqno += 1
            _sock_append_bytes(self._buf, plain)
            return  # one record successfully decrypted

    def _fill_buf(mut self) raises:
        """Read and decrypt one TLS ApplicationData record, appending plaintext to _buf.

        Raises "tls: close_notify" on clean shutdown.
        Skips ChangeCipherSpec and non-ApplicationData records silently.
        """
        if self._is12:
            self._fill_buf_12()
            return

        while True:
            # Read 5-byte TLS record header
            var header = tls_tcp_read(self._fd, 5)
            var rtype = header[0]
            var rlen = (Int(header[3]) << 8) | Int(header[4])
            if rlen > 16640:
                raise Error("tls_socket: recv record too large: " + String(rlen))
            var rbody = tls_tcp_read(self._fd, rlen)

            if rtype == CTYPE_CHANGE_CIPHER_SPEC:
                continue

            if rtype == CTYPE_ALERT:
                tls_handle_incoming_alert(rbody)
                raise Error("tls_socket: alert (unreachable)")

            if rtype != CTYPE_APPLICATION_DATA:
                continue  # skip unexpected record types

            # Reconstruct full record for record_open
            var full_record = List[UInt8](capacity=5 + rlen)
            full_record.append(rtype)
            full_record.append(header[1])
            full_record.append(header[2])
            full_record.append(header[3])
            full_record.append(header[4])
            _sock_append_bytes(full_record, rbody)

            var decrypted = record_open(
                self._keys.cipher,
                self._keys.server_write_key,
                self._keys.server_write_iv,
                self._keys.server_seqno,
                full_record,
            )
            if self._keys.server_seqno >= (UInt64(1) << 62):
                raise Error("tls: server sequence number overflow")
            self._keys.server_seqno += 1

            var inner_type = decrypted[0]
            var plaintext  = decrypted[1].copy()

            if inner_type == CTYPE_ALERT:
                tls_handle_incoming_alert(plaintext)
                raise Error("tls_socket: alert (unreachable)")

            if inner_type == CTYPE_HANDSHAKE:
                # Post-handshake messages: parse and collect NewSessionTicket
                var pos = 0
                while pos < len(plaintext):
                    try:
                        var hs = parse_handshake_msg(plaintext, pos)
                        var msg = hs[0]
                        pos = hs[1]
                        if msg.msg_type == HS_NEW_SESSION_TICKET:
                            try:
                                var ticket = parse_new_session_ticket(msg.body)
                                ticket.psk = tls13_psk_from_ticket(
                                    self._keys.resumption_secret, ticket.nonce
                                )
                                self._keys.session_tickets.append(ticket^)
                            except:
                                pass  # malformed ticket — ignore, do not abort
                    except:
                        break  # incomplete message — stop parsing
                continue

            if inner_type != CTYPE_APPLICATION_DATA:
                continue  # other post-handshake types

            _sock_append_bytes(self._buf, plaintext)
            return  # one record successfully read

    def recv(mut self, max_bytes: Int) raises -> List[UInt8]:
        """Read up to max_bytes of decrypted application data.

        Buffers data across TLS records so multiple small reads work correctly.
        If buffer is empty, reads the next TLS record to refill it.
        """
        if len(self._buf) == 0:
            self._fill_buf()
        var give = len(self._buf)
        if give > max_bytes:
            give = max_bytes
        var out = List[UInt8](capacity=give)
        for i in range(give):
            out.append(self._buf[i])
        # Consume give bytes from front of buffer
        var remaining = len(self._buf) - give
        if remaining == 0:
            self._buf = List[UInt8]()
        else:
            var new_buf = List[UInt8](capacity=remaining)
            for i in range(give, len(self._buf)):
                new_buf.append(self._buf[i])
            self._buf = new_buf^
        return out^

    def recv_exact(mut self, n: Int) raises -> List[UInt8]:
        """Read exactly n decrypted bytes, looping recv() until done.

        Raises:
            Error if connection closes before n bytes are received.
        """
        var result = List[UInt8](capacity=n)
        while len(result) < n:
            var chunk = self.recv(n - len(result))
            if len(chunk) == 0:
                raise Error(
                    "tls: connection closed after "
                    + String(len(result))
                    + " of "
                    + String(n)
                    + " bytes"
                )
            for i in range(len(chunk)):
                result.append(chunk[i])
        return result^

    def recv_all(mut self, max_size: Int = 16777216) raises -> List[UInt8]:
        """Read all ApplicationData until server closes connection (close_notify or TCP close).

        Loops recv(), accumulates bytes. Stops when:
          - close_notify alert is received (clean shutdown) → return data
          - TCP connection closed → return data accumulated so far
          - max_size exceeded → raises

        Re-raises unexpected errors (non-close alerts, etc.).
        """
        var result = List[UInt8]()
        # Drain any already-buffered bytes first
        _sock_append_bytes(result, self._buf)
        self._buf = List[UInt8]()
        # Read records until connection closes
        while True:
            try:
                self._fill_buf()
                _sock_append_bytes(result, self._buf)
                self._buf = List[UInt8]()
                if len(result) > max_size:
                    raise Error("tls: recv_all exceeded max_size")
            except e:
                var err_str = String(e)
                if _sock_contains(err_str, "close_notify"):
                    break
                if _sock_contains(err_str, "connection closed"):
                    break
                raise Error(err_str)
        return result^

    def close(mut self) raises:
        """Send close_notify alert and close the TCP socket."""
        if self._is12:
            if len(self._keys12.client_write_key) > 0:
                var alert_body = List[UInt8](capacity=2)
                alert_body.append(ALERT_LEVEL_WARNING)
                alert_body.append(ALERT_CLOSE_NOTIFY)
                var payload = record_seal_12(
                    UInt8(self._keys12.cipher),
                    self._keys12.client_write_key,
                    self._keys12.client_write_iv,
                    self._keys12.client_seqno,
                    CTYPE_ALERT,
                    alert_body,
                )
                var record = List[UInt8](capacity=5 + len(payload))
                record.append(CTYPE_ALERT)
                record.append(0x03)
                record.append(0x03)
                record.append(UInt8((len(payload) >> 8) & 0xFF))
                record.append(UInt8(len(payload) & 0xFF))
                _sock_append_bytes(record, payload)
                try:
                    tls_tcp_write(self._fd, record)
                except:
                    pass
        else:
            if len(self._keys.client_write_key) > 0:
                var alert_body = List[UInt8](capacity=2)
                alert_body.append(ALERT_LEVEL_WARNING)
                alert_body.append(ALERT_CLOSE_NOTIFY)
                var sealed = record_seal(
                    self._keys.cipher,
                    self._keys.client_write_key,
                    self._keys.client_write_iv,
                    self._keys.client_seqno,
                    CTYPE_ALERT,
                    alert_body,
                )
                try:
                    tls_tcp_write(self._fd, sealed)
                except:
                    pass
        _ = external_call["close", Int32](self._fd)

    def session_tickets(self) -> List[SessionTicket]:
        """Return copies of NewSessionTicket records received from the server.

        Tickets are collected transparently during recv() calls.
        Returns an empty list for TLS 1.2 connections or when no tickets arrived.
        """
        if self._is12:
            return List[SessionTicket]()
        return self._keys.session_tickets.copy()
