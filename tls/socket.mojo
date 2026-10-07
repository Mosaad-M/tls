# ============================================================================
# tls/socket.mojo — TlsSocket: TCP fd wrapper with TLS 1.3 + TLS 1.2 support
# ============================================================================
# API:
#   def load_system_ca_bundle() raises -> List[X509Cert]
#       Reads /etc/ssl/certs/ca-certificates.crt, parses all CERTIFICATE blocks.
#
#   struct TlsSocket(Movable):
#       def __init__(out self, tcp_fd: Int32 = 0)
#       def connect(mut self, hostname: String, trust_anchors: List[X509Cert],
#                   alpn_protocols: List[String] = []) raises
#           Auto-negotiates TLS 1.3 or TLS 1.2 based on server's ServerHello.
#       def negotiated_protocol(self) -> String
#           Returns ALPN protocol selected by the server, or "" if not negotiated.
#       def send(mut self, data: List[UInt8]) raises -> Int
#       def recv(mut self, max_bytes: Int) raises -> List[UInt8]
#       def recv_all(mut self, max_size: Int = 16*1024*1024,
#                    allow_truncation: Bool = False) raises -> List[UInt8]
#           Reads until an authenticated close_notify; a bare TCP close
#           raises "tls: truncated: ..." unless allow_truncation is True.
#       def close_notify_received(self) -> Bool
#       def set_timeout(mut self, seconds: Int) raises
#           Read timeouts raise "tls: read timed out" and can be retried.
#       def close(mut self) raises
# ============================================================================

from std.ffi import external_call
from std.sys.info import CompilationTarget
from crypto.cert import X509Cert, cert_parse
from crypto.pem import pem_decode
from crypto.hash import SHA256, SHA384
from crypto.random import csprng_bytes
from crypto.curve25519 import x25519_public_key
from crypto.record import (
    record_seal, record_open,
    record_seal_12, record_open_12,
    AeadKey, record_seal_k, record_open_k, record_seal_12_k, record_open_12_k,
    CIPHER_AES_128_GCM, CIPHER_AES_256_GCM,
    CTYPE_APPLICATION_DATA, CTYPE_CHANGE_CIPHER_SPEC, CTYPE_ALERT, CTYPE_HANDSHAKE,
)
from tls.connection import (
    tls13_after_server_hello, tls_cipher_from_suite, TlsKeys,
    tls_tcp_read, tls_tcp_write, tls_read_some, tls_prepare_fd, tls_set_timeout,
    tls_handle_incoming_alert, tls_send_plaintext_alert, tls_ec_keypair, HandshakeReader,
    ALERT_LEVEL_WARNING, ALERT_LEVEL_FATAL, ALERT_CLOSE_NOTIFY,
)
from tls.connection12 import (
    tls12_client_handshake, tls12_client_handshake_mtls, TlsKeys12,
)
from tls.message import (
    build_client_hello, parse_handshake_msg, parse_server_hello,
    parse_new_session_ticket, SessionTicket, HandshakeMsg,
    is_hello_retry_request, parse_hello_retry_request, hrr_message_hash,
    HS_SERVER_HELLO, HS_NEW_SESSION_TICKET, GROUP_X25519,
)
from crypto.handshake import (
    tls13_psk_from_ticket, tls13_next_traffic_secret,
    tls13_traffic_keys, tls13_traffic_keys_sha384,
)
from tls.message12 import (
    parse_server_hello_version, check_downgrade_sentinel, parse_server_hello_tls12_exts,
)

comptime _ALERT_UNEXPECTED_MESSAGE : UInt8 = 10
comptime _HS_KEY_UPDATE : UInt8 = 24
comptime _MAX_TICKETS = 8
comptime _RX_CHUNK = 18432  # > one maximal record (5 + 16640)
comptime _ALERT_ILLEGAL_PARAMETER  : UInt8 = 47

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

    macOS: /etc/ssl/cert.pem
    Linux: /etc/ssl/certs/ca-certificates.crt
    PEM-decodes all CERTIFICATE blocks, and cert_parses each one.
    Silently skips certs that fail to parse.
    """
    comptime CA_BUNDLE = "/etc/ssl/cert.pem" if CompilationTarget.is_macos() else "/etc/ssl/certs/ca-certificates.crt"
    var path = String(CA_BUNDLE)
    var raw: List[UInt8]
    try:
        with open(path, "r") as f:
            raw = f.read_bytes()
    except:
        raise Error("load_system_ca_bundle: cannot open " + path)
    # Not validated as UTF-8 (read() would be): only the ASCII PEM blocks
    # matter, and a stray byte in a comment must not lose the whole bundle
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
    var _close_notify: Bool  # True once an authenticated close_notify arrived
    var _rx:     List[UInt8] # raw bytes received but not yet a whole record
    var _broken: Bool        # a record write failed part-way; no more sends
    var _failed: String      # first fatal receive error; later calls re-raise it
    var _hs_rx:  List[UInt8] # post-handshake handshake bytes awaiting reassembly
    var _key_update_after: UInt64  # client records per key before a KeyUpdate
    var _seal_ak: AeadKey    # prepared record keys, reused across records
    var _open_ak: AeadKey

    def __init__(out self, tcp_fd: Int32 = 0):
        self._fd     = tcp_fd
        self._keys   = TlsKeys()
        self._keys12 = TlsKeys12()
        self._buf    = List[UInt8]()
        self._is12   = False
        self._close_notify = False
        self._rx     = List[UInt8]()
        self._broken = False
        self._failed = String("")
        self._hs_rx  = List[UInt8]()
        # RFC 8446 §5.5: AES-GCM keys must change before ~2^24.5 records
        self._key_update_after = UInt64(1) << 24
        self._seal_ak = AeadKey()
        self._open_ak = AeadKey()
        if tcp_fd > 0:
            tls_prepare_fd(tcp_fd)

    def __moveinit__(out self, deinit take: Self):
        self._fd     = take._fd
        self._keys   = take._keys^
        self._keys12 = take._keys12^
        self._buf    = take._buf^
        self._is12   = take._is12
        self._close_notify = take._close_notify
        self._rx     = take._rx^
        self._broken = take._broken
        self._failed = take._failed^
        self._hs_rx  = take._hs_rx^
        self._key_update_after = take._key_update_after
        self._seal_ak = take._seal_ak^
        self._open_ak = take._open_ak^

    def connect(
        mut self,
        hostname:       String,
        trust_anchors:  List[X509Cert],
        alpn_protocols: List[String] = List[String](),
    ) raises:
        """Perform TLS handshake, auto-negotiating TLS 1.3 or TLS 1.2.

        alpn_protocols: optional ALPN protocol names (e.g. ["h2", "http/1.1"]).
        After a successful handshake, call negotiated_protocol() to read the
        server's selection. Returns "" if ALPN was not advertised or not echoed.
        """

        # ── Generate ECDHE key pair + client_random ───────────────────────────
        var ecdhe_private = csprng_bytes(32)
        var key_share_pub = x25519_public_key(ecdhe_private)
        var client_random = csprng_bytes(32)

        # ── Build + send ClientHello (unified TLS 1.3 + 1.2 cipher suites) ───
        var ch_msg = build_client_hello(client_random, List[UInt8](), key_share_pub, hostname, alpn_protocols)
        tls_prepare_fd(self._fd)
        self._send_handshake_plain(ch_msg, 0x01)  # ClientHello record: legacy version 0x0301

        # Initialize both transcript hashers
        var th    = SHA256()
        var th384 = SHA384()
        th.update(ch_msg)
        th384.update(ch_msg)

        var reader = HandshakeReader(self._fd, True)
        var sh_msg = reader.expect(HS_SERVER_HELLO, "ServerHello")
        var key_share_group = GROUP_X25519
        var hrr_cipher: UInt16 = 0

        # ── HelloRetryRequest (RFC 8446 §4.1.4) ───────────────────────────────
        if is_hello_retry_request(parse_server_hello(sh_msg.body).random):
            var cookie: List[UInt8]
            try:
                var hrr = parse_hello_retry_request(sh_msg.body)
                hrr_cipher = hrr.cipher_suite
                key_share_group = hrr.selected_group
                cookie = hrr.cookie.copy()
            except e:
                tls_send_plaintext_alert(self._fd, _ALERT_ILLEGAL_PARAMETER)
                raise e^
            # ClientHello1 is replaced in the transcript by message_hash(CH1)
            th = SHA256()
            th384 = SHA384()
            th.update(hrr_message_hash(ch_msg, False))
            th384.update(hrr_message_hash(ch_msg, True))
            var hrr_full = _sock_wrap_hs_msg(HS_SERVER_HELLO, sh_msg.body)
            th.update(hrr_full)
            th384.update(hrr_full)

            # The server cannot send its ServerHello before ClientHello2
            reader.require_boundary("HelloRetryRequest")
            # ClientHello2: same random, the server's cookie, and a key share
            # for the group the server selected; a cookie-only HRR keeps the
            # X25519 share unchanged (RFC 8446 §4.1.2)
            var ch2_share = key_share_pub.copy()
            if key_share_group != GROUP_X25519:
                var kp = tls_ec_keypair(key_share_group)
                ecdhe_private = kp[0].copy()
                ch2_share = kp[1].copy()
            var ch2 = build_client_hello(
                client_random, List[UInt8](), ch2_share, hostname,
                alpn_protocols, key_share_group, cookie,
            )
            self._send_handshake_plain(ch2, 0x03)
            th.update(ch2)
            th384.update(ch2)

            sh_msg = reader.expect(HS_SERVER_HELLO, "ServerHello")
            if is_hello_retry_request(parse_server_hello(sh_msg.body).random):
                tls_send_plaintext_alert(self._fd, _ALERT_UNEXPECTED_MESSAGE)
                raise Error("tls: second HelloRetryRequest (unexpected_message)")

        # Update transcript with the full ServerHello handshake message
        var sh_full = _sock_wrap_hs_msg(HS_SERVER_HELLO, sh_msg.body)
        th.update(sh_full)
        th384.update(sh_full)

        # ── Determine TLS version ─────────────────────────────────────────────
        var sv = parse_server_hello_version(sh_msg.body)
        var cipher_suite = sv[0]
        var server_random = sv[1].copy()
        var use_tls13 = sv[3]

        if hrr_cipher != 0 and (not use_tls13 or cipher_suite != hrr_cipher):
            # After a HelloRetryRequest the ServerHello must keep TLS 1.3
            # and the cipher suite the HRR chose
            tls_send_plaintext_alert(self._fd, _ALERT_ILLEGAL_PARAMETER)
            raise Error("tls: ServerHello does not match the HelloRetryRequest (illegal_parameter)")

        if use_tls13:
            # ── TLS 1.3 path ──────────────────────────────────────────────────
            try:
                # keys change after ServerHello: nothing may follow it
                reader.require_boundary("ServerHello")
                self._keys = tls13_after_server_hello(
                    self._fd, hostname, trust_anchors,
                    ecdhe_private, sh_msg.body, th, th384, key_share_group,
                    alpn_protocols,
                )
                self._is12 = False
            except e:
                self._is12 = False  # ensure flag is consistent on failure
                raise Error(String(e))
        else:
            # ── TLS 1.2 path ──────────────────────────────────────────────────
            self._check_downgrade(server_random)
            var ems = parse_server_hello_tls12_exts(sh_msg.body)
            var use_sha384 = (cipher_suite == 0xC030 or cipher_suite == 0xC02C)
            try:
                self._keys12 = tls12_client_handshake(
                    self._fd, hostname, trust_anchors,
                    client_random, server_random, cipher_suite,
                    th, th384, use_sha384, ems, reader.buf.copy(),
                )
                self._is12 = True
            except e:
                self._is12 = False  # reset to safe state on handshake failure
                raise Error(String(e))

    def connect_with_client_cert(
        mut self,
        hostname:       String,
        trust_anchors:  List[X509Cert],
        client_cert:    List[UInt8],   # DER-encoded leaf certificate
        client_key:     List[UInt8],   # 32-byte P-256 private scalar
        alpn_protocols: List[String] = List[String](),
    ) raises:
        """TLS 1.2 mTLS handshake with P-256 ECDSA client authentication.

        Raises if TLS 1.3 is negotiated (TLS 1.3 client auth is deferred to v1.3.0).
        Both client_cert and client_key must be non-empty.
        """
        if len(client_cert) == 0 or len(client_key) == 0:
            raise Error("mTLS: must provide both client_cert and client_key")

        var ecdhe_private = csprng_bytes(32)
        var key_share_pub = x25519_public_key(ecdhe_private)
        var client_random = csprng_bytes(32)

        var ch_msg = build_client_hello(client_random, List[UInt8](), key_share_pub, hostname, alpn_protocols)
        var ch_n = len(ch_msg)
        var ch_record = List[UInt8](capacity=5 + ch_n)
        ch_record.append(0x16)
        ch_record.append(0x03)
        ch_record.append(0x01)
        ch_record.append(UInt8((ch_n >> 8) & 0xFF))
        ch_record.append(UInt8(ch_n & 0xFF))
        _sock_append_bytes(ch_record, ch_msg)
        tls_prepare_fd(self._fd)
        tls_tcp_write(self._fd, ch_record)

        var th    = SHA256()
        var th384 = SHA384()
        th.update(ch_msg)
        th384.update(ch_msg)

        # Read ServerHello (records may also carry the next messages)
        var reader = HandshakeReader(self._fd, False)
        var sh_msg = reader.expect(HS_SERVER_HELLO, "ServerHello")
        if is_hello_retry_request(parse_server_hello(sh_msg.body).random):
            raise Error("mTLS: requires TLS 1.2; server sent a HelloRetryRequest")

        var sh_full = _sock_wrap_hs_msg(HS_SERVER_HELLO, sh_msg.body)
        th.update(sh_full)
        th384.update(sh_full)

        var sv = parse_server_hello_version(sh_msg.body)
        var cipher_suite = sv[0]
        var server_random = sv[1].copy()
        var use_tls13 = sv[3]

        if use_tls13:
            raise Error("mTLS: requires TLS 1.2; server negotiated TLS 1.3")
        self._check_downgrade(server_random)
        var ems = parse_server_hello_tls12_exts(sh_msg.body)

        var use_sha384 = (cipher_suite == 0xC030 or cipher_suite == 0xC02C)
        try:
            self._keys12 = tls12_client_handshake_mtls(
                self._fd, hostname, trust_anchors,
                client_random, server_random, cipher_suite,
                th, th384, use_sha384,
                client_cert, client_key, ems, reader.buf.copy(),
            )
            self._is12 = True
        except e:
            self._is12 = False
            raise Error(String(e))

    def _send_handshake_plain(self, msg: List[UInt8], minor: UInt8) raises:
        """Send a plaintext handshake record (ClientHello) with version 3.minor."""
        var n = len(msg)
        var record = List[UInt8](capacity=5 + n)
        record.append(0x16)  # content_type = Handshake
        record.append(0x03)
        record.append(minor)
        record.append(UInt8((n >> 8) & 0xFF))
        record.append(UInt8(n & 0xFF))
        _sock_append_bytes(record, msg)
        tls_tcp_write(self._fd, record)

    def _check_downgrade(self, server_random: List[UInt8]) raises:
        """Send illegal_parameter and raise if a TLS 1.2 ServerHello carries
        the TLS 1.3 downgrade sentinel."""
        try:
            check_downgrade_sentinel(server_random)
        except e:
            tls_send_plaintext_alert(self._fd, _ALERT_ILLEGAL_PARAMETER)
            raise e^

    def set_timeout(mut self, seconds: Int) raises:
        """Set the socket's receive and send timeouts (whole seconds; 0 = none).

        A read that times out raises "tls: read timed out" and can be
        retried: a partly received record is kept. A write that times out
        leaves the connection unusable for further sends. Sockets from the
        tcp package already have timeouts (its timeout_secs).
        """
        tls_set_timeout(self._fd, seconds)

    def _write_record(mut self, record: List[UInt8]) raises:
        """Write one whole record. A failure part-way through cannot be
        repaired (the peer would see a cut record), so it disables sends."""
        if self._broken:
            raise Error("tls: connection broken by an earlier write failure")
        try:
            tls_tcp_write(self._fd, record)
        except e:
            self._broken = True
            raise e^

    def _read_record(mut self) raises -> Tuple[List[UInt8], List[UInt8]]:
        """Return the next record as (5-byte header, body).

        Bytes are buffered in _rx, so a read timeout part-way through a
        record loses nothing and the call can simply be repeated. TCP EOF
        between records raises "tls: connection closed without
        close_notify"; EOF inside one raises "tls: truncated record".
        """
        while True:
            if len(self._rx) >= 5:
                var rlen = (Int(self._rx[3]) << 8) | Int(self._rx[4])
                if rlen > 16640:  # 2^14 + 256 (RFC 8446 §5.2)
                    raise Error("tls: record too large: " + String(rlen))
                var total = 5 + rlen
                if len(self._rx) >= total:
                    var header = List[UInt8](capacity=5)
                    for i in range(5):
                        header.append(self._rx[i])
                    var body = List[UInt8](capacity=rlen)
                    for i in range(5, total):
                        body.append(self._rx[i])
                    var rest = List[UInt8](capacity=len(self._rx) - total)
                    for i in range(total, len(self._rx)):
                        rest.append(self._rx[i])
                    self._rx = rest^
                    return (header^, body^)
            var chunk = tls_read_some(self._fd, _RX_CHUNK)
            if len(chunk) == 0:
                if len(self._rx) == 0:
                    raise Error("tls: connection closed without close_notify")
                raise Error("tls: truncated record")
            _sock_append_bytes(self._rx, chunk)

    def _key_update(mut self, update_requested: Bool) raises:
        """Apply a server KeyUpdate (RFC 8446 §4.6.3); answer if requested."""
        if len(self._keys.server_app_secret) == 0:
            raise Error("tls: KeyUpdate without application traffic secrets")
        var use384 = self._keys.use_sha384
        var key_len = 16 if self._keys.cipher == CIPHER_AES_128_GCM else 32

        var s_next = tls13_next_traffic_secret(self._keys.server_app_secret, use384)
        var s_kp = tls13_traffic_keys_sha384(s_next, key_len, 12) if use384 else tls13_traffic_keys(s_next, key_len, 12)
        self._keys.server_app_secret = s_next^
        self._keys.server_write_key = s_kp[0].copy()
        self._keys.server_write_iv = s_kp[1].copy()
        self._keys.server_seqno = 0

        if update_requested:
            self._update_client_keys()

    def _update_client_keys(mut self) raises:
        """Send KeyUpdate(update_not_requested) under the current client keys,
        then switch to the next client traffic secret (RFC 8446 §4.6.3)."""
        var use384 = self._keys.use_sha384
        var key_len = 16 if self._keys.cipher == CIPHER_AES_128_GCM else 32
        var msg: List[UInt8] = [_HS_KEY_UPDATE, 0, 0, 1, 0]
        var sealed = record_seal_k(
                self._seal_ak,
            self._keys.cipher,
            self._keys.client_write_key,
            self._keys.client_write_iv,
            self._keys.client_seqno,
            CTYPE_HANDSHAKE,
            msg,
        )
        self._write_record(sealed)
        var c_next = tls13_next_traffic_secret(self._keys.client_app_secret, use384)
        var c_kp = tls13_traffic_keys_sha384(c_next, key_len, 12) if use384 else tls13_traffic_keys(c_next, key_len, 12)
        self._keys.client_app_secret = c_next^
        self._keys.client_write_key = c_kp[0].copy()
        self._keys.client_write_iv = c_kp[1].copy()
        self._keys.client_seqno = 0

    def send(mut self, data: List[UInt8]) raises -> Int:
        """Encrypt data as a TLS ApplicationData record and write to socket."""
        if self._failed.byte_length() > 0:
            raise Error("tls: connection failed earlier: " + self._failed)
        if len(data) > 16384:
            raise Error("tls: send: plaintext exceeds TLS record limit (16384 bytes)")
        if self._is12:
            var payload = record_seal_12_k(
                self._seal_ak,
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
            self._write_record(record)
            if self._keys12.client_seqno >= UInt64(4611686018427387904):
                raise Error("tls: client sequence number overflow")
            self._keys12.client_seqno += 1
        else:
            if self._keys.client_seqno >= self._key_update_after and len(self._keys.client_app_secret) > 0:
                self._update_client_keys()
            var sealed = record_seal_k(
                self._seal_ak,
                self._keys.cipher,
                self._keys.client_write_key,
                self._keys.client_write_iv,
                self._keys.client_seqno,
                CTYPE_APPLICATION_DATA,
                data,
            )
            self._write_record(sealed)
            if self._keys.client_seqno >= (UInt64(1) << 62):
                raise Error("tls: client sequence number overflow")
            self._keys.client_seqno += 1
        return len(data)

    def _handle_alert(mut self, alert_body: List[UInt8]) raises:
        """Handle a decrypted alert. Always raises; close_notify sets the flag."""
        if len(alert_body) == 2 and alert_body[1] == ALERT_CLOSE_NOTIFY:
            self._close_notify = True
        tls_handle_incoming_alert(alert_body)
        raise Error("tls: alert (unreachable)")

    def _fill_buf_12(mut self) raises:
        """Read and decrypt one TLS 1.2 record, appending plaintext to _buf.

        After the handshake every alert must be encrypted: a plaintext or
        undecryptable alert is an attack, never a shutdown.
        """
        while True:
            var rec = self._read_record()
            var rtype = rec[0][0]
            var rbody = rec[1].copy()
            var rlen = len(rbody)

            if rtype == CTYPE_CHANGE_CIPHER_SPEC:
                # renegotiation is not supported: no CCS after the handshake
                raise Error("tls: ChangeCipherSpec after the handshake (unexpected_message)")

            if rtype == CTYPE_ALERT:
                if rlen < 8 + 16:
                    raise Error("tls: unexpected plaintext alert after handshake (unexpected_message)")
                var alert_plain: List[UInt8]
                try:
                    alert_plain = record_open_12_k(
                self._open_ak,
                        UInt8(self._keys12.cipher),
                        self._keys12.server_write_key,
                        self._keys12.server_write_iv,
                        self._keys12.server_seqno,
                        rtype, rbody,
                    )
                except:
                    raise Error("tls: bad_record_mac (alert failed to decrypt)")
                self._keys12.server_seqno += 1
                self._handle_alert(alert_plain)

            if rtype != CTYPE_APPLICATION_DATA:
                raise Error(
                    "tls: unexpected record type " + String(Int(rtype))
                    + " after handshake (unexpected_message)"
                )
            if rlen < 8 + 16:  # must have at least explicit_nonce + tag
                raise Error("tls12_socket: record too short: " + String(rlen))

            var plain = record_open_12_k(
                self._open_ak,
                UInt8(self._keys12.cipher),
                self._keys12.server_write_key,
                self._keys12.server_write_iv,
                self._keys12.server_seqno,
                rtype, rbody,
            )
            if self._keys12.server_seqno >= UInt64(4611686018427387904):
                raise Error("tls: server sequence number overflow")
            self._keys12.server_seqno += 1
            if len(plain) > 16384:
                raise Error("tls: record plaintext too long (record_overflow)")
            if len(plain) == 0:
                continue  # empty records are legal; never report them as EOF
            _sock_append_bytes(self._buf, plain)
            return  # one record successfully decrypted

    def _fill_buf(mut self) raises:
        """Read and decrypt one TLS ApplicationData record, appending plaintext to _buf.

        Raises "tls: close_notify" on an authenticated shutdown, and
        "tls: connection closed without close_notify" when TCP closes
        without one. Collects NewSessionTicket messages along the way.
        """
        if self._is12:
            self._fill_buf_12()
            return

        while True:
            var rec = self._read_record()
            var header = rec[0].copy()
            var rbody = rec[1].copy()
            var rtype = header[0]

            if rtype == CTYPE_CHANGE_CIPHER_SPEC:
                # only allowed before the peer's Finished (RFC 8446 §5)
                raise Error("tls: ChangeCipherSpec after the handshake (unexpected_message)")

            if rtype == CTYPE_ALERT:
                # TLS 1.3 alerts after the handshake are always encrypted
                raise Error("tls: unexpected plaintext alert after handshake (unexpected_message)")

            if rtype != CTYPE_APPLICATION_DATA:
                raise Error(
                    "tls: unexpected record type " + String(Int(rtype))
                    + " after handshake (unexpected_message)"
                )

            # Reconstruct full record for record_open
            var full_record = header^
            _sock_append_bytes(full_record, rbody)

            var decrypted = record_open_k(
                self._open_ak,
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
                self._handle_alert(plaintext)

            if inner_type == CTYPE_HANDSHAKE:
                # Post-handshake messages (NewSessionTicket, KeyUpdate),
                # reassembled across records
                if len(plaintext) == 0:
                    raise Error("tls: empty handshake record (unexpected_message)")
                _sock_append_bytes(self._hs_rx, plaintext)
                self._process_post_handshake()
                continue

            if inner_type != CTYPE_APPLICATION_DATA:
                raise Error(
                    "tls: unexpected inner content type " + String(Int(inner_type))
                    + " (unexpected_message)"
                )

            if len(plaintext) == 0:
                continue  # empty records are legal; never report them as EOF
            _sock_append_bytes(self._buf, plaintext)
            return  # one record successfully read

    def _process_post_handshake(mut self) raises:
        """Handle every complete message in _hs_rx; keep a partial one."""
        while len(self._hs_rx) >= 4:
            var mtype = self._hs_rx[0]
            var mlen = (Int(self._hs_rx[1]) << 16) | (Int(self._hs_rx[2]) << 8) | Int(self._hs_rx[3])
            if mlen > 65536:
                raise Error("tls: post-handshake message too large (record_overflow)")
            if len(self._hs_rx) < 4 + mlen:
                return
            var body = List[UInt8](capacity=mlen)
            for i in range(mlen):
                body.append(self._hs_rx[4 + i])
            var rest = List[UInt8](capacity=len(self._hs_rx) - 4 - mlen)
            for i in range(4 + mlen, len(self._hs_rx)):
                rest.append(self._hs_rx[i])
            self._hs_rx = rest^
            if mtype == _HS_KEY_UPDATE:
                if mlen != 1:
                    raise Error("tls: malformed KeyUpdate (decode_error)")
                if len(self._hs_rx) != 0:
                    # keys change at the record boundary
                    raise Error("tls: KeyUpdate not at the end of its record (unexpected_message)")
                if body[0] > 1:
                    raise Error("tls: bad KeyUpdate request value (illegal_parameter)")
                self._key_update(body[0] == 1)
            elif mtype == HS_NEW_SESSION_TICKET:
                try:
                    var ticket = parse_new_session_ticket(body)
                    ticket.psk = tls13_psk_from_ticket(self._keys.resumption_secret, ticket.nonce)
                    self._keys.session_tickets.append(ticket^)
                    # keep the most recent few (tickets are not used yet)
                    if len(self._keys.session_tickets) > _MAX_TICKETS:
                        var kept = List[SessionTicket]()
                        for i in range(1, len(self._keys.session_tickets)):
                            kept.append(self._keys.session_tickets[i].copy())
                        self._keys.session_tickets = kept^
                except:
                    pass  # an unusable ticket is ignored, as before
            else:
                raise Error(
                    "tls: unexpected post-handshake message type " + String(Int(mtype))
                    + " (unexpected_message)"
                )

    def _send_alert(mut self, code: UInt8):
        """Best effort: one encrypted fatal alert with the current client keys."""
        if self._broken or self._fd < 0:
            return
        var body: List[UInt8] = [ALERT_LEVEL_FATAL, code]
        try:
            if self._is12:
                if len(self._keys12.client_write_key) == 0:
                    return
                var payload = record_seal_12_k(
                self._seal_ak,
                    UInt8(self._keys12.cipher), self._keys12.client_write_key,
                    self._keys12.client_write_iv, self._keys12.client_seqno, CTYPE_ALERT, body,
                )
                var record = List[UInt8](capacity=5 + len(payload))
                record.append(CTYPE_ALERT)
                record.append(0x03)
                record.append(0x03)
                record.append(UInt8((len(payload) >> 8) & 0xFF))
                record.append(UInt8(len(payload) & 0xFF))
                _sock_append_bytes(record, payload)
                self._write_record(record)
            else:
                if len(self._keys.client_write_key) == 0:
                    return
                self._write_record(record_seal_k(
                self._seal_ak,
                    self._keys.cipher, self._keys.client_write_key,
                    self._keys.client_write_iv, self._keys.client_seqno, CTYPE_ALERT, body,
                ))
        except:
            pass

    def _fill_checked(mut self) raises:
        """_fill_buf, but a fatal error is remembered: the connection is dead
        after it (RFC 8446 §6.2) and later calls raise it again. Read
        timeouts are not fatal. Locally detected protocol errors also send
        the matching fatal alert."""
        if self._failed.byte_length() > 0:
            raise Error("tls: connection failed earlier: " + self._failed)
        try:
            self._fill_buf()
        except e:
            var msg = String(e)
            if _sock_contains(msg, "read timed out"):
                raise Error(msg)
            self._failed = msg
            if _sock_contains(msg, "(unexpected_message)"):
                self._send_alert(10)
            elif _sock_contains(msg, "authentication failed") or _sock_contains(msg, "(bad_record_mac)"):
                self._send_alert(20)
            elif _sock_contains(msg, "(record_overflow)"):
                self._send_alert(22)
            elif _sock_contains(msg, "(illegal_parameter)"):
                self._send_alert(47)
            elif _sock_contains(msg, "(decode_error)"):
                self._send_alert(50)
            raise Error(msg)

    def recv(mut self, max_bytes: Int) raises -> List[UInt8]:
        """Read up to max_bytes of decrypted application data.

        Buffers data across TLS records so multiple small reads work correctly.
        If buffer is empty, reads the next TLS record to refill it.
        """
        if len(self._buf) == 0:
            self._fill_checked()
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

    def recv_all(
        mut self, max_size: Int = 16777216, allow_truncation: Bool = False
    ) raises -> List[UInt8]:
        """Read all ApplicationData until the server's close_notify.

        Returns the data once an authenticated close_notify arrives. If TCP
        closes without one, an attacker may have cut the stream short, so
        this raises "tls: truncated: ..." unless allow_truncation is True
        (for protocols that carry their own lengths, or servers known to
        skip close_notify). A record cut mid-way always raises, as does
        exceeding max_size.
        """
        var result = List[UInt8]()
        # Drain any already-buffered bytes first
        _sock_append_bytes(result, self._buf)
        self._buf = List[UInt8]()
        while True:
            try:
                self._fill_checked()
            except e:
                if self._close_notify:
                    break
                var err_str = String(e)
                if _sock_contains(err_str, "connection closed without close_notify"):
                    if allow_truncation:
                        break
                    raise Error(
                        "tls: truncated: connection closed without close_notify"
                        + " (pass allow_truncation=True to accept)"
                    )
                raise Error(err_str)
            _sock_append_bytes(result, self._buf)
            self._buf = List[UInt8]()
            if len(result) > max_size:
                raise Error("tls: recv_all exceeded max_size")
        return result^

    def close_notify_received(self) -> Bool:
        """True once the server sent an authenticated close_notify: everything
        it sent has arrived. False after a bare TCP close."""
        return self._close_notify

    def close(mut self) raises:
        """Send close_notify alert and close the TCP socket.

        After a failed write the close_notify is skipped: it would follow a
        partly sent record.
        """
        if self._fd < 0:
            return  # already closed: never touch a possibly reused fd number
        if self._broken or self._failed.byte_length() > 0:
            pass
        elif self._is12:
            if len(self._keys12.client_write_key) > 0:
                var alert_body = List[UInt8](capacity=2)
                alert_body.append(ALERT_LEVEL_WARNING)
                alert_body.append(ALERT_CLOSE_NOTIFY)
                var payload = record_seal_12_k(
                self._seal_ak,
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
                var sealed = record_seal_k(
                self._seal_ak,
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
        self._fd = -1

    def session_tickets(self) -> List[SessionTicket]:
        """Return copies of NewSessionTicket records received from the server.

        Tickets are collected transparently during recv() calls.
        Returns an empty list for TLS 1.2 connections or when no tickets arrived.
        """
        if self._is12:
            return List[SessionTicket]()
        return self._keys.session_tickets.copy()

    def negotiated_protocol(self) -> String:
        """Return the ALPN protocol selected by the server during the handshake.

        Returns the protocol name (e.g. "h2" or "http/1.1") if the server
        echoed an ALPN extension in EncryptedExtensions, or "" if ALPN was
        not advertised in the ClientHello, not supported by the server, or
        this is a TLS 1.2 connection (TLS 1.2 ALPN deferred to v1.4.0).
        """
        if self._is12:
            return String("")
        return self._keys.negotiated_protocol
