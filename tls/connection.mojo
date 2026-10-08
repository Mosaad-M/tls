# ============================================================================
# tls/connection.mojo — TLS 1.3 client handshake state machine
# ============================================================================
# API:
#   tls13_client_handshake(fd, hostname, trust_anchors, cipher) → TlsKeys
#       fd: connected TCP socket file descriptor (Int32)
#
# TlsKeys struct holds all post-handshake keying material.
# ============================================================================

from std.ffi import external_call, get_errno
from std.memory import alloc
from std.sys.info import CompilationTarget
from crypto.hash import SHA256, SHA384, sha256, sha384, sha512
from crypto.handshake import (
    tls13_early_secret, tls13_handshake_secret, tls13_master_secret,
    tls13_derive_secret, tls13_traffic_keys, tls13_finished_key,
    tls13_compute_finished, tls13_verify_finished,
    tls13_early_secret_sha384, tls13_handshake_secret_sha384, tls13_master_secret_sha384,
    tls13_derive_secret_sha384, tls13_traffic_keys_sha384, tls13_finished_key_sha384,
    tls13_compute_finished_sha384, tls13_verify_finished_sha384,
    tls13_cert_verify_input, CERT_VERIFY_SERVER_CTX,
)
from crypto.record import (
    record_seal, record_open,
    CIPHER_AES_128_GCM, CIPHER_AES_256_GCM, CIPHER_CHACHA20_POLY1305,
    CTYPE_HANDSHAKE, CTYPE_APPLICATION_DATA, CTYPE_CHANGE_CIPHER_SPEC, CTYPE_ALERT,
)
from crypto.cert import X509Cert, cert_parse, cert_chain_verify
from crypto.asn1 import asn1_parse_ecdsa_sig, asn1_parse_ecdsa_sig_48
from crypto.curve25519 import x25519_public_key, x25519_shared
from crypto.random import csprng_bytes
from crypto.p256 import p256_ecdsa_verify, p256_ecdh, p256_public_key
from crypto.p384 import p384_ecdh, p384_public_key
from crypto.p384 import p384_ecdsa_verify
from crypto.rsa import rsa_pss_verify
from tls.message import (
    build_client_hello, build_finished,
    parse_handshake_msg, parse_server_hello, parse_server_hello_key_share,
    parse_certificate_chain, parse_cert_verify, parse_finished,
    parse_new_session_ticket, parse_alpn_from_ee, SessionTicket,
    validate_encrypted_extensions, parse_certificate_request13, build_empty_certificate13,
    HandshakeMsg,
    HS_SERVER_HELLO, HS_ENCRYPTED_EXTS, HS_CERTIFICATE, HS_CERT_REQUEST,
    HS_CERT_VERIFY, HS_FINISHED, HS_NEW_SESSION_TICKET,
    GROUP_X25519, GROUP_SECP256R1, GROUP_SECP384R1,
)


# ── Alert codes ───────────────────────────────────────────────────────────────
comptime ALERT_LEVEL_WARNING : UInt8 = 1
comptime ALERT_LEVEL_FATAL   : UInt8 = 2
comptime ALERT_CLOSE_NOTIFY  : UInt8 = 0
comptime ALERT_BAD_CERT      : UInt8 = 42


# ============================================================================
# TlsKeys — post-handshake keying material
# ============================================================================

struct TlsKeys(Copyable, Movable):
    var cipher:                UInt8
    var client_write_key:      List[UInt8]
    var client_write_iv:       List[UInt8]
    var server_write_key:      List[UInt8]
    var server_write_iv:       List[UInt8]
    var client_seqno:          UInt64
    var server_seqno:          UInt64
    var resumption_secret:     List[UInt8]
    var session_tickets:       List[SessionTicket]
    var negotiated_protocol:   String   # ALPN protocol selected by server, "" if none
    var client_app_secret:     List[UInt8]  # current application traffic secrets,
    var server_app_secret:     List[UInt8]  # kept for KeyUpdate (RFC 8446 §4.6.3)
    var use_sha384:            Bool         # key schedule hash (TLS_AES_256_GCM_SHA384)

    def __init__(out self):
        self.cipher              = 0
        self.client_write_key    = List[UInt8]()
        self.client_write_iv     = List[UInt8]()
        self.server_write_key    = List[UInt8]()
        self.server_write_iv     = List[UInt8]()
        self.client_seqno        = 0
        self.server_seqno        = 0
        self.resumption_secret   = List[UInt8]()
        self.session_tickets     = List[SessionTicket]()
        self.negotiated_protocol = String("")
        self.client_app_secret   = List[UInt8]()
        self.server_app_secret   = List[UInt8]()
        self.use_sha384          = False

    def __copyinit__(out self, copy: Self):
        self.cipher              = copy.cipher
        self.client_write_key    = copy.client_write_key.copy()
        self.client_write_iv     = copy.client_write_iv.copy()
        self.server_write_key    = copy.server_write_key.copy()
        self.server_write_iv     = copy.server_write_iv.copy()
        self.client_seqno        = copy.client_seqno
        self.server_seqno        = copy.server_seqno
        self.resumption_secret   = copy.resumption_secret.copy()
        self.session_tickets     = copy.session_tickets.copy()
        self.negotiated_protocol = copy.negotiated_protocol
        self.client_app_secret   = copy.client_app_secret.copy()
        self.server_app_secret   = copy.server_app_secret.copy()
        self.use_sha384          = copy.use_sha384

    def __moveinit__(out self, deinit take: Self):
        self.cipher              = take.cipher
        self.client_write_key    = take.client_write_key^
        self.client_write_iv     = take.client_write_iv^
        self.server_write_key    = take.server_write_key^
        self.server_write_iv     = take.server_write_iv^
        self.client_seqno        = take.client_seqno
        self.server_seqno        = take.server_seqno
        self.resumption_secret   = take.resumption_secret^
        self.session_tickets     = take.session_tickets^
        self.negotiated_protocol = take.negotiated_protocol^
        self.client_app_secret   = take.client_app_secret^
        self.server_app_secret   = take.server_app_secret^
        self.use_sha384          = take.use_sha384


# ============================================================================
# TCP I/O helpers (FFI: recv / send / setsockopt)
# ============================================================================
# A Mojo program may declare each C function with one signature only, and
# std declares open/read/write and errno access (__error/__errno_location)
# itself. tls therefore declares none of those: sockets use recv/send with
# the tcp package's signatures (tests/test_ffi_compat.mojo), errno comes from
# std.ffi.get_errno, and files go through std open() (tests/test_std_compat.mojo).

comptime _EINTR      : Int32 = 4
comptime _EPIPE      : Int32 = 32
comptime _EAGAIN     : Int32 = 35 if CompilationTarget.is_macos() else 11
comptime _ECONNRESET : Int32 = 54 if CompilationTarget.is_macos() else 104
comptime _MSG_NOSIGNAL : Int32 = 0x4000          # Linux; macOS uses SO_NOSIGPIPE
comptime _SOL_SOCKET   : Int32 = 0xFFFF if CompilationTarget.is_macos() else 1
comptime _SO_NOSIGPIPE : Int32 = 0x1022          # macOS only
comptime _SO_RCVTIMEO  : Int32 = 0x1006 if CompilationTarget.is_macos() else 20
comptime _SO_SNDTIMEO  : Int32 = 0x1005 if CompilationTarget.is_macos() else 21


def _errno() -> Int32:
    """Current errno."""
    return Int32(get_errno().value)


def tls_prepare_fd(fd: Int32):
    """Stop writes to a closed peer from raising SIGPIPE (macOS: SO_NOSIGPIPE;
    Linux uses MSG_NOSIGNAL on each send). Harmless on non-sockets."""
    comptime if CompilationTarget.is_macos():
        var one = alloc[Int32](1)
        one[] = 1
        _ = external_call["setsockopt", Int32](
            fd, _SOL_SOCKET, _SO_NOSIGPIPE, Int(one), Int32(4)
        )
        one.unsafe_free()


def tls_set_timeout(fd: Int32, seconds: Int) raises:
    """Set SO_RCVTIMEO and SO_SNDTIMEO (whole seconds; 0 = no timeout)."""
    if seconds < 0:
        raise Error("tls: timeout must be >= 0 seconds")
    var tv = alloc[UInt8](16)  # struct timeval { tv_sec (8), tv_usec (8 incl. padding) }
    for i in range(16):
        tv[unsafe_offset=i] = 0
    tv.unsafe_bitcast[Int]()[unsafe_offset=0] = seconds
    var rc1 = external_call["setsockopt", Int32](fd, _SOL_SOCKET, _SO_RCVTIMEO, Int(tv), Int32(16))
    var rc2 = external_call["setsockopt", Int32](fd, _SOL_SOCKET, _SO_SNDTIMEO, Int(tv), Int32(16))
    tv.unsafe_free()
    if rc1 != 0 or rc2 != 0:
        raise Error("tls: setsockopt timeout failed (errno=" + String(_errno()) + ")")


def tls_read_into(fd: Int32, addr: Int, max_bytes: Int) raises -> Int:
    """Read up to max_bytes into memory at addr; returns the count, 0 at EOF.

    Retries EINTR. A receive timeout (SO_RCVTIMEO) raises "tls: read timed
    out"; any other failure raises "tls: tcp read failed (errno=N)".
    """
    while True:
        # Same argument types as the tcp package's recv()
        var got = external_call["recv", Int](fd, addr, max_bytes, Int32(0))
        if got >= 0:
            return got
        var err = _errno()
        if err == _EINTR:
            continue
        if err == _EAGAIN:
            raise Error("tls: read timed out")
        raise Error("tls: tcp read failed (errno=" + String(err) + ")")


def tls_read_some(fd: Int32, max_bytes: Int) raises -> List[UInt8]:
    """Read up to max_bytes; an empty result means EOF (see tls_read_into)."""
    # Receive straight into the result's storage (no copy)
    var out = List[UInt8](unsafe_uninit_length=max(max_bytes, 0))
    var got = tls_read_into(fd, Int(out.unsafe_ptr()), max_bytes)
    out.resize(unsafe_uninit_length=got)
    return out^


def _tcp_read(fd: Int32, n: Int) raises -> List[UInt8]:
    """Read exactly n bytes during the handshake. Raises on error or EOF."""
    var out = List[UInt8](capacity=n)
    while len(out) < n:
        var chunk = tls_read_some(fd, n - len(out))
        if len(chunk) == 0:
            raise Error("tls: connection closed during handshake")
        for i in range(len(chunk)):
            out.append(chunk[i])
    return out^


def _tcp_write(fd: Int32, data: List[UInt8]) raises:
    """Write all bytes to the socket fd.

    Never raises SIGPIPE (MSG_NOSIGNAL on Linux, SO_NOSIGPIPE on macOS via
    tls_prepare_fd). Retries EINTR. Raises "tls: connection closed by peer
    (write failed)" on EPIPE/ECONNRESET and "tls: write timed out" when
    SO_SNDTIMEO expires.
    """
    var n = len(data)
    var base = Int(data.unsafe_ptr())  # data is borrowed: alive for the whole call
    var total = 0
    # MSG_NOSIGNAL on Linux; on macOS tls_prepare_fd set SO_NOSIGPIPE
    comptime FLAGS = _MSG_NOSIGNAL if CompilationTarget.is_linux() else Int32(0)
    while total < n:
        # Same argument types as the tcp package's send()
        var sent = external_call["send", Int](fd, base + total, n - total, FLAGS)
        if sent < 0:
            var err = _errno()
            if err == _EINTR:
                continue
            if err == _EAGAIN:
                raise Error("tls: write timed out")
            if err == _EPIPE or err == _ECONNRESET:
                raise Error("tls: connection closed by peer (write failed)")
            raise Error("tls: tcp write failed (errno=" + String(err) + ")")
        if sent == 0:
            raise Error("tls: tcp write failed (wrote 0 bytes)")
        total += sent


# ============================================================================
# Internal TLS helpers
# ============================================================================

def _append_bytes(mut out: List[UInt8], src: List[UInt8]):
    for i in range(len(src)):
        out.append(src[i])


def _make_tls_record(content_type: UInt8, data: List[UInt8]) -> List[UInt8]:
    """Wrap data in TLS record (5-byte header + data)."""
    var n = len(data)
    var out = List[UInt8](capacity=5 + n)
    out.append(content_type)
    out.append(0x03)
    out.append(0x03)
    out.append(UInt8((n >> 8) & 0xFF))
    out.append(UInt8(n & 0xFF))
    _append_bytes(out, data)
    return out^


def _read_tls_record(fd: Int32) raises -> Tuple[UInt8, List[UInt8]]:
    """Read one TLS record. Returns (content_type, body)."""
    var header = _tcp_read(fd, 5)
    var content_type = header[0]
    var n = (Int(header[3]) << 8) | Int(header[4])
    if n > 16384 + 256:
        raise Error("tls: record too large: " + String(n))
    var body = _tcp_read(fd, n)
    return (content_type, body^)


def _wrap_hs_msg(msg_type: UInt8, body: List[UInt8]) -> List[UInt8]:
    """Wrap body in a 4-byte Handshake header."""
    var out = List[UInt8](capacity=4 + len(body))
    out.append(msg_type)
    var n = len(body)
    out.append(UInt8((n >> 16) & 0xFF))
    out.append(UInt8((n >> 8) & 0xFF))
    out.append(UInt8(n & 0xFF))
    _append_bytes(out, body)
    return out^


def _transcript_hash(h: SHA256) -> List[UInt8]:
    """Get current transcript hash without consuming the hasher."""
    var h_copy = h.copy()
    return h_copy.finalize()


def _transcript_hash_sha384(h: SHA384) -> List[UInt8]:
    """Get current SHA-384 transcript hash without consuming the hasher."""
    var h_copy = h.copy()
    return h_copy.finalize()


def _key_len_for_cipher(cipher: UInt8) -> Int:
    if cipher == CIPHER_AES_128_GCM:
        return 16
    return 32


def _cipher_from_suite(suite: UInt16) raises -> UInt8:
    if suite == 0x1301:
        return CIPHER_AES_128_GCM
    if suite == 0x1302:
        return CIPHER_AES_256_GCM
    if suite == 0x1303:
        return CIPHER_CHACHA20_POLY1305
    raise Error("tls: unsupported cipher suite " + String(Int(suite)))


def _verify_cert_verify_sig(
    cert:       X509Cert,
    sig_scheme: UInt16,
    sig_bytes:  List[UInt8],
    cv_input:   List[UInt8],
) raises:
    """Verify a TLS 1.3 CertificateVerify signature.

    RSA must use PSS here: RFC 8446 §4.4.3 forbids PKCS#1 v1.5 (0x0401) in
    CertificateVerify, so it falls through to "unsupported sig_scheme".
    """
    if sig_scheme == 0x0403:  # ecdsa_secp256r1_sha256
        # In TLS 1.3 the scheme names the curve as well as the hash
        if cert.pub_key_alg != "ec" or cert.ec_curve != "p256":
            raise Error("tls: sig_scheme ECDSA P-256 but cert has no P-256 key")
        var msg_hash = sha256(cv_input)
        var sig_res = asn1_parse_ecdsa_sig(sig_bytes)
        p256_ecdsa_verify(cert.ec_point, msg_hash, sig_res[0].copy(), sig_res[1].copy())
    elif sig_scheme == 0x0503:  # ecdsa_secp384r1_sha384
        if cert.pub_key_alg != "ec" or cert.ec_curve != "p384":
            raise Error("tls: sig_scheme ECDSA P-384 but cert has no P-384 key")
        var msg_hash = sha384(cv_input)
        var sig_res = asn1_parse_ecdsa_sig_48(sig_bytes)
        p384_ecdsa_verify(cert.ec_point, msg_hash, sig_res[0].copy(), sig_res[1].copy())
    elif sig_scheme == 0x0804:  # rsa_pss_rsae_sha256
        if cert.pub_key_alg != "rsa":
            raise Error("tls: sig_scheme RSA-PSS-SHA256 but cert has no RSA key")
        var msg_hash = sha256(cv_input)
        rsa_pss_verify(cert.rsa_n, cert.rsa_e, msg_hash, sig_bytes, 32)
    elif sig_scheme == 0x0805:  # rsa_pss_rsae_sha384
        if cert.pub_key_alg != "rsa":
            raise Error("tls: sig_scheme RSA-PSS-SHA384 but cert has no RSA key")
        var msg_hash = sha384(cv_input)
        rsa_pss_verify(cert.rsa_n, cert.rsa_e, msg_hash, sig_bytes, 48)
    elif sig_scheme == 0x0806:  # rsa_pss_rsae_sha512
        if cert.pub_key_alg != "rsa":
            raise Error("tls: sig_scheme RSA-PSS-SHA512 but cert has no RSA key")
        var msg_hash = sha512(cv_input)
        rsa_pss_verify(cert.rsa_n, cert.rsa_e, msg_hash, sig_bytes, 64)
    else:
        raise Error("tls: unsupported sig_scheme " + String(Int(sig_scheme)))


# ============================================================================
# Read all encrypted server handshake messages until Finished
# ============================================================================

comptime HS_MAX_MESSAGE = 65536   # largest handshake message accepted
comptime HS_MAX_FLIGHT = 262144   # total handshake bytes per reader


struct HandshakeReader(Movable):
    """Reads handshake messages from records, reassembling messages that span
    records and splitting records that carry several (RFC 8446 §5.1, RFC 5246
    §6.2.1). Plaintext, or decrypted with TLS 1.3 handshake keys after
    use_keys(). Bounded: one message <= HS_MAX_MESSAGE, all messages <=
    HS_MAX_FLIGHT, so a peer cannot make the client buffer without limit.

    allow_ccs: accept plaintext ChangeCipherSpec records (value 1) and skip
    them, as TLS 1.3 middlebox compatibility allows during the handshake.
    """
    var fd: Int32
    var buf: List[UInt8]        # handshake bytes received, not yet returned
    var returned: Int           # bytes of messages returned so far
    var allow_ccs: Bool
    var encrypted: Bool
    var cipher: UInt8
    var key: List[UInt8]
    var iv: List[UInt8]
    var seqno: UInt64

    def __init__(out self, fd: Int32, allow_ccs: Bool, pending: List[UInt8] = List[UInt8]()):
        self.fd = fd
        self.buf = pending.copy()
        self.returned = 0
        self.allow_ccs = allow_ccs
        self.encrypted = False
        self.cipher = 0
        self.key = List[UInt8]()
        self.iv = List[UInt8]()
        self.seqno = 0

    def __moveinit__(out self, deinit take: Self):
        self.fd = take.fd
        self.buf = take.buf^
        self.returned = take.returned
        self.allow_ccs = take.allow_ccs
        self.encrypted = take.encrypted
        self.cipher = take.cipher
        self.key = take.key^
        self.iv = take.iv^
        self.seqno = take.seqno

    def at_boundary(self) -> Bool:
        return len(self.buf) == 0

    def require_boundary(self, after: String) raises:
        """Handshake messages may not span a key change (RFC 8446 §5.1)."""
        if len(self.buf) != 0:
            raise Error("tls: handshake data after " + after + " in the same record (unexpected_message)")

    def use_keys(mut self, cipher: UInt8, key: List[UInt8], iv: List[UInt8]) raises:
        self.require_boundary("ServerHello")
        self.encrypted = True
        self.cipher = cipher
        self.key = key.copy()
        self.iv = iv.copy()
        self.seqno = 0

    def _fill(mut self) raises:
        var header = _tcp_read(self.fd, 5)
        var rtype = header[0]
        var rlen = (Int(header[3]) << 8) | Int(header[4])
        var limit = 16384 + 256 if self.encrypted else 16384
        if rlen > limit:
            raise Error("tls: record too large: " + String(rlen) + " (record_overflow)")
        var body = _tcp_read(self.fd, rlen)
        if rtype == CTYPE_CHANGE_CIPHER_SPEC:
            if not self.allow_ccs or len(body) != 1 or body[0] != 1:
                raise Error("tls: unexpected ChangeCipherSpec (unexpected_message)")
            return
        if rtype == CTYPE_ALERT:
            tls_handle_incoming_alert(body)
            raise Error("tls: alert (unreachable)")
        var data: List[UInt8]
        if self.encrypted:
            if rtype != CTYPE_APPLICATION_DATA:
                raise Error("tls: plaintext record during the encrypted handshake (unexpected_message)")
            var dec = record_open(self.cipher, self.key, self.iv, self.seqno, _make_tls_record(rtype, body))
            self.seqno += 1
            if dec[0] == CTYPE_ALERT:
                tls_handle_incoming_alert(dec[1])
                raise Error("tls: alert (unreachable)")
            if dec[0] != CTYPE_HANDSHAKE:
                raise Error("tls: non-handshake record during the handshake (unexpected_message)")
            data = dec[1].copy()
        else:
            if rtype != CTYPE_HANDSHAKE:
                raise Error("tls: expected a handshake record, got type " + String(Int(rtype)) + " (unexpected_message)")
            data = body^
        if len(data) == 0:
            raise Error("tls: empty handshake record (unexpected_message)")
        _append_bytes(self.buf, data)

    def next_message(mut self) raises -> HandshakeMsg:
        while True:
            if len(self.buf) >= 4:
                var mlen = (Int(self.buf[1]) << 16) | (Int(self.buf[2]) << 8) | Int(self.buf[3])
                if mlen > HS_MAX_MESSAGE:
                    raise Error("tls: handshake message too large: " + String(mlen))
                if len(self.buf) >= 4 + mlen:
                    self.returned += 4 + mlen
                    if self.returned > HS_MAX_FLIGHT:
                        raise Error("tls: handshake too large")
                    var msg = HandshakeMsg()
                    msg.msg_type = self.buf[0]
                    var body = List[UInt8](capacity=mlen)
                    for i in range(mlen):
                        body.append(self.buf[4 + i])
                    msg.body = body^
                    var rest = List[UInt8](capacity=len(self.buf) - 4 - mlen)
                    for i in range(4 + mlen, len(self.buf)):
                        rest.append(self.buf[i])
                    self.buf = rest^
                    return msg^
            self._fill()

    def expect(mut self, msg_type: UInt8, what: String) raises -> HandshakeMsg:
        """The next message, which must be of msg_type (RFC 8446 §4 / RFC 5246
        §7.3 fix the order; anything else is unexpected_message)."""
        var msg = self.next_message()
        if msg.msg_type != msg_type:
            raise Error(
                "tls: expected " + what + ", got handshake message type "
                + String(Int(msg.msg_type)) + " (unexpected_message)"
            )
        return msg^


# ============================================================================
# tls13_after_server_hello — complete TLS 1.3 handshake after SH exchange
# ============================================================================

def tls_ec_keypair(group: UInt16) raises -> Tuple[List[UInt8], List[UInt8]]:
    """Ephemeral (private, public) key pair for an ECDHE group: X25519,
    secp256r1 or secp384r1. NIST-curve scalars are drawn until they fall in
    [1, n-1] (a miss has probability about 2^-32)."""
    if group == GROUP_X25519:
        var k = csprng_bytes(32)
        var pub = x25519_public_key(k)
        return (k^, pub^)
    var size = 32 if group == GROUP_SECP256R1 else 48
    if group != GROUP_SECP256R1 and group != GROUP_SECP384R1:
        raise Error("tls: unsupported key exchange group " + String(Int(group)))
    for _ in range(8):
        var k = csprng_bytes(size)
        try:
            var pub = p256_public_key(k) if group == GROUP_SECP256R1 else p384_public_key(k)
            return (k^, pub^)
        except:
            pass
    raise Error("tls: could not generate a key for group " + String(Int(group)))


def tls_ec_shared(group: UInt16, private_key: List[UInt8], peer_public: List[UInt8]) raises -> List[UInt8]:
    """ECDHE shared secret: X25519 output, or the x-coordinate for NIST curves
    (RFC 8446 §7.4.2, RFC 8422 §5.10). Peer keys are validated; the private
    key is handled in constant time."""
    if group == GROUP_X25519:
        return x25519_shared(private_key, peer_public)
    if group == GROUP_SECP256R1:
        return p256_ecdh(private_key, peer_public)
    if group == GROUP_SECP384R1:
        return p384_ecdh(private_key, peer_public)
    raise Error("tls: unsupported key exchange group " + String(Int(group)))


def tls13_after_server_hello(
    fd:                Int32,
    hostname:          String,
    trust_anchors:     List[X509Cert],
    ecdhe_private:     List[UInt8],
    server_hello_body: List[UInt8],
    th:                SHA256,         # transcript hasher (updated with CH+SH)
    th384:             SHA384,
    key_share_group:   UInt16 = GROUP_X25519,  # group of ecdhe_private
    alpn_protocols:    List[String] = List[String](),  # what the ClientHello offered
) raises -> TlsKeys:
    """Complete TLS 1.3 handshake after ClientHello+ServerHello exchange.

    Derives HS keys, reads/verifies server messages, sends client Finished,
    derives application traffic keys.
    Args:
        ecdhe_private: Client ephemeral private key for key_share_group
                       (X25519, or secp256r1 / secp384r1 after a HelloRetryRequest)
        server_hello_body: ServerHello body (to extract cipher + key_share)
        th, th384: Transcript hashers already updated with CH + SH
    """
    var server_hello = parse_server_hello(server_hello_body)
    var negotiated_cipher = _cipher_from_suite(server_hello.cipher_suite)
    var key_len = _key_len_for_cipher(negotiated_cipher)
    var use_sha384 = (negotiated_cipher == CIPHER_AES_256_GCM)

    # Make local mutable copies of the transcript hashers
    var th_local    = th.copy()
    var th384_local = th384.copy()

    # ── Handshake key derivation ──────────────────────────────────────────────
    var server_pub_key = parse_server_hello_key_share(server_hello.extensions, key_share_group)
    var dhe_shared = tls_ec_shared(key_share_group, ecdhe_private, server_pub_key)

    var hs_secret: List[UInt8]
    var s_hs_ts: List[UInt8]
    var c_hs_ts: List[UInt8]
    var server_hs_key: List[UInt8]
    var server_hs_iv: List[UInt8]

    if use_sha384:
        var th_sh = _transcript_hash_sha384(th384_local)
        var es = tls13_early_secret_sha384()
        hs_secret = tls13_handshake_secret_sha384(es, dhe_shared)
        s_hs_ts = tls13_derive_secret_sha384(hs_secret, "s hs traffic", th_sh)
        c_hs_ts = tls13_derive_secret_sha384(hs_secret, "c hs traffic", th_sh)
        var hs_kp = tls13_traffic_keys_sha384(s_hs_ts, key_len, 12)
        server_hs_key = hs_kp[0].copy()
        server_hs_iv  = hs_kp[1].copy()
    else:
        var th_sh = _transcript_hash(th_local)
        var es = tls13_early_secret()
        hs_secret = tls13_handshake_secret(es, dhe_shared)
        s_hs_ts = tls13_derive_secret(hs_secret, "s hs traffic", th_sh)
        c_hs_ts = tls13_derive_secret(hs_secret, "c hs traffic", th_sh)
        var hs_kp = tls13_traffic_keys(s_hs_ts, key_len, 12)
        server_hs_key = hs_kp[0].copy()
        server_hs_iv  = hs_kp[1].copy()

    # ── Server flight, in order: EncryptedExtensions, [CertificateRequest],
    #    Certificate, CertificateVerify, Finished (RFC 8446 §2, §4) ─────────
    var reader = HandshakeReader(fd, True)
    reader.use_keys(negotiated_cipher, server_hs_key, server_hs_iv)

    var ee = reader.expect(HS_ENCRYPTED_EXTS, "EncryptedExtensions")
    var alpn_proto = validate_encrypted_extensions(ee.body, alpn_protocols)
    th_local.update(_wrap_hs_msg(ee.msg_type, ee.body))
    th384_local.update(_wrap_hs_msg(ee.msg_type, ee.body))

    var cert_msg = reader.next_message()
    var cert_request = False
    var cert_request_ctx = List[UInt8]()
    if cert_msg.msg_type == HS_CERT_REQUEST:
        cert_request_ctx = parse_certificate_request13(cert_msg.body)
        cert_request = True
        th_local.update(_wrap_hs_msg(cert_msg.msg_type, cert_msg.body))
        th384_local.update(_wrap_hs_msg(cert_msg.msg_type, cert_msg.body))
        cert_msg = reader.expect(HS_CERTIFICATE, "Certificate")
    elif cert_msg.msg_type != HS_CERTIFICATE:
        raise Error(
            "tls: expected Certificate, got handshake message type "
            + String(Int(cert_msg.msg_type)) + " (unexpected_message)"
        )
    var cert_body = cert_msg.body.copy()
    th_local.update(_wrap_hs_msg(HS_CERTIFICATE, cert_body))
    th384_local.update(_wrap_hs_msg(HS_CERTIFICATE, cert_body))

    # ── Verify certificate chain ──────────────────────────────────────────────
    var cert_ders = parse_certificate_chain(cert_body)
    var cert_chain = List[X509Cert]()
    for i in range(len(cert_ders)):
        cert_chain.append(cert_parse(cert_ders[i]))
    cert_chain_verify(cert_chain, trust_anchors, hostname)

    # ── Verify CertificateVerify (signs the transcript through Certificate) ──
    var th_for_cv: List[UInt8]
    if use_sha384:
        th_for_cv = _transcript_hash_sha384(th384_local)
    else:
        th_for_cv = _transcript_hash(th_local)
    var cv = reader.expect(HS_CERT_VERIFY, "CertificateVerify")
    var cv_result  = parse_cert_verify(cv.body)
    var sig_scheme = cv_result[0]
    var sig_bytes  = cv_result[1].copy()
    var cv_input   = tls13_cert_verify_input(CERT_VERIFY_SERVER_CTX, th_for_cv)
    _verify_cert_verify_sig(cert_chain[0], sig_scheme, sig_bytes, cv_input)
    th_local.update(_wrap_hs_msg(cv.msg_type, cv.body))
    th384_local.update(_wrap_hs_msg(cv.msg_type, cv.body))

    # ── Verify server Finished ────────────────────────────────────────────────
    var th_for_fin: List[UInt8]
    if use_sha384:
        th_for_fin = _transcript_hash_sha384(th384_local)
    else:
        th_for_fin = _transcript_hash(th_local)
    var fin = reader.expect(HS_FINISHED, "Finished")
    # the next record uses new keys: nothing may follow Finished in its record
    reader.require_boundary("Finished")
    var server_vd = parse_finished(fin.body)
    if use_sha384:
        var s_fkey = tls13_finished_key_sha384(s_hs_ts)
        tls13_verify_finished_sha384(s_fkey, th_for_fin, server_vd)
    else:
        var s_fkey = tls13_finished_key(s_hs_ts)
        tls13_verify_finished(s_fkey, th_for_fin, server_vd)
    th_local.update(_wrap_hs_msg(fin.msg_type, fin.body))
    th384_local.update(_wrap_hs_msg(fin.msg_type, fin.body))

    # Application traffic secrets use the transcript through server Finished
    var th_for_c_fin: List[UInt8]
    if use_sha384:
        th_for_c_fin = _transcript_hash_sha384(th384_local)
    else:
        th_for_c_fin = _transcript_hash(th_local)

    # ── Client flight: [empty Certificate], Finished ─────────────────────────
    var client_hs_key: List[UInt8]
    var client_hs_iv: List[UInt8]
    if use_sha384:
        var c_hs_kp = tls13_traffic_keys_sha384(c_hs_ts, key_len, 12)
        client_hs_key = c_hs_kp[0].copy()
        client_hs_iv  = c_hs_kp[1].copy()
    else:
        var c_hs_kp = tls13_traffic_keys(c_hs_ts, key_len, 12)
        client_hs_key = c_hs_kp[0].copy()
        client_hs_iv  = c_hs_kp[1].copy()
    var client_seq: UInt64 = 0
    if cert_request:
        # No client certificates in TLS 1.3: decline with an empty
        # Certificate (RFC 8446 §4.4.2); the server decides whether to continue
        var empty_cert = build_empty_certificate13(cert_request_ctx)
        _tcp_write(fd, record_seal(negotiated_cipher, client_hs_key, client_hs_iv, client_seq, CTYPE_HANDSHAKE, empty_cert))
        client_seq += 1
        th_local.update(empty_cert)
        th384_local.update(empty_cert)

    var client_vd: List[UInt8]
    if use_sha384:
        var c_fkey = tls13_finished_key_sha384(c_hs_ts)
        client_vd = tls13_compute_finished_sha384(c_fkey, _transcript_hash_sha384(th384_local))
    else:
        var c_fkey = tls13_finished_key(c_hs_ts)
        client_vd = tls13_compute_finished(c_fkey, _transcript_hash(th_local))

    var client_fin_msg = build_finished(client_vd)
    var client_fin_sealed = record_seal(
        negotiated_cipher, client_hs_key, client_hs_iv, client_seq, CTYPE_HANDSHAKE, client_fin_msg
    )
    _tcp_write(fd, client_fin_sealed)

    # ── Derive application traffic keys ───────────────────────────────────────
    # RFC 8446 §7.1: c/s ap traffic use transcript through server Finished
    var c_ap_key: List[UInt8]
    var c_ap_iv: List[UInt8]
    var s_ap_key: List[UInt8]
    var s_ap_iv: List[UInt8]
    var res_secret: List[UInt8]
    var c_ap_secret: List[UInt8]
    var s_ap_secret: List[UInt8]

    if use_sha384:
        var ms = tls13_master_secret_sha384(hs_secret)
        var c_ap_ts = tls13_derive_secret_sha384(ms, "c ap traffic", th_for_c_fin)
        var s_ap_ts = tls13_derive_secret_sha384(ms, "s ap traffic", th_for_c_fin)
        th384_local.update(client_fin_msg)
        var th_app = _transcript_hash_sha384(th384_local)
        res_secret = tls13_derive_secret_sha384(ms, "res master", th_app)
        var c_kp = tls13_traffic_keys_sha384(c_ap_ts, key_len, 12)
        var s_kp = tls13_traffic_keys_sha384(s_ap_ts, key_len, 12)
        c_ap_key = c_kp[0].copy()
        c_ap_iv  = c_kp[1].copy()
        s_ap_key = s_kp[0].copy()
        s_ap_iv  = s_kp[1].copy()
        c_ap_secret = c_ap_ts^
        s_ap_secret = s_ap_ts^
    else:
        var ms = tls13_master_secret(hs_secret)
        var c_ap_ts = tls13_derive_secret(ms, "c ap traffic", th_for_c_fin)
        var s_ap_ts = tls13_derive_secret(ms, "s ap traffic", th_for_c_fin)
        th_local.update(client_fin_msg)
        var th_app = _transcript_hash(th_local)
        res_secret = tls13_derive_secret(ms, "res master", th_app)
        var c_kp = tls13_traffic_keys(c_ap_ts, key_len, 12)
        var s_kp = tls13_traffic_keys(s_ap_ts, key_len, 12)
        c_ap_key = c_kp[0].copy()
        c_ap_iv  = c_kp[1].copy()
        s_ap_key = s_kp[0].copy()
        s_ap_iv  = s_kp[1].copy()
        c_ap_secret = c_ap_ts^
        s_ap_secret = s_ap_ts^

    var keys = TlsKeys()
    keys.cipher              = negotiated_cipher
    keys.client_write_key    = c_ap_key^
    keys.client_write_iv     = c_ap_iv^
    keys.server_write_key    = s_ap_key^
    keys.server_write_iv     = s_ap_iv^
    keys.client_seqno        = 0
    keys.server_seqno        = 0
    keys.resumption_secret   = res_secret^
    keys.negotiated_protocol = alpn_proto^
    keys.client_app_secret   = c_ap_secret^
    keys.server_app_secret   = s_ap_secret^
    keys.use_sha384          = use_sha384
    return keys^


# ============================================================================
# tls13_client_handshake — full TLS 1.3 client handshake over a TCP socket
# ============================================================================

def _tls13_handshake_impl(
    fd:             Int32,
    hostname:       String,
    trust_anchors:  List[X509Cert],
    cipher:         UInt8,
    alpn_protocols: List[String] = List[String](),
) raises -> TlsKeys:
    # ── Step 1: ECDHE key pair + client_random ────────────────────────────────
    var ecdhe_private = csprng_bytes(32)
    var key_share_pub = x25519_public_key(ecdhe_private)
    var client_random = csprng_bytes(32)

    # ── Step 2: Build + send ClientHello ─────────────────────────────────────
    var ch_msg = build_client_hello(client_random, List[UInt8](), key_share_pub, hostname, alpn_protocols)

    # Use legacy version 0x0301 for ClientHello record for max compat
    var ch_n = len(ch_msg)
    var ch_record = List[UInt8](capacity=5 + ch_n)
    ch_record.append(0x16)  # Handshake
    ch_record.append(0x03)
    ch_record.append(0x01)  # legacy version
    ch_record.append(UInt8((ch_n >> 8) & 0xFF))
    ch_record.append(UInt8(ch_n & 0xFF))
    _append_bytes(ch_record, ch_msg)
    _tcp_write(fd, ch_record)

    # Transcript hash: maintain both SHA-256 and SHA-384 hashers until cipher is known
    var th    = SHA256()
    var th384 = SHA384()
    th.update(ch_msg)
    th384.update(ch_msg)

    # ── Step 3: Read ServerHello (plaintext record) ───────────────────────────
    var sh_rec_type: UInt8 = 0
    var sh_rec_body = List[UInt8]()

    # Skip any CCS that may arrive before ServerHello
    while True:
        var rec = _read_tls_record(fd)
        sh_rec_type = rec[0]
        sh_rec_body = rec[1].copy()
        if sh_rec_type == CTYPE_CHANGE_CIPHER_SPEC:
            continue
        if sh_rec_type == CTYPE_ALERT:
            tls_handle_incoming_alert(sh_rec_body)
            raise Error("tls: alert before ServerHello (unreachable)")
        break

    if sh_rec_type != CTYPE_HANDSHAKE:
        raise Error("tls: expected Handshake record for ServerHello")

    var sh_parse = parse_handshake_msg(sh_rec_body, 0)
    var sh_msg_obj = sh_parse[0].copy()
    if sh_msg_obj.msg_type != HS_SERVER_HELLO:
        raise Error("tls: expected ServerHello (0x02), got " + String(Int(sh_msg_obj.msg_type)))

    var sh_full = _wrap_hs_msg(HS_SERVER_HELLO, sh_msg_obj.body)
    th.update(sh_full)
    th384.update(sh_full)

    # ── Step 3b: Complete handshake via tls13_after_server_hello ─────────────
    return tls13_after_server_hello(
        fd, hostname, trust_anchors, ecdhe_private, sh_msg_obj.body, th, th384
    )


def tls13_client_handshake(
    fd:             Int32,
    hostname:       String,
    trust_anchors:  List[X509Cert],
    cipher:         UInt8,
    alpn_protocols: List[String] = List[String](),
) raises -> TlsKeys:
    """Perform a TLS 1.3 client handshake over a connected TCP socket.

    Sends a fatal handshake_failure alert to the peer before propagating any
    error, so the server can cleanly terminate the connection.

    Args:
        fd:             Connected TCP socket file descriptor.
        hostname:       Server hostname (SNI + cert verification).
        trust_anchors:  Trusted root CA certificates.
        cipher:         Preferred cipher hint (server may negotiate differently).
        alpn_protocols: Optional ALPN protocol names to advertise (e.g. ["h2","http/1.1"]).
    Returns:
        TlsKeys with application-layer keying material; keys.negotiated_protocol
        holds the ALPN protocol selected by the server (or "" if none).
    """
    try:
        return _tls13_handshake_impl(fd, hostname, trust_anchors, cipher, alpn_protocols)
    except e:
        tls_send_plaintext_alert(fd, 40)  # handshake_failure
        raise Error(String(e))


# ============================================================================
# Alert handling
# ============================================================================

def tls_send_alert[write_fn: def(List[UInt8]) thin raises -> None](
    keys:     TlsKeys,
    level:    UInt8,
    code:     UInt8,
) raises:
    """Send a TLS alert. Uses plaintext record if keys are not yet established."""
    var alert_body = List[UInt8](capacity=2)
    alert_body.append(level)
    alert_body.append(code)
    if len(keys.client_write_key) > 0:
        var record = record_seal(
            keys.cipher, keys.client_write_key, keys.client_write_iv,
            keys.client_seqno, CTYPE_ALERT, alert_body,
        )
        write_fn(record)
    else:
        write_fn(_make_tls_record(CTYPE_ALERT, alert_body))


def tls_handle_incoming_alert(alert_body: List[UInt8]) raises:
    """Handle an incoming TLS alert record body (RFC 8446 §6). Always raises.

    alert_body[0] = level (1=warning, 2=fatal)
    alert_body[1] = description code
    close_notify (0) at warning level is treated as EOF.
    """
    if len(alert_body) != 2:
        raise Error("tls: malformed alert (decode_error)")
    var level = alert_body[0]
    var code  = alert_body[1]
    # All alerts cause connection termination; just report the description.
    # close_notify carries the canonical "tls: close_notify" string so recv_all
    # can detect EOF.
    if code == 0:
        raise Error("tls: close_notify")
    elif code == 10:
        raise Error("tls: unexpected_message")
    elif code == 20:
        raise Error("tls: bad_record_mac")
    elif code == 22:
        raise Error("tls: record_overflow")
    elif code == 40:
        raise Error("tls: handshake_failure")
    elif code == 42:
        raise Error("tls: bad_certificate")
    elif code == 43:
        raise Error("tls: unsupported_certificate")
    elif code == 44:
        raise Error("tls: certificate_revoked")
    elif code == 45:
        raise Error("tls: certificate_expired")
    elif code == 46:
        raise Error("tls: certificate_unknown")
    elif code == 47:
        raise Error("tls: illegal_parameter")
    elif code == 48:
        raise Error("tls: unknown_ca")
    elif code == 49:
        raise Error("tls: access_denied")
    elif code == 50:
        raise Error("tls: decode_error")
    elif code == 51:
        raise Error("tls: decrypt_error")
    elif code == 70:
        raise Error("tls: protocol_version")
    elif code == 71:
        raise Error("tls: insufficient_security")
    elif code == 80:
        raise Error("tls: internal_error")
    elif code == 86:
        raise Error("tls: inappropriate_fallback")
    elif code == 90:
        raise Error("tls: user_canceled")
    elif code == 109:
        raise Error("tls: missing_extension")
    elif code == 110:
        raise Error("tls: unsupported_extension")
    elif code == 112:
        raise Error("tls: unrecognized_name")
    elif code == 113:
        raise Error("tls: bad_certificate_status_response")
    elif code == 115:
        raise Error("tls: unknown_psk_identity")
    elif code == 116:
        raise Error("tls: certificate_required")
    elif code == 120:
        raise Error("tls: no_application_protocol")
    else:
        raise Error("tls: alert level=" + String(Int(level)) + " code=" + String(Int(code)))


# ============================================================================
# Public TCP I/O — re-exported for use by tls/socket.mojo
# ============================================================================

def tls_tcp_read(fd: Int32, n: Int) raises -> List[UInt8]:
    """Read exactly n bytes from tcp socket fd."""
    return _tcp_read(fd, n)


def tls_tcp_write(fd: Int32, data: List[UInt8]) raises:
    """Write all bytes to tcp socket fd."""
    _tcp_write(fd, data)


def tls_send_plaintext_alert(fd: Int32, code: UInt8):
    """Send a plaintext TLS fatal alert. Best-effort — swallows send errors."""
    var body = List[UInt8](capacity=2)
    body.append(ALERT_LEVEL_FATAL)
    body.append(code)
    var record = _make_tls_record(CTYPE_ALERT, body)
    try:
        _tcp_write(fd, record)
    except:
        pass


def tls_cipher_from_suite(suite: UInt16) raises -> UInt8:
    """Convert TLS 1.3 cipher suite identifier to CIPHER_* constant."""
    return _cipher_from_suite(suite)
