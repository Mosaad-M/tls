# ============================================================================
# tls/connection.mojo — TLS 1.3 client handshake state machine
# ============================================================================
# API:
#   tls13_client_handshake(fd, hostname, trust_anchors, cipher) → TlsKeys
#       fd: connected TCP socket file descriptor (Int32)
#
# TlsKeys struct holds all post-handshake keying material.
# ============================================================================

from std.ffi import external_call
from std.memory.unsafe_pointer import alloc
from crypto.hash import SHA256, SHA384, sha256, sha384
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
from crypto.curve25519 import x25519_public_key, x25519
from crypto.random import csprng_bytes
from crypto.p256 import p256_ecdsa_verify
from crypto.p384 import p384_ecdsa_verify
from crypto.rsa import rsa_pkcs1_verify, rsa_pss_verify
from tls.message import (
    build_client_hello, build_finished,
    parse_handshake_msg, parse_server_hello, parse_server_hello_key_share,
    parse_certificate_chain, parse_cert_verify, parse_finished,
    parse_new_session_ticket, parse_alpn_from_ee, SessionTicket,
    HandshakeMsg,
    HS_SERVER_HELLO, HS_ENCRYPTED_EXTS, HS_CERTIFICATE,
    HS_CERT_VERIFY, HS_FINISHED, HS_NEW_SESSION_TICKET,
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


# ============================================================================
# TCP I/O helpers (FFI: read / write system calls)
# ============================================================================

def _tcp_read(fd: Int32, n: Int) raises -> List[UInt8]:
    """Read exactly n bytes from the socket fd. Raises on error or EOF."""
    if n == 0:
        return List[UInt8]()
    var buf = alloc[UInt8](n)
    var total = 0
    while total < n:
        var got = external_call["read", Int](fd, buf + total, n - total)
        if got <= 0:
            buf.free()
            raise Error("tls: tcp read failed or connection closed")
        total += got
    var out = List[UInt8](capacity=n)
    for i in range(n):
        out.append((buf + i)[])
    buf.free()
    return out^


def _tcp_write(fd: Int32, data: List[UInt8]) raises:
    """Write all bytes to the socket fd."""
    var n = len(data)
    if n == 0:
        return
    var buf = alloc[UInt8](n)
    for i in range(n):
        (buf + i)[] = data[i]
    var total = 0
    while total < n:
        var sent = external_call["write", Int](Int(fd), buf + total, n - total)
        if sent <= 0:
            buf.free()
            raise Error("tls: tcp write failed")
        total += sent
    buf.free()


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
    """Verify CertificateVerify signature."""
    if sig_scheme == 0x0403:  # ecdsa_secp256r1_sha256
        if cert.pub_key_alg != "ec":
            raise Error("tls: sig_scheme ECDSA but cert has no EC key")
        var msg_hash = sha256(cv_input)
        var sig_res = asn1_parse_ecdsa_sig(sig_bytes)
        p256_ecdsa_verify(cert.ec_point, msg_hash, sig_res[0].copy(), sig_res[1].copy())
    elif sig_scheme == 0x0502:  # ecdsa_secp384r1_sha384
        if cert.pub_key_alg != "ec":
            raise Error("tls: sig_scheme ECDSA P-384 but cert has no EC key")
        var msg_hash = sha384(cv_input)
        var sig_res = asn1_parse_ecdsa_sig_48(sig_bytes)
        p384_ecdsa_verify(cert.ec_point, msg_hash, sig_res[0].copy(), sig_res[1].copy())
    elif sig_scheme == 0x0401:  # rsa_pkcs1_sha256
        if cert.pub_key_alg != "rsa":
            raise Error("tls: sig_scheme RSA-PKCS1 but cert has no RSA key")
        var msg_hash = sha256(cv_input)
        rsa_pkcs1_verify(cert.rsa_n, cert.rsa_e, msg_hash, sig_bytes)
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
    else:
        raise Error("tls: unsupported sig_scheme " + String(Int(sig_scheme)))


# ============================================================================
# Read all encrypted server handshake messages until Finished
# ============================================================================

def _read_server_hs_messages(
    fd:         Int32,
    cipher:     UInt8,
    hs_key:     List[UInt8],
    hs_iv:      List[UInt8],
    mut seqno:  UInt64,
) raises -> List[HandshakeMsg]:
    """Read encrypted server handshake messages until Finished.
    Handles multiple messages per record and multiple records.
    """
    var all_msgs = List[HandshakeMsg]()
    var got_finished = False

    while not got_finished:
        var rec = _read_tls_record(fd)
        var rtype = rec[0]
        var rbody = rec[1].copy()

        # Skip ChangeCipherSpec (TLS 1.3 compat)
        if rtype == CTYPE_CHANGE_CIPHER_SPEC:
            continue

        if rtype == CTYPE_ALERT:
            tls_handle_incoming_alert(rbody)
            raise Error("tls: alert (unreachable)")

        if rtype != CTYPE_APPLICATION_DATA:
            raise Error("tls: expected ApplicationData, got " + String(Int(rtype)))

        # Reconstruct full record for record_open
        var full_record = _make_tls_record(rtype, rbody)
        var decrypted = record_open(cipher, hs_key, hs_iv, seqno, full_record)
        seqno += 1

        var inner_type = decrypted[0]
        var plaintext  = decrypted[1].copy()

        if inner_type == CTYPE_CHANGE_CIPHER_SPEC:
            continue
        if inner_type == CTYPE_ALERT:
            tls_handle_incoming_alert(plaintext)
            raise Error("tls: alert (unreachable)")
        if inner_type != CTYPE_HANDSHAKE:
            # Skip NewSessionTicket etc. that arrive here
            continue

        # Parse all handshake messages within this record
        var off = 0
        while off < len(plaintext):
            var res = parse_handshake_msg(plaintext, off)
            var msg = res[0].copy()
            off = res[1]
            if msg.msg_type == HS_FINISHED:
                got_finished = True
            all_msgs.append(msg^)

    return all_msgs^


def _find_msg(messages: List[HandshakeMsg], msg_type: UInt8) raises -> List[UInt8]:
    """Find first message of the given type. Raises if not found."""
    for i in range(len(messages)):
        if messages[i].msg_type == msg_type:
            return messages[i].body.copy()
    raise Error("tls: handshake message type " + String(Int(msg_type)) + " not found")


# ============================================================================
# tls13_after_server_hello — complete TLS 1.3 handshake after SH exchange
# ============================================================================

def tls13_after_server_hello(
    fd:                Int32,
    hostname:          String,
    trust_anchors:     List[X509Cert],
    ecdhe_private:     List[UInt8],
    server_hello_body: List[UInt8],
    th:                SHA256,         # transcript hasher (updated with CH+SH)
    th384:             SHA384,
) raises -> TlsKeys:
    """Complete TLS 1.3 handshake after ClientHello+ServerHello exchange.

    Derives HS keys, reads/verifies server messages, sends client Finished,
    derives application traffic keys.
    Args:
        ecdhe_private: Client ephemeral private key (32 bytes)
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
    var server_pub_key = parse_server_hello_key_share(server_hello.extensions)
    var dhe_shared = x25519(ecdhe_private, server_pub_key)

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

    var server_seqno: UInt64 = 0

    # ── Read all server encrypted handshake messages ──────────────────────────
    var hs_msgs = _read_server_hs_messages(
        fd, negotiated_cipher, server_hs_key, server_hs_iv, server_seqno
    )

    var ee_body   = _find_msg(hs_msgs, HS_ENCRYPTED_EXTS)
    var alpn_proto = parse_alpn_from_ee(ee_body)
    var cert_body = _find_msg(hs_msgs, HS_CERTIFICATE)
    var cv_body   = _find_msg(hs_msgs, HS_CERT_VERIFY)
    var fin_body  = _find_msg(hs_msgs, HS_FINISHED)

    # Update transcript hashers in handshake message order
    th_local.update(_wrap_hs_msg(HS_ENCRYPTED_EXTS, ee_body))
    th384_local.update(_wrap_hs_msg(HS_ENCRYPTED_EXTS, ee_body))
    th_local.update(_wrap_hs_msg(HS_CERTIFICATE, cert_body))
    th384_local.update(_wrap_hs_msg(HS_CERTIFICATE, cert_body))

    var th_for_cv: List[UInt8]
    if use_sha384:
        th_for_cv = _transcript_hash_sha384(th384_local)
    else:
        th_for_cv = _transcript_hash(th_local)
    th_local.update(_wrap_hs_msg(HS_CERT_VERIFY, cv_body))
    th384_local.update(_wrap_hs_msg(HS_CERT_VERIFY, cv_body))

    var th_for_fin: List[UInt8]
    if use_sha384:
        th_for_fin = _transcript_hash_sha384(th384_local)
    else:
        th_for_fin = _transcript_hash(th_local)
    th_local.update(_wrap_hs_msg(HS_FINISHED, fin_body))
    th384_local.update(_wrap_hs_msg(HS_FINISHED, fin_body))

    # ── Verify certificate chain ──────────────────────────────────────────────
    var cert_ders = parse_certificate_chain(cert_body)
    var cert_chain = List[X509Cert]()
    for i in range(len(cert_ders)):
        cert_chain.append(cert_parse(cert_ders[i]))
    cert_chain_verify(cert_chain, trust_anchors, hostname)

    # ── Verify CertificateVerify ──────────────────────────────────────────────
    var cv_result  = parse_cert_verify(cv_body)
    var sig_scheme = cv_result[0]
    var sig_bytes  = cv_result[1].copy()
    var cv_input   = tls13_cert_verify_input(CERT_VERIFY_SERVER_CTX, th_for_cv)
    _verify_cert_verify_sig(cert_chain[0], sig_scheme, sig_bytes, cv_input)

    # ── Verify server Finished ────────────────────────────────────────────────
    var server_vd = parse_finished(fin_body)
    if use_sha384:
        var s_fkey = tls13_finished_key_sha384(s_hs_ts)
        tls13_verify_finished_sha384(s_fkey, th_for_fin, server_vd)
    else:
        var s_fkey = tls13_finished_key(s_hs_ts)
        tls13_verify_finished(s_fkey, th_for_fin, server_vd)

    # ── Send client Finished ──────────────────────────────────────────────────
    var th_for_c_fin: List[UInt8]
    var client_vd: List[UInt8]
    var client_hs_key: List[UInt8]
    var client_hs_iv: List[UInt8]

    if use_sha384:
        var c_hs_kp = tls13_traffic_keys_sha384(c_hs_ts, key_len, 12)
        client_hs_key = c_hs_kp[0].copy()
        client_hs_iv  = c_hs_kp[1].copy()
        th_for_c_fin = _transcript_hash_sha384(th384_local)
        var c_fkey = tls13_finished_key_sha384(c_hs_ts)
        client_vd = tls13_compute_finished_sha384(c_fkey, th_for_c_fin)
    else:
        var c_hs_kp = tls13_traffic_keys(c_hs_ts, key_len, 12)
        client_hs_key = c_hs_kp[0].copy()
        client_hs_iv  = c_hs_kp[1].copy()
        th_for_c_fin = _transcript_hash(th_local)
        var c_fkey = tls13_finished_key(c_hs_ts)
        client_vd = tls13_compute_finished(c_fkey, th_for_c_fin)

    var client_fin_msg = build_finished(client_vd)
    var client_fin_sealed = record_seal(
        negotiated_cipher, client_hs_key, client_hs_iv, 0, CTYPE_HANDSHAKE, client_fin_msg
    )
    _tcp_write(fd, client_fin_sealed)

    # ── Derive application traffic keys ───────────────────────────────────────
    # RFC 8446 §7.1: c/s ap traffic use transcript through server Finished
    var c_ap_key: List[UInt8]
    var c_ap_iv: List[UInt8]
    var s_ap_key: List[UInt8]
    var s_ap_iv: List[UInt8]
    var res_secret: List[UInt8]

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

def tls_send_alert(
    write_fn: def(List[UInt8]) raises -> None,
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
    if len(alert_body) < 2:
        raise Error("tls: malformed alert")
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
