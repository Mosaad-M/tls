# ============================================================================
# tls/connection12.mojo — TLS 1.2 client handshake state machine
# ============================================================================
# API:
#   struct TlsKeys12(Copyable, Movable) — post-handshake keying material
#
#   tls12_client_handshake(fd, hostname, trust_anchors,
#                          client_random, server_random, cipher_suite,
#                          transcript_sha256, transcript_sha384,
#                          use_sha384) raises -> TlsKeys12
#
# Implements RFC 5246 TLS 1.2 full handshake with ECDHE key exchange.
# Supported cipher suites:
#   0xC02F  TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256  (prf_sha256, key_len=16)
#   0xC030  TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384  (prf_sha384, key_len=32)
#   0xC02B  TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 (prf_sha256, key_len=16)
#   0xC02C  TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 (prf_sha384, key_len=32)
# ============================================================================

from std.ffi import external_call
from crypto.hash import SHA256, SHA384, sha256, sha384
from crypto.prf import (
    tls12_master_secret, tls12_key_block, tls12_key_block_sha384,
    tls12_verify_data, tls12_verify_data_sha384,
)
from crypto.record import (
    record_seal_12, record_open_12,
    CIPHER_AES_128_GCM, CIPHER_AES_256_GCM,
    CTYPE_HANDSHAKE, CTYPE_APPLICATION_DATA, CTYPE_CHANGE_CIPHER_SPEC, CTYPE_ALERT,
)
from crypto.cert import X509Cert, cert_parse, cert_chain_verify
from crypto.asn1 import asn1_parse_ecdsa_sig, asn1_parse_ecdsa_sig_48
from crypto.curve25519 import x25519_public_key, x25519
from crypto.random import csprng_bytes
from crypto.p256 import p256_ecdsa_verify, p256_public_key, p256_ecdh, p256_ecdsa_sign
from crypto.p384 import p384_ecdsa_verify
from crypto.rsa import rsa_pkcs1_verify
from tls.message import (
    parse_handshake_msg, HandshakeMsg,
    HS_CERTIFICATE, HS_FINISHED,
)
from tls.message12 import (
    parse_server_key_exchange,
    parse_server_hello_done,
    build_client_key_exchange,
    build_change_cipher_spec_body,
    build_finished_body,
    parse_finished_body,
    parse_certificate_request12,
    build_client_certificate12,
    build_client_certificate_verify12,
    _ecdsa_raw_to_der,
    TLS12_ECDHE_RSA_AES128_GCM_SHA256,
    TLS12_ECDHE_RSA_AES256_GCM_SHA384,
    TLS12_ECDHE_ECDSA_AES128_GCM_SHA256,
    TLS12_ECDHE_ECDSA_AES256_GCM_SHA384,
    NAMED_CURVE_X25519,
    NAMED_CURVE_SECP256R1,
    NAMED_CURVE_SECP384R1,
    HS_CERTIFICATE_REQUEST,
)
from tls.connection import (
    tls_tcp_read, tls_tcp_write,
    tls_handle_incoming_alert,
    tls_send_plaintext_alert,
    ALERT_LEVEL_FATAL, ALERT_CLOSE_NOTIFY,
)


# ── TLS 1.2 handshake message types ──────────────────────────────────────────
comptime HS12_SERVER_KEY_EXCHANGE : UInt8 = 0x0C
comptime HS12_SERVER_HELLO_DONE   : UInt8 = 0x0E
comptime HS12_CLIENT_KEY_EXCHANGE : UInt8 = 0x10


# ============================================================================
# TlsKeys12 — post-handshake keying material for TLS 1.2
# ============================================================================

struct TlsKeys12(Copyable, Movable):
    var cipher:           Int            # CIPHER_AES_128_GCM or CIPHER_AES_256_GCM
    var client_write_key: List[UInt8]
    var server_write_key: List[UInt8]
    var client_write_iv:  List[UInt8]   # 4 bytes (implicit IV)
    var server_write_iv:  List[UInt8]   # 4 bytes (implicit IV)
    var master_secret:    List[UInt8]   # 48 bytes
    var client_seqno:     UInt64
    var server_seqno:     UInt64
    var use_sha384:       Bool          # True for *_SHA384 cipher suites

    def __init__(out self):
        self.cipher           = 0
        self.client_write_key = List[UInt8]()
        self.server_write_key = List[UInt8]()
        self.client_write_iv  = List[UInt8]()
        self.server_write_iv  = List[UInt8]()
        self.master_secret    = List[UInt8]()
        self.client_seqno     = 0
        self.server_seqno     = 0
        self.use_sha384       = False

    def __copyinit__(out self, copy: Self):
        self.cipher           = copy.cipher
        self.client_write_key = copy.client_write_key.copy()
        self.server_write_key = copy.server_write_key.copy()
        self.client_write_iv  = copy.client_write_iv.copy()
        self.server_write_iv  = copy.server_write_iv.copy()
        self.master_secret    = copy.master_secret.copy()
        self.client_seqno     = copy.client_seqno
        self.server_seqno     = copy.server_seqno
        self.use_sha384       = copy.use_sha384

    def __moveinit__(out self, deinit take: Self):
        self.cipher           = take.cipher
        self.client_write_key = take.client_write_key^
        self.server_write_key = take.server_write_key^
        self.client_write_iv  = take.client_write_iv^
        self.server_write_iv  = take.server_write_iv^
        self.master_secret    = take.master_secret^
        self.client_seqno     = take.client_seqno
        self.server_seqno     = take.server_seqno
        self.use_sha384       = take.use_sha384


# ============================================================================
# Internal helpers
# ============================================================================

def _append_bytes12(mut out: List[UInt8], src: List[UInt8]):
    for i in range(len(src)):
        out.append(src[i])


def _make_tls12_record(content_type: UInt8, data: List[UInt8]) -> List[UInt8]:
    """Wrap data in a TLS 1.2 record (5-byte header + data)."""
    var n = len(data)
    var out = List[UInt8](capacity=5 + n)
    out.append(content_type)
    out.append(0x03)   # version hi
    out.append(0x03)   # version lo = TLS 1.2
    out.append(UInt8((n >> 8) & 0xFF))
    out.append(UInt8(n & 0xFF))
    _append_bytes12(out, data)
    return out^


def _wrap_hs_msg12(msg_type: UInt8, body: List[UInt8]) -> List[UInt8]:
    """Wrap body in a 4-byte Handshake header (for transcript)."""
    var out = List[UInt8](capacity=4 + len(body))
    out.append(msg_type)
    var n = len(body)
    out.append(UInt8((n >> 16) & 0xFF))
    out.append(UInt8((n >> 8) & 0xFF))
    out.append(UInt8(n & 0xFF))
    _append_bytes12(out, body)
    return out^


def _transcript_hash12(h: SHA256) -> List[UInt8]:
    var h_copy = h.copy()
    return h_copy.finalize()


def _transcript_hash12_384(h: SHA384) -> List[UInt8]:
    var h_copy = h.copy()
    return h_copy.finalize()


def _parse_cert_chain_12(body: List[UInt8]) raises -> List[List[UInt8]]:
    """Parse TLS 1.2 Certificate message body → list of DER cert bytes.

    TLS 1.2 format: 3-byte list_len + (3-byte cert_len + cert_bytes)*
    (No context byte, no per-cert extensions unlike TLS 1.3)
    """
    if len(body) < 3:
        raise Error("parse_cert_chain_12: body too short")
    var list_len = (Int(body[0]) << 16) | (Int(body[1]) << 8) | Int(body[2])
    var off = 3
    var list_end = off + list_len
    if list_end > len(body):
        raise Error("parse_cert_chain_12: list_len exceeds body")
    var certs = List[List[UInt8]]()
    while off + 3 <= list_end:
        var cert_len = (Int(body[off]) << 16) | (Int(body[off + 1]) << 8) | Int(body[off + 2])
        off += 3
        if off + cert_len > list_end:
            raise Error("parse_cert_chain_12: cert data truncated")
        var cert_der = List[UInt8](capacity=cert_len)
        for i in range(cert_len):
            cert_der.append(body[off + i])
        certs.append(cert_der^)
        off += cert_len
    return certs^


def _verify_ske_signature(
    cert:           X509Cert,
    sig_hash:       UInt8,      # 4=SHA-256, 5=SHA-384
    sig_sig:        UInt8,      # 1=RSA, 3=ECDSA
    sig_bytes:      List[UInt8],
    signed_data:    List[UInt8],
) raises:
    """Verify ServerKeyExchange signature."""
    var msg_hash: List[UInt8]
    if sig_hash == 4:
        msg_hash = sha256(signed_data)
    elif sig_hash == 5:
        msg_hash = sha384(signed_data)
    else:
        raise Error("tls12: unsupported sig_hash " + String(Int(sig_hash)))

    if sig_sig == 1:  # RSA
        if cert.pub_key_alg != "rsa":
            raise Error("tls12: sig is RSA but cert has no RSA key")
        rsa_pkcs1_verify(cert.rsa_n, cert.rsa_e, msg_hash, sig_bytes)
    elif sig_sig == 3:  # ECDSA
        if cert.pub_key_alg != "ec":
            raise Error("tls12: sig is ECDSA but cert has no EC key")
        if sig_hash == 4:  # SHA-256 → P-256
            var sig_res = asn1_parse_ecdsa_sig(sig_bytes)
            p256_ecdsa_verify(cert.ec_point, msg_hash, sig_res[0].copy(), sig_res[1].copy())
        else:  # SHA-384 → P-384
            var sig_res = asn1_parse_ecdsa_sig_48(sig_bytes)
            p384_ecdsa_verify(cert.ec_point, msg_hash, sig_res[0].copy(), sig_res[1].copy())
    else:
        raise Error("tls12: unsupported sig_sig " + String(Int(sig_sig)))


def _read_server_hs12_until_done(fd: Int32) raises -> List[HandshakeMsg]:
    """Read TLS 1.2 server handshake messages until ServerHelloDone.

    Accumulates data across multiple TLS records, handling the common case
    where Certificate + ServerKeyExchange + ServerHelloDone arrive in one record.
    Returns list of HandshakeMsg in arrival order.
    """
    var all_msgs = List[HandshakeMsg]()
    var raw_buf = List[UInt8]()
    var got_shd = False

    while not got_shd:
        # Read one TLS record
        var header = tls_tcp_read(fd, 5)
        var rtype = header[0]
        var rlen = (Int(header[3]) << 8) | Int(header[4])
        var rbody = tls_tcp_read(fd, rlen)

        if rtype == CTYPE_CHANGE_CIPHER_SPEC:
            continue
        if rtype == CTYPE_ALERT:
            tls_handle_incoming_alert(rbody)
            raise Error("tls12: alert before ServerHelloDone (unreachable)")
        if rtype != CTYPE_HANDSHAKE:
            continue

        _append_bytes12(raw_buf, rbody)

        # Parse all complete messages from the buffer
        var parse_off = 0
        while True:
            if parse_off + 4 > len(raw_buf):
                break  # need more data for header
            var mtype = raw_buf[parse_off]
            var mlen = (Int(raw_buf[parse_off + 1]) << 16) | (Int(raw_buf[parse_off + 2]) << 8) | Int(raw_buf[parse_off + 3])
            if parse_off + 4 + mlen > len(raw_buf):
                break  # incomplete message body — read more
            var msg = HandshakeMsg()
            msg.msg_type = mtype
            var body = List[UInt8](capacity=mlen)
            for i in range(mlen):
                body.append(raw_buf[parse_off + 4 + i])
            msg.body = body^
            if mtype == HS12_SERVER_HELLO_DONE:
                got_shd = True
            all_msgs.append(msg^)
            parse_off += 4 + mlen

        # Trim processed bytes from buffer
        var remaining = len(raw_buf) - parse_off
        var new_buf = List[UInt8](capacity=remaining)
        for i in range(parse_off, len(raw_buf)):
            new_buf.append(raw_buf[i])
        raw_buf = new_buf^

    return all_msgs^


def _find_msg12(messages: List[HandshakeMsg], msg_type: UInt8) raises -> List[UInt8]:
    """Find first message of the given type. Raises if not found."""
    for i in range(len(messages)):
        if messages[i].msg_type == msg_type:
            return messages[i].body.copy()
    raise Error("tls12: handshake message type " + String(Int(msg_type)) + " not found")


# ============================================================================
# tls12_client_handshake
# ============================================================================

def _tls12_handshake_impl(
    fd:             Int32,
    hostname:       String,
    trust_anchors:  List[X509Cert],
    client_random:  List[UInt8],
    server_random:  List[UInt8],
    cipher_suite:   UInt16,
    transcript_sha256: SHA256,
    transcript_sha384: SHA384,
    use_sha384:     Bool,
    client_cert:    List[UInt8],   # DER leaf cert (empty = no mTLS)
    client_key:     List[UInt8],   # 32-byte P-256 private scalar (empty = no mTLS)
) raises -> TlsKeys12:
    # Determine cipher parameters
    var key_len = 16
    var cipher = CIPHER_AES_128_GCM
    if cipher_suite == TLS12_ECDHE_RSA_AES256_GCM_SHA384 or cipher_suite == TLS12_ECDHE_ECDSA_AES256_GCM_SHA384:
        key_len = 32
        cipher = CIPHER_AES_256_GCM

    # Maintain local copies of the transcript hashers
    var th    = transcript_sha256.copy()
    var th384 = transcript_sha384.copy()

    # ── Step 1: Read all server handshake messages until ServerHelloDone ──────
    var srv_msgs = _read_server_hs12_until_done(fd)

    var cert_body = _find_msg12(srv_msgs, HS_CERTIFICATE)
    var ske_body  = _find_msg12(srv_msgs, HS12_SERVER_KEY_EXCHANGE)
    var shd_body  = _find_msg12(srv_msgs, HS12_SERVER_HELLO_DONE)

    # Check for optional CertificateRequest
    var cert_req_body = List[UInt8]()
    var has_cert_req = False
    for i in range(len(srv_msgs)):
        if srv_msgs[i].msg_type == HS_CERTIFICATE_REQUEST:
            cert_req_body = srv_msgs[i].body.copy()
            has_cert_req = True
            break

    # Update transcript in RFC 5246 §7.3 message order
    th.update(_wrap_hs_msg12(HS_CERTIFICATE, cert_body))
    th384.update(_wrap_hs_msg12(HS_CERTIFICATE, cert_body))
    th.update(_wrap_hs_msg12(HS12_SERVER_KEY_EXCHANGE, ske_body))
    th384.update(_wrap_hs_msg12(HS12_SERVER_KEY_EXCHANGE, ske_body))
    if has_cert_req:
        th.update(_wrap_hs_msg12(HS_CERTIFICATE_REQUEST, cert_req_body))
        th384.update(_wrap_hs_msg12(HS_CERTIFICATE_REQUEST, cert_req_body))
    th.update(_wrap_hs_msg12(HS12_SERVER_HELLO_DONE, shd_body))
    th384.update(_wrap_hs_msg12(HS12_SERVER_HELLO_DONE, shd_body))

    # ── Step 2: Parse certificate chain (TLS 1.2 format) ─────────────────────
    parse_server_hello_done(shd_body)  # validates empty body

    var cert_ders = _parse_cert_chain_12(cert_body)
    if len(cert_ders) == 0:
        raise Error("tls12: no certificates in Certificate message")

    var cert_chain = List[X509Cert]()
    for i in range(len(cert_ders)):
        cert_chain.append(cert_parse(cert_ders[i]))

    # ── Step 3: Verify certificate chain ─────────────────────────────────────
    cert_chain_verify(cert_chain, trust_anchors, hostname)

    # ── Step 4: Parse and verify ServerKeyExchange signature ─────────────────
    var ske_result = parse_server_key_exchange(ske_body)
    var named_curve   = ske_result[0]
    var server_pubkey = ske_result[1].copy()
    var sig_hash      = ske_result[2]
    var sig_sig       = ske_result[3]
    var sig_bytes     = ske_result[4].copy()

    if named_curve != NAMED_CURVE_X25519 and named_curve != NAMED_CURVE_SECP256R1:
        raise Error("tls12: unsupported ECDHE curve " + String(Int(named_curve)))

    # Signed data = client_random || server_random || SKE params
    var signed_data = List[UInt8]()
    _append_bytes12(signed_data, client_random)
    _append_bytes12(signed_data, server_random)
    signed_data.append(0x03)   # curve_type = named_curve
    signed_data.append(UInt8(named_curve >> 8))
    signed_data.append(UInt8(named_curve & 0xFF))
    signed_data.append(UInt8(len(server_pubkey)))
    _append_bytes12(signed_data, server_pubkey)

    _verify_ske_signature(cert_chain[0], sig_hash, sig_sig, sig_bytes, signed_data)

    # ── Step 5: Generate ephemeral ECDHE key pair (curve-specific) ───────────
    var ecdhe_private = csprng_bytes(32)
    var ecdhe_public: List[UInt8]
    var pre_master: List[UInt8]
    if named_curve == NAMED_CURVE_X25519:
        ecdhe_public = x25519_public_key(ecdhe_private)
        # ── Step 6: Compute pre_master secret (x25519) ──────────────────────
        pre_master = x25519(ecdhe_private, server_pubkey)
    else:
        # named_curve == NAMED_CURVE_SECP256R1
        ecdhe_public = p256_public_key(ecdhe_private)
        # ── Step 6: Compute pre_master secret (P-256 ECDH) ──────────────────
        pre_master = p256_ecdh(ecdhe_private, server_pubkey)

    # ── Step 7: Derive master secret ─────────────────────────────────────────
    var master = tls12_master_secret(pre_master, client_random, server_random)

    # ── Step 8: Derive key block ──────────────────────────────────────────────
    # key_block length = 2 * (key_len + 4)
    var kb_len = 2 * (key_len + 4)
    var key_block: List[UInt8]
    if use_sha384:
        key_block = tls12_key_block_sha384(master, server_random, client_random, kb_len)
    else:
        key_block = tls12_key_block(master, server_random, client_random, kb_len)

    # Extract keys and 4-byte implicit IVs
    var client_key = List[UInt8](capacity=key_len)
    var server_key = List[UInt8](capacity=key_len)
    var client_iv  = List[UInt8](capacity=4)
    var server_iv  = List[UInt8](capacity=4)
    for i in range(key_len):
        client_key.append(key_block[i])
    for i in range(key_len):
        server_key.append(key_block[key_len + i])
    for i in range(4):
        client_iv.append(key_block[2 * key_len + i])
    for i in range(4):
        server_iv.append(key_block[2 * key_len + 4 + i])

    # ── Step 9a: Send client Certificate (if server requested it) ────────────
    # RFC 5246 §7.3: Certificate comes BEFORE ClientKeyExchange
    if has_cert_req:
        var cli_cert_chain = List[List[UInt8]]()
        if len(client_cert) > 0:
            cli_cert_chain.append(client_cert.copy())
        var cli_cert_msg = build_client_certificate12(cli_cert_chain)
        # cli_cert_msg already has 4-byte HS header; update transcript directly
        th.update(cli_cert_msg)
        th384.update(cli_cert_msg)
        var cli_cert_record = _make_tls12_record(CTYPE_HANDSHAKE, cli_cert_msg)
        tls_tcp_write(fd, cli_cert_record)

    # ── Step 9: Send ClientKeyExchange ────────────────────────────────────────
    var cke_body = build_client_key_exchange(ecdhe_public)
    var cke_hs   = _wrap_hs_msg12(HS12_CLIENT_KEY_EXCHANGE, cke_body)
    th.update(cke_hs)
    th384.update(cke_hs)
    var cke_record = _make_tls12_record(CTYPE_HANDSHAKE, cke_hs)
    tls_tcp_write(fd, cke_record)

    # ── Step 9b: Send CertificateVerify (if we sent a certificate) ────────────
    # RFC 5246 §7.4.8: signs transcript hash through ClientKeyExchange
    if has_cert_req and len(client_cert) > 0 and len(client_key) > 0:
        var cv_hash: List[UInt8]
        if use_sha384:
            cv_hash = _transcript_hash12_384(th384)
        else:
            cv_hash = _transcript_hash12(th)
        var nonce = csprng_bytes(32)
        var sig_rs = p256_ecdsa_sign(client_key, cv_hash, nonce)
        var r = sig_rs[0].copy()
        var s = sig_rs[1].copy()
        var sig_der = _ecdsa_raw_to_der(r, s)
        # SHA-256 hash alg (4), ECDSA sig alg (3)
        var cv_msg = build_client_certificate_verify12(4, 3, sig_der)
        th.update(cv_msg)
        th384.update(cv_msg)
        var cv_record = _make_tls12_record(CTYPE_HANDSHAKE, cv_msg)
        tls_tcp_write(fd, cv_record)

    # ── Step 10: Send ChangeCipherSpec ────────────────────────────────────────
    var ccs_body   = build_change_cipher_spec_body()
    var ccs_record = _make_tls12_record(CTYPE_CHANGE_CIPHER_SPEC, ccs_body)
    tls_tcp_write(fd, ccs_record)

    # ── Step 11: Send client Finished (encrypted) ─────────────────────────────
    var c_hash: List[UInt8]
    if use_sha384:
        c_hash = _transcript_hash12_384(th384)
    else:
        c_hash = _transcript_hash12(th)

    var c_vd: List[UInt8]
    if use_sha384:
        c_vd = tls12_verify_data_sha384(master, "client finished", c_hash)
    else:
        c_vd = tls12_verify_data(master, "client finished", c_hash)

    var fin_hs = build_finished_body(c_vd)
    th.update(fin_hs)
    th384.update(fin_hs)

    var fin_payload = record_seal_12(cipher, client_key, client_iv, UInt64(0), CTYPE_HANDSHAKE, fin_hs)
    var fin_total   = List[UInt8](capacity=5 + len(fin_payload))
    fin_total.append(CTYPE_HANDSHAKE)
    fin_total.append(0x03)
    fin_total.append(0x03)
    fin_total.append(UInt8((len(fin_payload) >> 8) & 0xFF))
    fin_total.append(UInt8(len(fin_payload) & 0xFF))
    _append_bytes12(fin_total, fin_payload)
    tls_tcp_write(fd, fin_total)

    # ── Step 12: Read server ChangeCipherSpec + Finished ──────────────────────
    # Read records until we find the encrypted Finished
    var srv_fin_plain = List[UInt8]()
    var found_fin = False

    while not found_fin:
        var rec_header = tls_tcp_read(fd, 5)
        var srv_rtype  = rec_header[0]
        var srv_rlen   = (Int(rec_header[3]) << 8) | Int(rec_header[4])
        var srv_rbody  = tls_tcp_read(fd, srv_rlen)

        if srv_rtype == CTYPE_CHANGE_CIPHER_SPEC:
            continue  # skip server's CCS

        if srv_rtype == CTYPE_ALERT:
            tls_handle_incoming_alert(srv_rbody)
            raise Error("tls12: alert from server (unreachable)")

        if srv_rtype != CTYPE_HANDSHAKE:
            continue  # skip unexpected record types

        # Decrypt the server's Finished record
        srv_fin_plain = record_open_12(
            cipher, server_key, server_iv, UInt64(0), CTYPE_HANDSHAKE, srv_rbody
        )
        found_fin = True

    var srv_vd = parse_finished_body(srv_fin_plain)

    # Server's verify_data covers transcript through client Finished
    # (already in th/th384 from step 11 — do NOT add server Finished)
    var s_hash: List[UInt8]
    if use_sha384:
        s_hash = _transcript_hash12_384(th384)
    else:
        s_hash = _transcript_hash12(th)

    var expected_srv_vd: List[UInt8]
    if use_sha384:
        expected_srv_vd = tls12_verify_data_sha384(master, "server finished", s_hash)
    else:
        expected_srv_vd = tls12_verify_data(master, "server finished", s_hash)

    if len(srv_vd) != len(expected_srv_vd):
        raise Error("tls12: server Finished verify_data length mismatch")
    for i in range(len(srv_vd)):
        if srv_vd[i] != expected_srv_vd[i]:
            raise Error("tls12: server Finished verify_data mismatch at byte " + String(i))

    # ── Step 13: Build and return TlsKeys12 ───────────────────────────────────
    var keys = TlsKeys12()
    keys.cipher           = Int(cipher)
    keys.client_write_key = client_key^
    keys.server_write_key = server_key^
    keys.client_write_iv  = client_iv^
    keys.server_write_iv  = server_iv^
    keys.master_secret    = master^
    keys.client_seqno     = 1  # seqno 0 was used for client Finished
    keys.server_seqno     = 1  # seqno 0 was used for server Finished
    keys.use_sha384       = use_sha384
    return keys^


def tls12_client_handshake(
    fd:             Int32,
    hostname:       String,
    trust_anchors:  List[X509Cert],
    client_random:  List[UInt8],    # 32 bytes from ClientHello
    server_random:  List[UInt8],    # 32 bytes from ServerHello
    cipher_suite:   UInt16,
    transcript_sha256: SHA256,      # hash of ClientHello + ServerHello so far
    transcript_sha384: SHA384,
    use_sha384:     Bool,
) raises -> TlsKeys12:
    """Perform TLS 1.2 client handshake after ClientHello+ServerHello exchange.

    Sends a fatal handshake_failure alert before propagating any error.
    """
    try:
        return _tls12_handshake_impl(
            fd, hostname, trust_anchors,
            client_random, server_random, cipher_suite,
            transcript_sha256, transcript_sha384, use_sha384,
            List[UInt8](), List[UInt8](),
        )
    except e:
        tls_send_plaintext_alert(fd, 40)  # handshake_failure
        raise Error(String(e))


def tls12_client_handshake_mtls(
    fd:             Int32,
    hostname:       String,
    trust_anchors:  List[X509Cert],
    client_random:  List[UInt8],
    server_random:  List[UInt8],
    cipher_suite:   UInt16,
    transcript_sha256: SHA256,
    transcript_sha384: SHA384,
    use_sha384:     Bool,
    client_cert:    List[UInt8],   # DER-encoded leaf certificate
    client_key:     List[UInt8],   # 32-byte P-256 private scalar
) raises -> TlsKeys12:
    """TLS 1.2 mTLS handshake: responds to CertificateRequest with P-256 ECDSA auth.

    Both client_cert and client_key must be provided together.
    Sends a fatal handshake_failure alert before propagating any error.
    """
    if len(client_cert) == 0 or len(client_key) == 0:
        raise Error("mTLS: must provide both client_cert and client_key")
    try:
        return _tls12_handshake_impl(
            fd, hostname, trust_anchors,
            client_random, server_random, cipher_suite,
            transcript_sha256, transcript_sha384, use_sha384,
            client_cert, client_key,
        )
    except e:
        tls_send_plaintext_alert(fd, 40)  # handshake_failure
        raise Error(String(e))
