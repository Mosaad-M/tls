# ============================================================================
# tls/message12.mojo — TLS 1.2 wire-format message parsers and builders
# ============================================================================
# API:
#   parse_server_hello_version(body) → (cipher, server_random, session_id, use_tls13)
#   parse_server_key_exchange(body)  → (named_curve, ecdhe_pubkey, sig_hash, sig_sig, sig_bytes)
#   parse_server_hello_done(body)    raises if body not empty
#   build_client_key_exchange(pubkey) → bytes
#   build_change_cipher_spec_body()  → [0x01]
#   build_finished_body(verify_data) → bytes (12-byte verify_data)
#   parse_finished_body(body)        → 12 bytes
# ============================================================================

from tls.message import (
    _read_u8, _read_u16be, _read_u24be, _slice,
    _append_u8, _append_u16be, _append_u24be, _append_bytes,
    parse_server_hello,
    EXT_SUPPORTED_VERSIONS,
    HS_FINISHED,
)


# ── TLS 1.2 named groups ──────────────────────────────────────────────────────
comptime NAMED_CURVE_X25519    : UInt16 = 0x001D
comptime NAMED_CURVE_SECP256R1 : UInt16 = 0x0017
comptime NAMED_CURVE_SECP384R1 : UInt16 = 0x0018

# ── TLS 1.2 cipher suites ─────────────────────────────────────────────────────
comptime TLS12_ECDHE_RSA_AES128_GCM_SHA256   : UInt16 = 0xC02F
comptime TLS12_ECDHE_RSA_AES256_GCM_SHA384   : UInt16 = 0xC030
comptime TLS12_ECDHE_ECDSA_AES128_GCM_SHA256 : UInt16 = 0xC02B
comptime TLS12_ECDHE_ECDSA_AES256_GCM_SHA384 : UInt16 = 0xC02C


# ── TLS 1.2 handshake types ───────────────────────────────────────────────────
comptime HS_CERTIFICATE_REQUEST : UInt8 = 0x0D
comptime HS_CERTIFICATE         : UInt8 = 0x0B
comptime HS_CERTIFICATE_VERIFY  : UInt8 = 0x0F


# ============================================================================
# parse_server_hello_version
# ============================================================================

def parse_server_hello_version(body: List[UInt8]) raises -> Tuple[UInt16, List[UInt8], List[UInt8], Bool]:
    """Parse ServerHello body, determine TLS version.

    Returns (cipher, server_random[32], session_id, use_tls13).
    TLS 1.3 is detected by presence of supported_versions extension with 0x0304.
    TLS 1.2 ServerHello lacks this extension.
    """
    var sh = parse_server_hello(body)

    # Check supported_versions extension for TLS 1.3 indicator
    var use_tls13 = False
    var ext_bytes = sh.extensions.copy()
    var off = 0
    while off + 4 <= len(ext_bytes):
        var ext_type = _read_u16be(ext_bytes, off)
        var ext_len  = Int(_read_u16be(ext_bytes, off + 2))
        off += 4
        if off + ext_len > len(ext_bytes):
            break
        if ext_type == EXT_SUPPORTED_VERSIONS:
            # In ServerHello, supported_versions contains exactly 2 bytes (the chosen version)
            if ext_len >= 2:
                var chosen = _read_u16be(ext_bytes, off)
                if chosen == 0x0304:
                    use_tls13 = True
        off += ext_len

    var cipher = sh.cipher_suite
    var rand   = sh.random.copy()
    var sid    = sh.session_id.copy()
    return (cipher, rand^, sid^, use_tls13)


# ============================================================================
# parse_server_key_exchange
# ============================================================================

def parse_server_key_exchange(body: List[UInt8]) raises -> Tuple[UInt16, List[UInt8], UInt8, UInt8, List[UInt8]]:
    """Parse ServerKeyExchange for ECDHE named curve.

    Returns (named_curve, ecdhe_pubkey, sig_hash_alg, sig_sig_alg, sig_bytes).
    Supports:
      - curve_type = 3 (named_curve)
      - TLS 1.2 signature algorithms
    """
    var off = 0
    # curve_type (1 byte): must be 3 (named_curve)
    if off >= len(body):
        raise Error("parse_ske: body empty")
    var curve_type = body[off]
    off += 1
    if curve_type != 3:
        raise Error("parse_ske: unsupported curve_type " + String(Int(curve_type)))

    # named_curve (2 bytes)
    if off + 2 > len(body):
        raise Error("parse_ske: truncated at named_curve")
    var named_curve = _read_u16be(body, off)
    off += 2

    # public key (1-byte length + bytes)
    if off >= len(body):
        raise Error("parse_ske: truncated at pubkey_len")
    var pubkey_len = Int(body[off])
    off += 1
    if off + pubkey_len > len(body):
        raise Error("parse_ske: pubkey truncated")
    var pubkey = _slice(body, off, off + pubkey_len)
    off += pubkey_len

    # signature algorithm (TLS 1.2): hash_alg(1) + sig_alg(1)
    if off + 2 > len(body):
        raise Error("parse_ske: truncated at sig_alg")
    var sig_hash = body[off]
    var sig_sig  = body[off + 1]
    off += 2

    # signature bytes (2-byte length + bytes)
    if off + 2 > len(body):
        raise Error("parse_ske: truncated at sig_len")
    var sig_len = Int(_read_u16be(body, off))
    off += 2
    if off + sig_len > len(body):
        raise Error("parse_ske: sig bytes truncated")
    var sig_bytes = _slice(body, off, off + sig_len)

    return (named_curve, pubkey^, sig_hash, sig_sig, sig_bytes^)


# ============================================================================
# parse_server_hello_done
# ============================================================================

def parse_server_hello_done(body: List[UInt8]) raises:
    """Validate ServerHelloDone body. Raises if not empty."""
    if len(body) != 0:
        raise Error("parse_server_hello_done: expected empty body, got " + String(len(body)))


# ============================================================================
# build_client_key_exchange
# ============================================================================

def build_client_key_exchange(pubkey: List[UInt8]) -> List[UInt8]:
    """Build ClientKeyExchange body for ECDHE: 1-byte length + public key bytes."""
    var out = List[UInt8](capacity=1 + len(pubkey))
    _append_u8(out, UInt8(len(pubkey)))
    _append_bytes(out, pubkey)
    return out^


# ============================================================================
# build_change_cipher_spec_body
# ============================================================================

def build_change_cipher_spec_body() -> List[UInt8]:
    """Build ChangeCipherSpec body: always [0x01]."""
    var out = List[UInt8](capacity=1)
    out.append(0x01)
    return out^


# ============================================================================
# build_finished_body
# ============================================================================

def build_finished_body(verify_data: List[UInt8]) -> List[UInt8]:
    """Build TLS 1.2 Finished handshake message body.

    Returns Handshake header (type + 3-byte length) + verify_data.
    verify_data must be 12 bytes.
    """
    var out = List[UInt8](capacity=4 + len(verify_data))
    _append_u8(out, HS_FINISHED)  # 0x14
    _append_u24be(out, len(verify_data))
    _append_bytes(out, verify_data)
    return out^


# ============================================================================
# parse_finished_body
# ============================================================================

def parse_finished_body(body: List[UInt8]) raises -> List[UInt8]:
    """Parse TLS 1.2 Finished handshake body → 12-byte verify_data.

    Input is the Handshake body (4-byte header + verify_data).
    """
    if len(body) < 4:
        raise Error("parse_finished_body: too short for header")
    var msg_type = body[0]
    if msg_type != HS_FINISHED:
        raise Error("parse_finished_body: expected Finished (0x14), got " + String(Int(msg_type)))
    var vd_len = _read_u24be(body, 1)
    if vd_len != 12:
        raise Error("parse_finished_body: expected 12-byte verify_data, got " + String(vd_len))
    if 4 + vd_len > len(body):
        raise Error("parse_finished_body: body truncated")
    return _slice(body, 4, 4 + vd_len)


# ============================================================================
# CertificateRequest12
# ============================================================================

struct CertificateRequest12(Copyable, Movable):
    """RFC 5246 §7.4.4 CertificateRequest parsed fields."""
    var certificate_types:         List[UInt8]    # e.g. [1=RSA, 64=ECDSA]
    var supported_signature_algs:  List[UInt16]   # packed (hash_alg << 8 | sig_alg)
    var certificate_authorities:   List[List[UInt8]]  # DER-encoded DNs (may be empty)

    def __init__(out self):
        self.certificate_types        = List[UInt8]()
        self.supported_signature_algs = List[UInt16]()
        self.certificate_authorities  = List[List[UInt8]]()

    def __copyinit__(out self, copy: Self):
        self.certificate_types        = copy.certificate_types.copy()
        self.supported_signature_algs = copy.supported_signature_algs.copy()
        self.certificate_authorities  = List[List[UInt8]]()
        for i in range(len(copy.certificate_authorities)):
            self.certificate_authorities.append(copy.certificate_authorities[i].copy())

    def __moveinit__(out self, deinit take: Self):
        self.certificate_types        = take.certificate_types^
        self.supported_signature_algs = take.supported_signature_algs^
        self.certificate_authorities  = take.certificate_authorities^


# ============================================================================
# parse_certificate_request12
# ============================================================================

def parse_certificate_request12(body: List[UInt8]) raises -> CertificateRequest12:
    """RFC 5246 §7.4.4 — parse CertificateRequest handshake body."""
    var off = 0
    var cr = CertificateRequest12()

    # certificate_types: 1-byte count + bytes
    if off >= len(body):
        raise Error("parse_certreq12: truncated at types_len")
    var types_len = Int(body[off])
    off += 1
    if off + types_len > len(body):
        raise Error("parse_certreq12: truncated at types")
    for i in range(types_len):
        cr.certificate_types.append(body[off + i])
    off += types_len

    # supported_signature_algorithms: 2-byte length + list of 2-byte pairs
    if off + 2 > len(body):
        raise Error("parse_certreq12: truncated at sig_algs_len")
    var algs_len = Int(_read_u16be(body, off))
    off += 2
    if off + algs_len > len(body):
        raise Error("parse_certreq12: truncated at sig_algs")
    var algs_end = off + algs_len
    while off + 2 <= algs_end:
        var pair = (UInt16(body[off]) << 8) | UInt16(body[off + 1])
        cr.supported_signature_algs.append(pair)
        off += 2
    off = algs_end

    # certificate_authorities: 2-byte total length + list of (2-byte dn_len + DN bytes)
    if off + 2 > len(body):
        raise Error("parse_certreq12: truncated at ca_list_len")
    var ca_list_len = Int(_read_u16be(body, off))
    off += 2
    if off + ca_list_len > len(body):
        raise Error("parse_certreq12: truncated at ca_list")
    var ca_end = off + ca_list_len
    while off + 2 <= ca_end:
        var dn_len = Int(_read_u16be(body, off))
        off += 2
        if off + dn_len > ca_end:
            raise Error("parse_certreq12: truncated at ca dn")
        cr.certificate_authorities.append(_slice(body, off, off + dn_len))
        off += dn_len

    return cr^


# ============================================================================
# _ecdsa_raw_to_der
# ============================================================================

def _ecdsa_raw_to_der(r: List[UInt8], s: List[UInt8]) raises -> List[UInt8]:
    """Encode raw (r[32], s[32]) as DER SEQUENCE { INTEGER r, INTEGER s }.

    Strips leading zero bytes; prepends 0x00 if high bit is set (sign extension).
    """
    # Strip leading zeros from r and s
    var ri = 0
    while ri < len(r) - 1 and r[ri] == 0:
        ri += 1
    var si = 0
    while si < len(s) - 1 and s[si] == 0:
        si += 1

    var r_trim = _slice(r, ri, len(r))
    var s_trim = _slice(s, si, len(s))

    # Prepend 0x00 if high bit set (INTEGER is signed)
    var r_der = List[UInt8]()
    if r_trim[0] >= 0x80:
        r_der.append(0x00)
    for i in range(len(r_trim)):
        r_der.append(r_trim[i])

    var s_der = List[UInt8]()
    if s_trim[0] >= 0x80:
        s_der.append(0x00)
    for i in range(len(s_trim)):
        s_der.append(s_trim[i])

    # SEQUENCE { INTEGER r, INTEGER s }
    var content = List[UInt8]()
    content.append(0x02)  # INTEGER tag
    content.append(UInt8(len(r_der)))
    for i in range(len(r_der)):
        content.append(r_der[i])
    content.append(0x02)  # INTEGER tag
    content.append(UInt8(len(s_der)))
    for i in range(len(s_der)):
        content.append(s_der[i])

    var out = List[UInt8]()
    out.append(0x30)  # SEQUENCE tag
    out.append(UInt8(len(content)))
    for i in range(len(content)):
        out.append(content[i])
    return out^


# ============================================================================
# build_client_certificate12
# ============================================================================

def build_client_certificate12(cert_chain: List[List[UInt8]]) -> List[UInt8]:
    """RFC 5246 §7.4.6 — build Certificate handshake message body.

    An empty cert_chain produces a 'no certificate' response (valid per RFC).
    Each entry is a DER-encoded certificate.
    """
    # Build the certificate_list: each entry is 3-byte length + DER bytes
    var certs_body = List[UInt8]()
    for i in range(len(cert_chain)):
        var cert = cert_chain[i].copy()
        var n = len(cert)
        _append_u24be(certs_body, n)
        _append_bytes(certs_body, cert)

    # Wrap in outer 3-byte length
    var out = List[UInt8]()
    _append_u8(out, HS_CERTIFICATE)  # 0x0B
    _append_u24be(out, 3 + len(certs_body))  # total body = 3-byte list length + certs
    _append_u24be(out, len(certs_body))       # certificate_list length
    _append_bytes(out, certs_body)
    return out^


# ============================================================================
# build_client_certificate_verify12
# ============================================================================

def build_client_certificate_verify12(
    sig_hash_alg: UInt8,   # e.g. 4 = SHA-256
    sig_sig_alg:  UInt8,   # e.g. 3 = ECDSA
    sig_bytes:    List[UInt8],
) -> List[UInt8]:
    """RFC 5246 §7.4.8 — build CertificateVerify handshake message body.

    sig_bytes is the DER-encoded signature (output of _ecdsa_raw_to_der).
    """
    # body = sig_hash_alg(1) + sig_sig_alg(1) + 2-byte sig_len + sig_bytes
    var body = List[UInt8]()
    _append_u8(body, sig_hash_alg)
    _append_u8(body, sig_sig_alg)
    _append_u16be(body, UInt16(len(sig_bytes)))
    _append_bytes(body, sig_bytes)

    var out = List[UInt8]()
    _append_u8(out, HS_CERTIFICATE_VERIFY)  # 0x0F
    _append_u24be(out, len(body))
    _append_bytes(out, body)
    return out^
