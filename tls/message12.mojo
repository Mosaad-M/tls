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
