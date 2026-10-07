# ============================================================================
# tls/message.mojo — TLS 1.3 wire-format message builders and parsers
# ============================================================================
# Builders:
#   build_client_hello(client_random, session_id, key_share_pub, sni,
#                      alpn_protocols=[])                             → bytes
#   build_client_hello_with_psk(..., alpn_protocols=[])              → bytes
#   build_finished(verify_data)                                      → bytes
#
# Parsers:
#   parse_handshake_msg(data, offset) → (HandshakeMsg, new_offset)
#   parse_server_hello(body)          → ServerHello
#   parse_server_hello_key_share(ext_bytes) → 32-byte x25519 public key
#   parse_alpn_from_ee(ee_body)       → negotiated protocol String (or "")
#   parse_certificate_chain(body)     → List[List[UInt8]] (DER certs)
#   parse_cert_verify(body)           → (sig_scheme: UInt16, sig_bytes)
#   parse_finished(body)              → 32-byte verify_data
# ============================================================================

from crypto.hash import sha256, sha384

# ── TLS handshake message types ───────────────────────────────────────────────
comptime HS_CLIENT_HELLO       : UInt8 = 0x01
comptime HS_SERVER_HELLO       : UInt8 = 0x02
comptime HS_NEW_SESSION_TICKET : UInt8 = 0x04
comptime HS_ENCRYPTED_EXTS     : UInt8 = 0x08
comptime HS_CERTIFICATE        : UInt8 = 0x0B
comptime HS_CERT_REQUEST       : UInt8 = 0x0D
comptime HS_CERT_VERIFY        : UInt8 = 0x0F
comptime HS_FINISHED           : UInt8 = 0x14

# ── TLS extension types ───────────────────────────────────────────────────────
comptime EXT_SERVER_NAME         : UInt16 = 0x0000
comptime EXT_ALPN                : UInt16 = 0x0010   # RFC 7301
comptime EXT_SUPPORTED_GROUPS    : UInt16 = 0x000A
comptime EXT_SIG_ALGS            : UInt16 = 0x000D
comptime EXT_SUPPORTED_VERSIONS  : UInt16 = 0x002B
comptime EXT_KEY_SHARE           : UInt16 = 0x0033

# ── Named groups ──────────────────────────────────────────────────────────────
comptime GROUP_X25519 : UInt16 = 0x001D
comptime GROUP_SECP256R1 : UInt16 = 0x0017
comptime GROUP_SECP384R1 : UInt16 = 0x0018
comptime EXT_EXTENDED_MASTER_SECRET : UInt16 = 0x0017   # RFC 7627
comptime EXT_COOKIE                 : UInt16 = 0x002C   # RFC 8446 §4.2.2
comptime EXT_RENEGOTIATION_INFO     : UInt16 = 0xFF01   # RFC 5746

# ── Cipher suites ─────────────────────────────────────────────────────────────
comptime CIPHER_TLS_AES_128_GCM_SHA256       : UInt16 = 0x1301
comptime CIPHER_TLS_AES_256_GCM_SHA384       : UInt16 = 0x1302
comptime CIPHER_TLS_CHACHA20_POLY1305_SHA256 : UInt16 = 0x1303


# ── PSK / session ticket extensions ──────────────────────────────────────────
comptime EXT_PRE_SHARED_KEY      : UInt16 = 0x0029
comptime EXT_PSK_KEY_EXCH_MODES  : UInt16 = 0x002D

# ── PSK key-exchange modes ────────────────────────────────────────────────────
comptime PSK_KE_MODE    : UInt8 = 0   # psk_ke (no FS — not advertised)
comptime PSK_DHE_KE_MODE: UInt8 = 1   # psk_dhe_ke (keeps forward secrecy)


# ============================================================================
# Parsed message structs
# ============================================================================

struct HandshakeMsg(Copyable, Movable):
    var msg_type: UInt8
    var body:     List[UInt8]

    def __init__(out self):
        self.msg_type = 0
        self.body = List[UInt8]()

    def __copyinit__(out self, copy: Self):
        self.msg_type = copy.msg_type
        self.body     = copy.body.copy()

    def __moveinit__(out self, deinit take: Self):
        self.msg_type = take.msg_type
        self.body     = take.body^


struct ServerHello(Copyable, Movable):
    var random:       List[UInt8]   # 32 bytes
    var session_id:   List[UInt8]
    var cipher_suite: UInt16
    var extensions:   List[UInt8]   # raw extension bytes (after 2-byte length)

    def __init__(out self):
        self.random       = List[UInt8]()
        self.session_id   = List[UInt8]()
        self.cipher_suite = 0
        self.extensions   = List[UInt8]()

    def __copyinit__(out self, copy: Self):
        self.random       = copy.random.copy()
        self.session_id   = copy.session_id.copy()
        self.cipher_suite = copy.cipher_suite
        self.extensions   = copy.extensions.copy()

    def __moveinit__(out self, deinit take: Self):
        self.random       = take.random^
        self.session_id   = take.session_id^
        self.cipher_suite = take.cipher_suite
        self.extensions   = take.extensions^


# ============================================================================
# Internal helpers
# ============================================================================

def _append_u8(mut out: List[UInt8], v: UInt8):
    out.append(v)


def _append_u16be(mut out: List[UInt8], v: UInt16):
    out.append(UInt8(v >> 8))
    out.append(UInt8(v & 0xFF))


def _append_u24be(mut out: List[UInt8], v: Int):
    out.append(UInt8((v >> 16) & 0xFF))
    out.append(UInt8((v >> 8) & 0xFF))
    out.append(UInt8(v & 0xFF))


def _append_bytes(mut out: List[UInt8], src: List[UInt8]):
    for i in range(len(src)):
        out.append(src[i])


def _read_u8(data: List[UInt8], off: Int) raises -> UInt8:
    if off >= len(data):
        raise Error("tls_msg: read_u8 out of bounds")
    return data[off]


def _read_u16be(data: List[UInt8], off: Int) raises -> UInt16:
    if off + 1 >= len(data):
        raise Error("tls_msg: read_u16be out of bounds")
    return (UInt16(data[off]) << 8) | UInt16(data[off + 1])


def _read_u24be(data: List[UInt8], off: Int) raises -> Int:
    if off + 2 >= len(data):
        raise Error("tls_msg: read_u24be out of bounds")
    return (Int(data[off]) << 16) | (Int(data[off + 1]) << 8) | Int(data[off + 2])


def _slice(data: List[UInt8], start: Int, end: Int) raises -> List[UInt8]:
    if end > len(data) or start > end:
        raise Error("tls_msg: slice out of bounds start=" + String(start) + " end=" + String(end) + " len=" + String(len(data)))
    var out = List[UInt8](capacity=end - start)
    for i in range(start, end):
        out.append(data[i])
    return out^


# ============================================================================
# build_client_hello
# ============================================================================

def _build_alpn_ext(protocols: List[String]) -> List[UInt8]:
    """Build the ALPN extension bytes (type + length + data) per RFC 7301 §3.1.

    Wire format:
        ext_type (0x0010)      2 bytes
        ext_data_length        2 bytes
          ProtocolList_length  2 bytes
            protocol_len       1 byte
            protocol_name      N bytes
            ...                (repeated)
    """
    # Build the ProtocolList content: 1-byte len + name bytes for each protocol
    var proto_list = List[UInt8](capacity=32)
    for i in range(len(protocols)):
        var pb = protocols[i].as_bytes()
        _append_u8(proto_list, UInt8(len(pb)))
        for j in range(len(pb)):
            proto_list.append(pb[j])

    # ext data = 2-byte ProtocolList length + ProtocolList content
    var pl_len = len(proto_list)
    var ext_data_len = 2 + pl_len

    var ext = List[UInt8](capacity=4 + ext_data_len)
    _append_u16be(ext, EXT_ALPN)                   # type
    _append_u16be(ext, UInt16(ext_data_len))        # ext data length
    _append_u16be(ext, UInt16(pl_len))              # ProtocolList length
    _append_bytes(ext, proto_list)
    return ext^


def parse_alpn_from_ee(ee_body: List[UInt8]) -> String:
    """The ALPN protocol in an EncryptedExtensions body, or "" (lenient;
    kept for compatibility, the handshake uses validate_encrypted_extensions)."""
    try:
        var offered = List[String]()
        return validate_encrypted_extensions(ee_body, offered, True)
    except:
        return String("")


def validate_encrypted_extensions(
    ee_body: List[UInt8], offered_alpn: List[String], any_alpn: Bool = False
) raises -> String:
    """Validate an EncryptedExtensions body and return the ALPN protocol
    the server selected ("" if none).

    RFC 8446 §4.2 / §4.3.1: the block must be well-formed with no duplicate
    extensions; only extensions the client offered and that may appear in
    EncryptedExtensions are allowed (server_name, supported_groups, ALPN).
    ALPN must name exactly one protocol from offered_alpn.
    """
    if len(ee_body) < 2:
        raise Error("tls: EncryptedExtensions too short (decode_error)")
    var total = (Int(ee_body[0]) << 8) | Int(ee_body[1])
    if 2 + total != len(ee_body):
        raise Error("tls: EncryptedExtensions length mismatch (decode_error)")
    var alpn = String("")
    var seen = List[UInt16]()
    var off = 2
    while off < len(ee_body):
        if off + 4 > len(ee_body):
            raise Error("tls: EncryptedExtensions truncated (decode_error)")
        var ext_type = _read_u16be(ee_body, off)
        var ext_len = Int(_read_u16be(ee_body, off + 2))
        off += 4
        if off + ext_len > len(ee_body):
            raise Error("tls: EncryptedExtensions extension overruns (decode_error)")
        for k in range(len(seen)):
            if seen[k] == ext_type:
                raise Error("tls: duplicate extension in EncryptedExtensions (illegal_parameter)")
        seen.append(ext_type)
        if ext_type == EXT_SERVER_NAME:
            if ext_len != 0:
                raise Error("tls: non-empty server_name in EncryptedExtensions (decode_error)")
        elif ext_type == EXT_SUPPORTED_GROUPS:
            pass  # the server's group preference: informational
        elif ext_type == EXT_ALPN:
            if len(offered_alpn) == 0 and not any_alpn:
                raise Error("tls: ALPN in EncryptedExtensions but none offered (unsupported_extension)")
            # ProtocolNameList with exactly one non-empty name
            if ext_len < 4:
                raise Error("tls: bad ALPN extension (decode_error)")
            var list_len = (Int(ee_body[off]) << 8) | Int(ee_body[off + 1])
            var name_len = Int(ee_body[off + 2])
            if list_len != ext_len - 2 or name_len == 0 or name_len != list_len - 1:
                raise Error("tls: ALPN must select exactly one protocol (illegal_parameter)")
            var name = _slice(ee_body, off + 3, off + 3 + name_len)
            var matched = any_alpn
            for k in range(len(offered_alpn)):
                var cand = offered_alpn[k].as_bytes()
                if len(cand) == name_len:
                    var same = True
                    for q in range(name_len):
                        if cand[q] != name[q]:
                            same = False
                            break
                    if same:
                        matched = True
                        alpn = offered_alpn[k]
                        break
            if not matched:
                raise Error("tls: server selected an ALPN protocol that was not offered (illegal_parameter)")
            if any_alpn and alpn.byte_length() == 0:
                for q in range(name_len):
                    if name[q] < 0x20 or name[q] > 0x7E:
                        raise Error("tls: non-printable ALPN protocol name")
                alpn = String(unsafe_from_utf8=name^)
        else:
            raise Error(
                "tls: extension " + String(Int(ext_type))
                + " not allowed in EncryptedExtensions (unsupported_extension)"
            )
        off += ext_len
    return alpn


def _is_ip_literal(host: String) -> Bool:
    """IPv4 dotted digits, or anything containing ':' (IPv6)."""
    var b = host.as_bytes()
    if len(b) == 0:
        return False
    var only_digits_dots = True
    for i in range(len(b)):
        if b[i] == 58:
            return True
        if b[i] != 46 and (b[i] < 48 or b[i] > 57):
            only_digits_dots = False
    return only_digits_dots


def build_client_hello(
    client_random:   List[UInt8],
    session_id:      List[UInt8],
    key_share_pub:   List[UInt8],
    sni:             String,
    alpn_protocols:  List[String] = List[String](),
    key_share_group: UInt16 = GROUP_X25519,
    cookie:          List[UInt8] = List[UInt8](),
) -> List[UInt8]:
    """Build a ClientHello offering TLS 1.3 and TLS 1.2.

    key_share_pub is the public key for key_share_group: 32 bytes for X25519
    (the first ClientHello), or 65 / 97 bytes for secp256r1 / secp384r1 (the
    second ClientHello after a HelloRetryRequest, which also echoes the
    server's cookie). alpn_protocols, when non-empty, adds an ALPN extension
    (RFC 7301). Returns raw Handshake bytes (type=0x01 + 3-byte length + body).
    """
    var body = List[UInt8](capacity=256)

    # legacy_version = 0x0303
    _append_u16be(body, 0x0303)

    # random (32 bytes)
    _append_bytes(body, client_random)

    # session_id
    _append_u8(body, UInt8(len(session_id)))
    _append_bytes(body, session_id)

    # cipher_suites: TLS 1.3 suites (preferred) + TLS 1.2 ECDHE+AEAD suites
    _append_u16be(body, 14)  # length = 7 * 2 bytes
    _append_u16be(body, CIPHER_TLS_AES_128_GCM_SHA256)        # 0x1301 TLS 1.3
    _append_u16be(body, CIPHER_TLS_CHACHA20_POLY1305_SHA256)  # 0x1303 TLS 1.3
    _append_u16be(body, CIPHER_TLS_AES_256_GCM_SHA384)        # 0x1302 TLS 1.3
    _append_u16be(body, 0xC02F)  # TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    _append_u16be(body, 0xC030)  # TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    _append_u16be(body, 0xC02B)  # TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
    _append_u16be(body, 0xC02C)  # TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384

    # compression_methods: [null]
    _append_u8(body, 1)   # count
    _append_u8(body, 0)   # null compression

    # ── Build extensions ─────────────────────────────────────────────────────

    var exts = List[UInt8](capacity=128)

    # server_name (SNI): DNS names only, never IP literals (RFC 6066 §3)
    if not _is_ip_literal(sni):
        var sni_bytes_span = sni.as_bytes()
        var sni_bytes = List[UInt8](capacity=len(sni_bytes_span))
        for i in range(len(sni_bytes_span)):
            sni_bytes.append(sni_bytes_span[i])
        var sni_name_len = len(sni_bytes)
        # ServerNameList = type(1) + len(2) + name
        var sni_list_len = 1 + 2 + sni_name_len
        var sni_ext_data_len = 2 + sni_list_len
        _append_u16be(exts, EXT_SERVER_NAME)
        _append_u16be(exts, UInt16(sni_ext_data_len))
        _append_u16be(exts, UInt16(sni_list_len))     # ServerNameList length
        _append_u8(exts, 0)                            # name_type = host_name
        _append_u16be(exts, UInt16(sni_name_len))
        _append_bytes(exts, sni_bytes)

    # supported_versions: TLS 1.3 (0x0304) + TLS 1.2 (0x0303)
    _append_u16be(exts, EXT_SUPPORTED_VERSIONS)
    _append_u16be(exts, 5)   # ext data length = 1 + 2*2
    _append_u8(exts, 4)      # versions list length in bytes
    _append_u16be(exts, 0x0304)  # TLS 1.3
    _append_u16be(exts, 0x0303)  # TLS 1.2

    # supported_groups: x25519 (preferred), P-256, P-384. In TLS 1.2 this
    # list also bounds the curves of ECDSA certificates a server may use
    # (RFC 8422 §5.1), so P-384 is needed for servers with P-384 certs.
    _append_u16be(exts, EXT_SUPPORTED_GROUPS)
    _append_u16be(exts, 8)    # ext data length = 2 + 3*2
    _append_u16be(exts, 6)    # group list length in bytes
    _append_u16be(exts, GROUP_X25519)     # 0x001D
    _append_u16be(exts, GROUP_SECP256R1)  # 0x0017
    _append_u16be(exts, GROUP_SECP384R1)  # 0x0018

    # signature_algorithms: only schemes this library can verify
    # (not 0x0603: secp521r1 in TLS 1.3, which this library cannot verify)
    _append_u16be(exts, EXT_SIG_ALGS)
    _append_u16be(exts, 18)  # ext data length = 2 + 8*2
    _append_u16be(exts, 16)  # sig alg list length in bytes (8 algs)
    _append_u16be(exts, 0x0403)  # ecdsa_secp256r1_sha256
    _append_u16be(exts, 0x0503)  # ecdsa_secp384r1_sha384
    _append_u16be(exts, 0x0401)  # rsa_pkcs1_sha256
    _append_u16be(exts, 0x0804)  # rsa_pss_rsae_sha256
    _append_u16be(exts, 0x0501)  # rsa_pkcs1_sha384
    _append_u16be(exts, 0x0805)  # rsa_pss_rsae_sha384
    _append_u16be(exts, 0x0601)  # rsa_pkcs1_sha512
    _append_u16be(exts, 0x0806)  # rsa_pss_rsae_sha512

    # key_share: one entry for key_share_group
    var ks_entry_len = 2 + 2 + len(key_share_pub)  # group + key_len + key
    var ks_list_len  = ks_entry_len
    _append_u16be(exts, EXT_KEY_SHARE)
    _append_u16be(exts, UInt16(2 + ks_list_len))  # ext data = 2-byte list length + entries
    _append_u16be(exts, UInt16(ks_list_len))
    _append_u16be(exts, key_share_group)
    _append_u16be(exts, UInt16(len(key_share_pub)))
    _append_bytes(exts, key_share_pub)

    # cookie (RFC 8446 §4.2.2): echoed from a HelloRetryRequest
    if len(cookie) > 0:
        _append_u16be(exts, EXT_COOKIE)
        _append_u16be(exts, UInt16(2 + len(cookie)))
        _append_u16be(exts, UInt16(len(cookie)))
        _append_bytes(exts, cookie)

    # extended_master_secret (RFC 7627), empty: used if TLS 1.2 is chosen
    _append_u16be(exts, EXT_EXTENDED_MASTER_SECRET)
    _append_u16be(exts, 0)

    # renegotiation_info (RFC 5746) with an empty renegotiated_connection
    _append_u16be(exts, EXT_RENEGOTIATION_INFO)
    _append_u16be(exts, 1)
    _append_u8(exts, 0)

    # ALPN (RFC 7301) — optional, emitted only when protocols are specified
    if len(alpn_protocols) > 0:
        _append_bytes(exts, _build_alpn_ext(alpn_protocols))

    # Append extensions length + extensions to body
    _append_u16be(body, UInt16(len(exts)))
    _append_bytes(body, exts)

    # Wrap in Handshake header: type(1) + length(3)
    var out = List[UInt8](capacity=4 + len(body))
    _append_u8(out, HS_CLIENT_HELLO)
    _append_u24be(out, len(body))
    _append_bytes(out, body)
    return out^


# ============================================================================
# build_finished
# ============================================================================

def build_finished(verify_data: List[UInt8]) -> List[UInt8]:
    """Build TLS 1.3 Finished handshake message. verify_data must be 32 bytes."""
    var out = List[UInt8](capacity=4 + len(verify_data))
    _append_u8(out, HS_FINISHED)
    _append_u24be(out, len(verify_data))
    _append_bytes(out, verify_data)
    return out^


# ============================================================================
# parse_handshake_msg
# ============================================================================

def parse_handshake_msg(data: List[UInt8], offset: Int) raises -> Tuple[HandshakeMsg, Int]:
    """Parse one handshake message. Returns (msg, next_offset)."""
    if offset + 4 > len(data):
        raise Error("parse_handshake_msg: not enough bytes for header")
    var msg_type = data[offset]
    var body_len = _read_u24be(data, offset + 1)
    var body_start = offset + 4
    var body_end = body_start + body_len
    if body_end > len(data):
        raise Error("parse_handshake_msg: body truncated")
    var msg = HandshakeMsg()
    msg.msg_type = msg_type
    msg.body     = _slice(data, body_start, body_end)
    return (msg^, body_end)


# ============================================================================
# parse_server_hello
# ============================================================================

def parse_server_hello(body: List[UInt8]) raises -> ServerHello:
    """Parse ServerHello body. Returns ServerHello struct."""
    var off = 0
    if off + 2 > len(body):
        raise Error("parse_server_hello: too short for legacy_version")
    if _read_u16be(body, 0) != 0x0303:
        raise Error("parse_server_hello: legacy_version must be 0x0303 (protocol_version)")
    off += 2

    # random (32 bytes)
    if off + 32 > len(body):
        raise Error("parse_server_hello: too short for random")
    var rand = _slice(body, off, off + 32)
    off += 32

    # session_id
    if off >= len(body):
        raise Error("parse_server_hello: too short for session_id_len")
    var sid_len = Int(body[off])
    off += 1
    if off + sid_len > len(body):
        raise Error("parse_server_hello: session_id truncated")
    var sid = _slice(body, off, off + sid_len)
    off += sid_len
    if sid_len > 32:
        raise Error("parse_server_hello: session_id longer than 32 bytes (decode_error)")

    # cipher_suite
    if off + 2 > len(body):
        raise Error("parse_server_hello: too short for cipher_suite")
    var cs = _read_u16be(body, off)
    off += 2

    # compression method: must be null
    if off >= len(body) or body[off] != 0:
        raise Error("parse_server_hello: compression method must be null (illegal_parameter)")
    off += 1

    # extensions: absent (TLS 1.2 only), or a block that ends the message
    var ext_bytes = List[UInt8]()
    if off != len(body):
        if off + 2 > len(body):
            raise Error("parse_server_hello: truncated extensions length (decode_error)")
        var ext_len = Int(_read_u16be(body, off))
        off += 2
        if off + ext_len != len(body):
            raise Error("parse_server_hello: extensions length mismatch (decode_error)")
        ext_bytes = _slice(body, off, off + ext_len)
        # well-formed list, no duplicates
        var e = 0
        var seen = List[UInt16]()
        while e < len(ext_bytes):
            if e + 4 > len(ext_bytes):
                raise Error("parse_server_hello: extension truncated (decode_error)")
            var t = _read_u16be(ext_bytes, e)
            var l = Int(_read_u16be(ext_bytes, e + 2))
            if e + 4 + l > len(ext_bytes):
                raise Error("parse_server_hello: extension overruns (decode_error)")
            for k in range(len(seen)):
                if seen[k] == t:
                    raise Error("parse_server_hello: duplicate extension (illegal_parameter)")
            seen.append(t)
            e += 4 + l

    var sh = ServerHello()
    sh.random       = rand^
    sh.session_id   = sid^
    sh.cipher_suite = cs
    sh.extensions   = ext_bytes^
    return sh^


# ============================================================================
# parse_server_hello_key_share
# ============================================================================

def parse_server_hello_key_share(
    ext_bytes: List[UInt8], expected_group: UInt16 = GROUP_X25519
) raises -> List[UInt8]:
    """Return the server's key_share public key, which must be for expected_group
    (the group of the key share the client sent): 32 bytes for X25519, a
    65- or 97-byte uncompressed point for secp256r1 / secp384r1."""
    var off = 0
    while off + 4 <= len(ext_bytes):
        var ext_type = _read_u16be(ext_bytes, off)
        var ext_len  = Int(_read_u16be(ext_bytes, off + 2))
        off += 4
        if off + ext_len > len(ext_bytes):
            raise Error("parse_server_hello_key_share: extension truncated")
        if ext_type == EXT_KEY_SHARE:
            # KeyShare: ServerHello has a single KeyShareEntry
            # group(2) + key_len(2) + key_bytes
            var ext_off = off
            if ext_off + 4 > off + ext_len:
                raise Error("parse_server_hello_key_share: key_share too short")
            var group = _read_u16be(ext_bytes, ext_off)
            if group != expected_group:
                raise Error(
                    "parse_server_hello_key_share: server chose group " + String(Int(group))
                    + ", not the one offered (illegal_parameter)"
                )
            var key_len = Int(_read_u16be(ext_bytes, ext_off + 2))
            ext_off += 4
            var want = 32 if group == GROUP_X25519 else (65 if group == GROUP_SECP256R1 else 97)
            if key_len != want or ext_off + key_len > off + ext_len:
                raise Error("parse_server_hello_key_share: bad key length " + String(key_len))
            return _slice(ext_bytes, ext_off, ext_off + key_len)
        off += ext_len

    raise Error("parse_server_hello_key_share: key_share extension not found")


# ============================================================================
# HelloRetryRequest (RFC 8446 §4.1.4)
# ============================================================================

def is_hello_retry_request(server_random: List[UInt8]) -> Bool:
    """A HelloRetryRequest is a ServerHello whose random is SHA-256("HelloRetryRequest")."""
    var hrr: List[UInt8] = [
        0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
        0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
    ]
    if len(server_random) != 32:
        return False
    for i in range(32):
        if server_random[i] != hrr[i]:
            return False
    return True


struct HelloRetryRequest(Copyable, Movable):
    var cipher_suite:   UInt16
    var selected_group: UInt16
    var cookie:         List[UInt8]   # empty if the server sent none

    def __init__(out self):
        self.cipher_suite = 0
        self.selected_group = 0
        self.cookie = List[UInt8]()


def parse_hello_retry_request(body: List[UInt8]) raises -> HelloRetryRequest:
    """Parse and validate a HelloRetryRequest from a client that sent an
    X25519 key share and offers X25519, secp256r1 and secp384r1.

    Requires supported_versions = TLS 1.3, a TLS 1.3 cipher suite, and a
    key_share selected_group that is secp256r1 or secp384r1 (offered, and not
    X25519, the group already sent). Errors carry the alert the RFC prescribes.
    """
    var sh = parse_server_hello(body)
    if len(sh.session_id) != 0:
        # TLS 1.3 legacy_session_id_echo: we send an empty legacy_session_id
        raise Error("tls: HelloRetryRequest session_id does not echo ours (illegal_parameter)")
    var hrr = HelloRetryRequest()
    hrr.cipher_suite = sh.cipher_suite
    if sh.cipher_suite != CIPHER_TLS_AES_128_GCM_SHA256 and sh.cipher_suite != CIPHER_TLS_AES_256_GCM_SHA384 \
            and sh.cipher_suite != CIPHER_TLS_CHACHA20_POLY1305_SHA256:
        raise Error("tls: HelloRetryRequest with a cipher suite not offered (illegal_parameter)")
    var ext = sh.extensions.copy()
    var version_ok = False
    var have_group = False
    var off = 0
    while off + 4 <= len(ext):
        var ext_type = _read_u16be(ext, off)
        var ext_len = Int(_read_u16be(ext, off + 2))
        off += 4
        if off + ext_len > len(ext):
            raise Error("tls: HelloRetryRequest extension truncated (decode_error)")
        if ext_type == EXT_SUPPORTED_VERSIONS:
            version_ok = ext_len == 2 and _read_u16be(ext, off) == 0x0304
        elif ext_type == EXT_KEY_SHARE:
            if ext_len != 2:
                raise Error("tls: bad HelloRetryRequest key_share (decode_error)")
            hrr.selected_group = _read_u16be(ext, off)
            have_group = True
        elif ext_type == EXT_COOKIE:
            if ext_len < 3:
                raise Error("tls: bad HelloRetryRequest cookie (decode_error)")
            var clen = Int(_read_u16be(ext, off))
            if clen == 0 or clen + 2 != ext_len:
                raise Error("tls: bad HelloRetryRequest cookie (decode_error)")
            hrr.cookie = _slice(ext, off + 2, off + 2 + clen)
        else:
            raise Error("tls: HelloRetryRequest with unexpected extension " + String(Int(ext_type)) + " (unsupported_extension)")
        off += ext_len
    if not version_ok:
        raise Error("tls: HelloRetryRequest without TLS 1.3 supported_versions (illegal_parameter)")
    if not have_group and len(hrr.cookie) == 0:
        raise Error("tls: HelloRetryRequest that would not change the ClientHello (illegal_parameter)")
    if have_group and hrr.selected_group != GROUP_SECP256R1 and hrr.selected_group != GROUP_SECP384R1:
        raise Error("tls: HelloRetryRequest selected a group we cannot use (illegal_parameter)")
    if not have_group:
        hrr.selected_group = GROUP_X25519  # cookie-only: keep the X25519 share
    return hrr^


def hrr_message_hash(client_hello1: List[UInt8], use_sha384: Bool) -> List[UInt8]:
    """The synthetic message that replaces ClientHello1 in the transcript after
    a HelloRetryRequest: message_hash(254) || uint24 Hash.length || Hash(CH1)."""
    var digest = sha384(client_hello1) if use_sha384 else sha256(client_hello1)
    var out = List[UInt8](capacity=4 + len(digest))
    _append_u8(out, 254)
    _append_u24be(out, len(digest))
    _append_bytes(out, digest)
    return out^


# ============================================================================
# parse_certificate_chain (TLS 1.3)
# ============================================================================

def parse_certificate_chain(body: List[UInt8]) raises -> List[List[UInt8]]:
    """Parse a TLS 1.3 server Certificate body → DER certificates.

    Strict (RFC 8446 §4.4.2): certificate_request_context must be empty,
    every length must be exact, there must be at least one certificate,
    and nothing may follow the list.
    """
    if len(body) < 4:
        raise Error("tls: Certificate message too short (decode_error)")
    if body[0] != 0:
        raise Error("tls: non-empty certificate_request_context from server (illegal_parameter)")
    var list_len = _read_u24be(body, 1)
    if 4 + list_len != len(body):
        raise Error("tls: Certificate list length mismatch (decode_error)")
    var off = 4
    var certs = List[List[UInt8]]()
    while off < len(body):
        if off + 3 > len(body):
            raise Error("tls: CertificateEntry truncated (decode_error)")
        var cert_len = _read_u24be(body, off)
        off += 3
        if cert_len == 0 or off + cert_len > len(body):
            raise Error("tls: bad certificate length (decode_error)")
        certs.append(_slice(body, off, off + cert_len))
        off += cert_len
        if off + 2 > len(body):
            raise Error("tls: CertificateEntry extensions missing (decode_error)")
        var ext_len = Int(_read_u16be(body, off))
        off += 2
        if off + ext_len > len(body):
            raise Error("tls: CertificateEntry extensions overrun (decode_error)")
        off += ext_len
    if len(certs) == 0:
        raise Error("tls: empty server Certificate (decode_error)")
    return certs^


def parse_certificate_request13(body: List[UInt8]) raises -> List[UInt8]:
    """Parse a TLS 1.3 CertificateRequest; return certificate_request_context.
    The extensions block must be exact and include signature_algorithms."""
    if len(body) < 1:
        raise Error("tls: CertificateRequest too short (decode_error)")
    var ctx_len = Int(body[0])
    if 1 + ctx_len + 2 > len(body):
        raise Error("tls: CertificateRequest truncated (decode_error)")
    var ctx = _slice(body, 1, 1 + ctx_len)
    var off = 1 + ctx_len
    var total = Int(_read_u16be(body, off))
    off += 2
    if off + total != len(body):
        raise Error("tls: CertificateRequest length mismatch (decode_error)")
    var has_sig_algs = False
    while off < len(body):
        if off + 4 > len(body):
            raise Error("tls: CertificateRequest extension truncated (decode_error)")
        var ext_type = _read_u16be(body, off)
        var ext_len = Int(_read_u16be(body, off + 2))
        off += 4
        if off + ext_len > len(body):
            raise Error("tls: CertificateRequest extension overruns (decode_error)")
        if ext_type == EXT_SIG_ALGS:
            has_sig_algs = True
        off += ext_len
    if not has_sig_algs:
        raise Error("tls: CertificateRequest without signature_algorithms (missing_extension)")
    return ctx^


def build_empty_certificate13(request_context: List[UInt8]) -> List[UInt8]:
    """Client Certificate message with no certificates (RFC 8446 §4.4.2):
    the client declines a CertificateRequest."""
    var body = List[UInt8]()
    _append_u8(body, UInt8(len(request_context)))
    _append_bytes(body, request_context)
    _append_u24be(body, 0)
    var out = List[UInt8]()
    _append_u8(out, HS_CERTIFICATE)
    _append_u24be(out, len(body))
    _append_bytes(out, body)
    return out^


# ============================================================================
# parse_cert_verify
# ============================================================================

def parse_cert_verify(body: List[UInt8]) raises -> Tuple[UInt16, List[UInt8]]:
    """Parse CertificateVerify body → (sig_scheme, sig_bytes); lengths exact."""
    if len(body) < 4:
        raise Error("parse_cert_verify: too short")
    var scheme = _read_u16be(body, 0)
    var sig_len = Int(_read_u16be(body, 2))
    if 4 + sig_len != len(body):
        raise Error("parse_cert_verify: signature length mismatch (decode_error)")
    var sig = _slice(body, 4, 4 + sig_len)
    return (scheme, sig^)


# ============================================================================
# parse_finished
# ============================================================================

def parse_finished(body: List[UInt8]) raises -> List[UInt8]:
    """Parse Finished body → 32-byte (SHA-256) or 48-byte (SHA-384) verify_data."""
    if len(body) != 32 and len(body) != 48:
        raise Error("parse_finished: expected 32 or 48 bytes, got " + String(len(body)))
    return body.copy()


# ============================================================================
# SessionTicket — TLS 1.3 NewSessionTicket (RFC 8446 §4.6.1)
# ============================================================================

struct SessionTicket(Copyable, Movable):
    """Parsed TLS 1.3 NewSessionTicket with derived PSK."""
    var lifetime_secs: UInt32       # ticket_lifetime (seconds)
    var age_add:       UInt32       # ticket_age_add  (obfuscation mask)
    var nonce:         List[UInt8]  # ticket_nonce
    var ticket:        List[UInt8]  # opaque identity bytes sent in ClientHello pre_shared_key
    var psk:           List[UInt8]  # PSK derived by connection layer (empty until set)

    def __init__(out self):
        self.lifetime_secs = 0
        self.age_add       = 0
        self.nonce         = List[UInt8]()
        self.ticket        = List[UInt8]()
        self.psk           = List[UInt8]()

    def __copyinit__(out self, copy: Self):
        self.lifetime_secs = copy.lifetime_secs
        self.age_add       = copy.age_add
        self.nonce         = copy.nonce.copy()
        self.ticket        = copy.ticket.copy()
        self.psk           = copy.psk.copy()

    def __moveinit__(out self, deinit take: Self):
        self.lifetime_secs = take.lifetime_secs
        self.age_add       = take.age_add
        self.nonce         = take.nonce^
        self.ticket        = take.ticket^
        self.psk           = take.psk^


def parse_new_session_ticket(body: List[UInt8]) raises -> SessionTicket:
    """Parse TLS 1.3 NewSessionTicket body (handshake type 0x04).

    RFC 8446 §4.6.1 wire format:
      uint32  ticket_lifetime
      uint32  ticket_age_add
      opaque  ticket_nonce<0..255>       (1-byte length)
      opaque  ticket<1..2^16-1>          (2-byte length)
      Extension extensions<0..2^16-2>   (2-byte length)

    All length fields are validated before indexing.
    Unknown extensions are structurally skipped.
    Raises with a descriptive message on any truncation.
    """
    var off = 0
    var n = len(body)

    # ticket_lifetime (4 bytes)
    if off + 4 > n:
        raise Error("NewSessionTicket: truncated at ticket_lifetime")
    var lifetime = (UInt32(body[off]) << 24) | (UInt32(body[off+1]) << 16) | (UInt32(body[off+2]) << 8) | UInt32(body[off+3])
    off += 4

    # ticket_age_add (4 bytes)
    if off + 4 > n:
        raise Error("NewSessionTicket: truncated at ticket_age_add")
    var age_add = (UInt32(body[off]) << 24) | (UInt32(body[off+1]) << 16) | (UInt32(body[off+2]) << 8) | UInt32(body[off+3])
    off += 4

    # ticket_nonce (1-byte length prefix)
    if off + 1 > n:
        raise Error("NewSessionTicket: truncated at ticket_nonce length")
    var nonce_len = Int(body[off])
    off += 1
    if off + nonce_len > n:
        raise Error("NewSessionTicket: truncated at ticket_nonce data")
    var nonce = _slice(body, off, off + nonce_len)
    off += nonce_len

    # ticket identity (2-byte length prefix)
    if off + 2 > n:
        raise Error("NewSessionTicket: truncated at ticket length")
    var ticket_len = Int(_read_u16be(body, off))
    off += 2
    if ticket_len == 0:
        raise Error("NewSessionTicket: ticket must be non-empty")
    if off + ticket_len > n:
        raise Error("NewSessionTicket: truncated at ticket data")
    var ticket = _slice(body, off, off + ticket_len)
    off += ticket_len

    # Extensions (2-byte total length, then skip each structurally)
    if off + 2 <= n:
        var ext_total = Int(_read_u16be(body, off))
        off += 2
        var ext_end = off + ext_total
        if ext_end > n:
            raise Error("NewSessionTicket: truncated at extensions")
        # Skip each extension: type(2) + length(2) + data
        while off + 4 <= ext_end:
            var ext_len = Int(_read_u16be(body, off + 2))
            off += 4 + ext_len
            if off > ext_end:
                raise Error("NewSessionTicket: extension overruns extensions block")

    var st = SessionTicket()
    st.lifetime_secs = lifetime
    st.age_add       = age_add
    st.nonce         = nonce^
    st.ticket        = ticket^
    return st^


# ============================================================================
# build_client_hello_with_psk
# ============================================================================

def build_client_hello_with_psk(
    client_random:  List[UInt8],
    session_id:     List[UInt8],
    key_share_pub:  List[UInt8],
    sni:            String,
    ticket:         SessionTicket,
    ticket_send_time_ms: UInt32,    # current time in ms (for obfuscated_ticket_age)
    alpn_protocols: List[String] = List[String](),
) -> List[UInt8]:
    """Build a TLS 1.3 ClientHello with PSK resumption extensions.

    Appends psk_key_exchange_modes and pre_shared_key extensions after the
    standard extensions. The pre_shared_key binder field is zeroed — the caller
    must:
      1. Hash this ClientHello (including zeroed binder)
      2. Compute the real binder = tls13_psk_binder(binder_key, transcript_hash)
      3. Overwrite the last 32 bytes of the returned buffer with the binder

    Safety: Only psk_dhe_ke mode is advertised (preserves forward secrecy).
    Returns raw Handshake bytes (type=0x01 + 3-byte length + body).
    """
    var body = List[UInt8](capacity=512)

    # legacy_version = 0x0303
    _append_u16be(body, 0x0303)
    _append_bytes(body, client_random)

    # session_id
    _append_u8(body, UInt8(len(session_id)))
    _append_bytes(body, session_id)

    # cipher_suites (same as build_client_hello)
    _append_u16be(body, 14)
    _append_u16be(body, CIPHER_TLS_AES_128_GCM_SHA256)
    _append_u16be(body, CIPHER_TLS_CHACHA20_POLY1305_SHA256)
    _append_u16be(body, CIPHER_TLS_AES_256_GCM_SHA384)
    _append_u16be(body, 0xC02F)
    _append_u16be(body, 0xC030)
    _append_u16be(body, 0xC02B)
    _append_u16be(body, 0xC02C)

    # compression_methods: [null]
    _append_u8(body, 1)
    _append_u8(body, 0)

    # ── Extensions ───────────────────────────────────────────────────────────

    var exts = List[UInt8](capacity=256)

    # server_name (SNI)
    var sni_bytes_span = sni.as_bytes()
    var sni_bytes = List[UInt8](capacity=len(sni_bytes_span))
    for i in range(len(sni_bytes_span)):
        sni_bytes.append(sni_bytes_span[i])
    var sni_name_len = len(sni_bytes)
    var sni_list_len = 1 + 2 + sni_name_len
    var sni_ext_data_len = 2 + sni_list_len
    _append_u16be(exts, EXT_SERVER_NAME)
    _append_u16be(exts, UInt16(sni_ext_data_len))
    _append_u16be(exts, UInt16(sni_list_len))
    _append_u8(exts, 0)
    _append_u16be(exts, UInt16(sni_name_len))
    _append_bytes(exts, sni_bytes)

    # supported_versions
    _append_u16be(exts, EXT_SUPPORTED_VERSIONS)
    _append_u16be(exts, 5)
    _append_u8(exts, 4)
    _append_u16be(exts, 0x0304)
    _append_u16be(exts, 0x0303)

    # supported_groups
    _append_u16be(exts, EXT_SUPPORTED_GROUPS)
    _append_u16be(exts, 8)
    _append_u16be(exts, 6)
    _append_u16be(exts, GROUP_X25519)
    _append_u16be(exts, GROUP_SECP256R1)
    _append_u16be(exts, GROUP_SECP384R1)

    # signature_algorithms
    _append_u16be(exts, EXT_SIG_ALGS)
    _append_u16be(exts, 18)
    _append_u16be(exts, 16)
    _append_u16be(exts, 0x0403)
    _append_u16be(exts, 0x0503)
    _append_u16be(exts, 0x0401)
    _append_u16be(exts, 0x0804)
    _append_u16be(exts, 0x0501)
    _append_u16be(exts, 0x0805)
    _append_u16be(exts, 0x0601)
    _append_u16be(exts, 0x0806)

    # key_share: x25519
    var ks_entry_len = 2 + 2 + 32
    _append_u16be(exts, EXT_KEY_SHARE)
    _append_u16be(exts, UInt16(2 + ks_entry_len))
    _append_u16be(exts, UInt16(ks_entry_len))
    _append_u16be(exts, GROUP_X25519)
    _append_u16be(exts, 32)
    _append_bytes(exts, key_share_pub)

    # ALPN — before PSK extensions (pre_shared_key must be last; RFC 8446 §4.2.11)
    if len(alpn_protocols) > 0:
        _append_bytes(exts, _build_alpn_ext(alpn_protocols))

    # psk_key_exchange_modes (0x002D): only psk_dhe_ke = 1
    # RFC 8446 §4.2.9: ext_data = modes_len(1) + mode(1)
    _append_u16be(exts, EXT_PSK_KEY_EXCH_MODES)
    _append_u16be(exts, 2)    # ext data length
    _append_u8(exts, 1)       # modes list length
    _append_u8(exts, PSK_DHE_KE_MODE)   # 0x01

    # pre_shared_key (0x0029) — MUST be last extension (RFC 8446 §4.2.11)
    # Wire format:
    #   identities<6..2^16-1>: (identity<1..2^16-1> + obfuscated_ticket_age(4))*
    #   binders<33..2^16-1>:   binder_entry(1-byte len + 32 bytes)*
    var ticket_len = len(ticket.ticket)
    var obf_age = ticket_send_time_ms + ticket.age_add   # RFC 8446 §4.2.11.1

    # Identity entry: 2-byte identity_len + identity + 4-byte obfuscated_age
    var identity_entry_len = 2 + ticket_len + 4
    var identities_len = identity_entry_len   # single identity

    # Binder entry: 1-byte binder_len + 32-byte zeroed binder placeholder
    var binders_len = 1 + 32   # single binder

    var psk_ext_data_len = 2 + identities_len + 2 + binders_len
    _append_u16be(exts, EXT_PRE_SHARED_KEY)
    _append_u16be(exts, UInt16(psk_ext_data_len))

    # identities list
    _append_u16be(exts, UInt16(identities_len))
    _append_u16be(exts, UInt16(ticket_len))
    _append_bytes(exts, ticket.ticket)
    _append_u8(exts, UInt8((obf_age >> 24) & 0xFF))
    _append_u8(exts, UInt8((obf_age >> 16) & 0xFF))
    _append_u8(exts, UInt8((obf_age >> 8) & 0xFF))
    _append_u8(exts, UInt8(obf_age & 0xFF))

    # binders list (zeroed placeholder — caller must patch before sending)
    _append_u16be(exts, UInt16(binders_len))
    _append_u8(exts, 32)   # binder length
    for _ in range(32):
        _append_u8(exts, 0)   # zeroed binder

    # Append extensions to body
    _append_u16be(body, UInt16(len(exts)))
    _append_bytes(body, exts)

    # Wrap in Handshake header
    var out = List[UInt8](capacity=4 + len(body))
    _append_u8(out, HS_CLIENT_HELLO)
    _append_u24be(out, len(body))
    _append_bytes(out, body)
    return out^


# ============================================================================
# parse_server_hello_selected_identity
# ============================================================================

def parse_server_hello_selected_identity(ext_bytes: List[UInt8]) -> Int:
    """Find pre_shared_key extension in ServerHello and return selected_identity index.

    Returns -1 if the extension is absent (PSK rejected, full handshake).
    Returns the selected identity index (typically 0) if PSK was accepted.
    """
    var off = 0
    while off + 4 <= len(ext_bytes):
        var ext_type = UInt16(0)
        if off + 1 < len(ext_bytes):
            ext_type = (UInt16(ext_bytes[off]) << 8) | UInt16(ext_bytes[off + 1])
        var ext_len = 0
        if off + 3 < len(ext_bytes):
            ext_len = (Int(ext_bytes[off + 2]) << 8) | Int(ext_bytes[off + 3])
        off += 4
        if off + ext_len > len(ext_bytes):
            return -1
        if ext_type == EXT_PRE_SHARED_KEY:
            # selected_identity is a single uint16
            if ext_len >= 2:
                return (Int(ext_bytes[off]) << 8) | Int(ext_bytes[off + 1])
            return -1
        off += ext_len
    return -1
