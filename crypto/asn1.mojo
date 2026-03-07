# ============================================================================
# asn1.mojo — ASN.1 DER parser for X.509 certificate processing
# ============================================================================
# API:
#   der_parse(data, offset) → (tag, content_bytes, next_offset)
#   der_raw_bytes(data, offset) → full TLV bytes (tag+length+value)
#   der_int_bytes(content) → INTEGER value (leading-zero stripped)
#   der_bit_str(content) → BIT STRING payload (skips unused-bits byte)
#   der_oid_eq(content, oid_hex) → Bool
#   der_children(content) → List[DerElem]   (parse SEQUENCE/SET children)
#
# High-level:
#   asn1_parse_rsa_spki(der)    → (n_bytes, e_bytes)
#   asn1_parse_ec_spki(der)     → 65-byte uncompressed EC point
#   asn1_parse_ecdsa_sig(der)   → (r_bytes, s_bytes)  each 32 bytes
# ============================================================================

# ASN.1 universal tags
comptime TAG_INTEGER         : UInt8 = 0x02
comptime TAG_BIT_STRING      : UInt8 = 0x03
comptime TAG_OCTET_STRING    : UInt8 = 0x04
comptime TAG_NULL            : UInt8 = 0x05
comptime TAG_OID             : UInt8 = 0x06
comptime TAG_UTF8_STRING     : UInt8 = 0x0C
comptime TAG_PRINTABLE_STRING: UInt8 = 0x13
comptime TAG_IA5_STRING      : UInt8 = 0x16
comptime TAG_SEQUENCE        : UInt8 = 0x30
comptime TAG_SET             : UInt8 = 0x31
comptime TAG_CTX0            : UInt8 = 0xA0  # [0] EXPLICIT
comptime TAG_CTX1            : UInt8 = 0xA1  # [1] EXPLICIT
comptime TAG_CTX3            : UInt8 = 0xA3  # [3] EXPLICIT (extensions)
comptime TAG_DNS_NAME        : UInt8 = 0x82  # [2] context-specific primitive (dNSName in GeneralName)

# OIDs (raw DER content bytes as hex strings)
comptime OID_RSA_ENCRYPTION    = "2a864886f70d010101"  # 1.2.840.113549.1.1.1
comptime OID_EC_PUBLIC_KEY     = "2a8648ce3d0201"       # 1.2.840.10045.2.1
comptime OID_P256              = "2a8648ce3d030107"     # 1.2.840.10045.3.1.7 (secp256r1)
comptime OID_SHA256_WITH_RSA   = "2a864886f70d01010b"  # 1.2.840.113549.1.1.11
comptime OID_SHA256_WITH_ECDSA = "2a8648ce3d040302"    # 1.2.840.10045.4.3.2
comptime OID_SUBJECT_ALT_NAME  = "551d11"               # 2.5.29.17
comptime OID_COMMON_NAME       = "550403"               # 2.5.4.3

# Additional signature algorithm OIDs (Session 1)
comptime OID_SHA1_WITH_RSA     = "2a864886f70d010105"  # 1.2.840.113549.1.1.5  sha1WithRSAEncryption
comptime OID_SHA384_WITH_RSA   = "2a864886f70d01010c"  # 1.2.840.113549.1.1.12 sha384WithRSAEncryption
comptime OID_SHA384_WITH_ECDSA = "2a8648ce3d040303"    # 1.2.840.10045.4.3.3   ecdsa-with-SHA384
comptime OID_RSA_PSS           = "2a864886f70d01010a"  # 1.2.840.113549.1.1.10 id-RSASSA-PSS
comptime OID_SHA512_WITH_RSA   = "2a864886f70d01010d"  # 1.2.840.113549.1.1.13 sha512WithRSAEncryption

# Hash algorithm OIDs (used in RSASSA-PSS-params AlgorithmIdentifier)
comptime OID_HASH_SHA256       = "608648016503040201"  # 2.16.840.1.101.3.4.2.1 id-sha256
comptime OID_HASH_SHA384       = "608648016503040202"  # 2.16.840.1.101.3.4.2.2 id-sha384

# EC curve OIDs (Session 3)
comptime OID_P384              = "2b81040022"           # 1.3.132.0.34 secp384r1


# ============================================================================
# DerElem: a parsed TLV element
# ============================================================================

struct DerElem(Copyable, Movable):
    var tag:     UInt8
    var content: List[UInt8]   # value bytes (excluding tag+length)

    fn __init__(out self):
        self.tag     = 0
        self.content = List[UInt8]()

    fn __copyinit__(out self, copy: Self):
        self.tag     = copy.tag
        self.content = copy.content.copy()

    fn __moveinit__(out self, deinit take: Self):
        self.tag     = take.tag
        self.content = take.content^


# ============================================================================
# Core: parse one TLV element at `offset` in `data`
# ============================================================================

fn der_parse(data: List[UInt8], offset: Int) raises -> Tuple[UInt8, List[UInt8], Int]:
    """Parse one DER element. Returns (tag, content_bytes, next_offset)."""
    if offset >= len(data):
        raise Error("asn1: unexpected end of data at offset " + String(offset))
    var tag = data[offset]
    var pos = offset + 1

    if pos >= len(data):
        raise Error("asn1: no length byte")
    var first = Int(data[pos])
    pos += 1

    var length: Int = 0
    if first & 0x80 == 0:
        length = first
    else:
        var n = first & 0x7F
        if n == 0 or n > 4:
            raise Error("asn1: invalid long-form length (n=" + String(n) + ")")
        for _ in range(n):
            if pos >= len(data):
                raise Error("asn1: truncated length bytes")
            length = (length << 8) | Int(data[pos])
            pos += 1

    if pos + length > len(data):
        raise Error("asn1: element extends past data end")
    var content = List[UInt8](capacity=length)
    for i in range(length):
        content.append(data[pos + i])
    return (tag, content^, pos + length)


fn der_raw_bytes(data: List[UInt8], offset: Int) raises -> List[UInt8]:
    """Return full TLV bytes (tag + length encoding + value) at `offset`."""
    var start = offset
    var res = der_parse(data, offset)
    var next_offset = res[2]
    var raw = List[UInt8](capacity=next_offset - start)
    for i in range(start, next_offset):
        raw.append(data[i])
    return raw^


# ============================================================================
# Parse all children of a constructed element (SEQUENCE, SET, ctx tags)
# ============================================================================

fn der_children(content: List[UInt8]) raises -> List[DerElem]:
    """Parse all TLV children inside a SEQUENCE/SET content."""
    var result = List[DerElem]()
    var offset = 0
    while offset < len(content):
        var res = der_parse(content, offset)
        var child = DerElem()
        child.tag     = res[0]
        child.content = res[1].copy()
        result.append(child^)
        offset = res[2]
    return result^


# ============================================================================
# Helpers
# ============================================================================

fn der_int_bytes(content: List[UInt8]) -> List[UInt8]:
    """Return INTEGER value bytes with leading 0x00 (sign byte) stripped."""
    var start = 0
    var n = len(content)
    while start < n - 1 and content[start] == 0x00:
        start += 1
    var out = List[UInt8](capacity=n - start)
    for i in range(start, n):
        out.append(content[i])
    return out^


fn der_bit_str(content: List[UInt8]) raises -> List[UInt8]:
    """Return BIT STRING payload (skip the leading unused-bits count byte)."""
    if len(content) == 0:
        raise Error("asn1: empty BIT STRING content")
    if content[0] != 0:
        raise Error("asn1: BIT STRING has " + String(Int(content[0])) + " unused bits")
    var out = List[UInt8](capacity=len(content) - 1)
    for i in range(1, len(content)):
        out.append(content[i])
    return out^


fn der_oid_eq(content: List[UInt8], oid_hex: String) raises -> Bool:
    """Compare OID content bytes against expected hex string."""
    var raw = oid_hex.as_bytes()
    if len(raw) % 2 != 0:
        raise Error("asn1: oid_hex has odd length")
    var expected_len = len(raw) // 2
    if len(content) != expected_len:
        return False
    for i in range(expected_len):
        var hi = raw[i * 2]
        var lo = raw[i * 2 + 1]
        var h: UInt8 = (hi - 48) if hi <= 57 else (hi - 87)
        var l: UInt8 = (lo - 48) if lo <= 57 else (lo - 87)
        if content[i] != ((h << 4) | l):
            return False
    return True


fn _pad32(b: List[UInt8]) -> List[UInt8]:
    """Zero-pad or right-trim byte slice to exactly 32 bytes."""
    var out = List[UInt8](capacity=32)
    var n = len(b)
    if n >= 32:
        for i in range(n - 32, n):
            out.append(b[i])
    else:
        for _ in range(32 - n):
            out.append(0)
        for i in range(n):
            out.append(b[i])
    return out^


fn _pad48(b: List[UInt8]) -> List[UInt8]:
    """Zero-pad or right-trim byte slice to exactly 48 bytes."""
    var out = List[UInt8](capacity=48)
    var n = len(b)
    if n >= 48:
        for i in range(n - 48, n):
            out.append(b[i])
    else:
        for _ in range(48 - n):
            out.append(0)
        for i in range(n):
            out.append(b[i])
    return out^


# ============================================================================
# High-level: parse RSA SubjectPublicKeyInfo → (n_bytes, e_bytes)
# Structure: SEQUENCE { SEQUENCE { OID(rsaEncryption), NULL }, BIT STRING {
#              SEQUENCE { INTEGER(n), INTEGER(e) } } }
# ============================================================================

fn asn1_parse_rsa_spki(der: List[UInt8]) raises -> Tuple[List[UInt8], List[UInt8]]:
    """Extract RSA modulus n and exponent e from SubjectPublicKeyInfo DER."""
    # Outer SEQUENCE
    var outer = der_parse(der, 0)
    if outer[0] != TAG_SEQUENCE:
        raise Error("asn1: RSA SPKI: outer tag not SEQUENCE")
    var outer_children = der_children(outer[1])
    if len(outer_children) < 2:
        raise Error("asn1: RSA SPKI: need 2 children in outer SEQUENCE")

    # children[0] = AlgorithmIdentifier SEQUENCE { OID, NULL }
    var algo_seq = outer_children[0].copy()
    if algo_seq.tag != TAG_SEQUENCE:
        raise Error("asn1: RSA SPKI: AlgorithmIdentifier not SEQUENCE")
    var algo_children = der_children(algo_seq.content)
    if len(algo_children) < 1 or algo_children[0].tag != TAG_OID:
        raise Error("asn1: RSA SPKI: no OID in AlgorithmIdentifier")
    if not der_oid_eq(algo_children[0].content, OID_RSA_ENCRYPTION):
        raise Error("asn1: RSA SPKI: OID is not rsaEncryption")

    # children[1] = BIT STRING containing DER SEQUENCE { n, e }
    var bit_str_elem = outer_children[1].copy()
    if bit_str_elem.tag != TAG_BIT_STRING:
        raise Error("asn1: RSA SPKI: second child not BIT STRING")
    var inner_der = der_bit_str(bit_str_elem.content)

    # Parse inner SEQUENCE { INTEGER(n), INTEGER(e) }
    var inner = der_parse(inner_der, 0)
    if inner[0] != TAG_SEQUENCE:
        raise Error("asn1: RSA SPKI: inner BIT STRING content not SEQUENCE")
    var rsa_children = der_children(inner[1])
    if len(rsa_children) < 2:
        raise Error("asn1: RSA SPKI: need n and e")
    if rsa_children[0].tag != TAG_INTEGER or rsa_children[1].tag != TAG_INTEGER:
        raise Error("asn1: RSA SPKI: n or e not INTEGER")

    var n_bytes = der_int_bytes(rsa_children[0].content)
    var e_bytes = der_int_bytes(rsa_children[1].content)
    return (n_bytes^, e_bytes^)


# ============================================================================
# High-level: parse EC SubjectPublicKeyInfo → 65-byte uncompressed EC point
# Structure: SEQUENCE { SEQUENCE { OID(id-ecPublicKey), OID(secp256r1) },
#                       BIT STRING { 04 || Qx || Qy } }
# ============================================================================

fn asn1_parse_ec_spki(der: List[UInt8]) raises -> List[UInt8]:
    """Extract 65-byte uncompressed EC point from SubjectPublicKeyInfo DER."""
    var outer = der_parse(der, 0)
    if outer[0] != TAG_SEQUENCE:
        raise Error("asn1: EC SPKI: outer not SEQUENCE")
    var outer_children = der_children(outer[1])
    if len(outer_children) < 2:
        raise Error("asn1: EC SPKI: need 2 children")

    # children[0] = AlgorithmIdentifier: { OID(ecPublicKey), OID(p256) }
    var algo = outer_children[0].copy()
    if algo.tag != TAG_SEQUENCE:
        raise Error("asn1: EC SPKI: AlgorithmIdentifier not SEQUENCE")
    var algo_ch = der_children(algo.content)
    if len(algo_ch) < 1 or algo_ch[0].tag != TAG_OID:
        raise Error("asn1: EC SPKI: no OID")
    if not der_oid_eq(algo_ch[0].content, OID_EC_PUBLIC_KEY):
        raise Error("asn1: EC SPKI: not id-ecPublicKey OID")
    # children[1] = BIT STRING { 04 || Qx || Qy }
    var bit = outer_children[1].copy()
    if bit.tag != TAG_BIT_STRING:
        raise Error("asn1: EC SPKI: second child not BIT STRING")
    var point = der_bit_str(bit.content)
    if point[0] != 0x04:
        raise Error("asn1: EC SPKI: expected uncompressed point (04 prefix)")
    if len(point) != 65 and len(point) != 97:
        raise Error("asn1: EC SPKI: expected 65-byte P-256 or 97-byte P-384 point, got " + String(len(point)))
    return point^


# ============================================================================
# High-level: parse DER-encoded ECDSA signature → (r_bytes, s_bytes)
# Structure: SEQUENCE { INTEGER(r), INTEGER(s) }
# Both r and s are returned zero-padded to 32 bytes.
# ============================================================================

fn asn1_parse_ecdsa_sig(der: List[UInt8]) raises -> Tuple[List[UInt8], List[UInt8]]:
    """Parse DER ECDSA signature. Returns (r, s) each 32 bytes."""
    var outer = der_parse(der, 0)
    if outer[0] != TAG_SEQUENCE:
        raise Error("asn1: ECDSA sig: outer not SEQUENCE")
    var children = der_children(outer[1])
    if len(children) < 2:
        raise Error("asn1: ECDSA sig: need r and s")
    if children[0].tag != TAG_INTEGER or children[1].tag != TAG_INTEGER:
        raise Error("asn1: ECDSA sig: r or s not INTEGER")
    var r = _pad32(der_int_bytes(children[0].content))
    var s = _pad32(der_int_bytes(children[1].content))
    return (r^, s^)


# ============================================================================
# High-level: parse DER-encoded ECDSA signature → (r_bytes, s_bytes) P-384
# Both r and s are returned zero-padded to 48 bytes.
# ============================================================================

fn asn1_parse_ecdsa_sig_48(der: List[UInt8]) raises -> Tuple[List[UInt8], List[UInt8]]:
    """Parse DER ECDSA signature. Returns (r, s) each 48 bytes (for P-384)."""
    var outer = der_parse(der, 0)
    if outer[0] != TAG_SEQUENCE:
        raise Error("asn1: ECDSA sig48: outer not SEQUENCE")
    var children = der_children(outer[1])
    if len(children) < 2:
        raise Error("asn1: ECDSA sig48: need r and s")
    if children[0].tag != TAG_INTEGER or children[1].tag != TAG_INTEGER:
        raise Error("asn1: ECDSA sig48: r or s not INTEGER")
    var r = _pad48(der_int_bytes(children[0].content))
    var s = _pad48(der_int_bytes(children[1].content))
    return (r^, s^)
