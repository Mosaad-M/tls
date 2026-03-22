# ============================================================================
# cert.mojo — X.509 DER certificate parsing and signature verification
# ============================================================================
# API:
#   cert_parse(der)              → X509Cert
#   cert_verify_sig(cert, issuer) → raises on invalid signature
#
# Supports:
#   sha256WithRSAEncryption (PKCS#1 v1.5) and ecdsa-with-SHA256 (P-256)
# ============================================================================

from ffi import external_call

from crypto.asn1 import (
    DerElem, der_parse, der_raw_bytes, der_children, der_bit_str, der_oid_eq,
    asn1_parse_rsa_spki, asn1_parse_ec_spki, asn1_parse_ecdsa_sig, asn1_parse_ecdsa_sig_48,
    TAG_BIT_STRING, TAG_OID, TAG_SEQUENCE, TAG_SET, TAG_CTX0, TAG_CTX3,
    TAG_OCTET_STRING, TAG_DNS_NAME,
    TAG_UTF8_STRING, TAG_PRINTABLE_STRING, TAG_IA5_STRING,
    OID_RSA_ENCRYPTION, OID_EC_PUBLIC_KEY, OID_P256, OID_P384,
    OID_SHA1_WITH_RSA,
    OID_SHA256_WITH_RSA, OID_SHA256_WITH_ECDSA,
    OID_SHA384_WITH_RSA, OID_SHA384_WITH_ECDSA,
    OID_SHA512_WITH_RSA,
    OID_RSA_PSS, OID_HASH_SHA384,
    OID_SUBJECT_ALT_NAME, OID_COMMON_NAME,
)
from crypto.rsa import rsa_pkcs1_verify, rsa_pss_verify
from crypto.p256 import p256_ecdsa_verify
from crypto.p384 import p384_ecdsa_verify
from crypto.hash import sha256, sha384
from crypto.sha1 import sha1


# ============================================================================
# X509Cert — parsed certificate fields needed for chain verification
# ============================================================================

struct X509Cert(Copyable, Movable):
    var tbs_raw:     List[UInt8]   # full TLV bytes of TBSCertificate (signed data)
    var sig_alg:     String         # "rsa" | "ecdsa" | "rsa-pss"
    var sig_hash:    String         # "sha256" | "sha384"
    var sig_bytes:   List[UInt8]   # raw signature (ECDSA: DER SEQUENCE { r, s })
    var pub_key_alg: String         # "rsa" | "ec"
    var ec_curve:    String         # "p256" | "p384" | "" (for RSA keys)
    var rsa_n:       List[UInt8]   # RSA modulus        (empty for EC keys)
    var rsa_e:       List[UInt8]   # RSA public exponent (empty for EC keys)
    var ec_point:    List[UInt8]   # 65 or 97-byte uncompressed EC point (empty for RSA)

    def __init__(out self):
        self.tbs_raw     = List[UInt8]()
        self.sig_alg     = String("")
        self.sig_hash    = String("sha256")
        self.sig_bytes   = List[UInt8]()
        self.pub_key_alg = String("")
        self.ec_curve    = String("p256")
        self.rsa_n       = List[UInt8]()
        self.rsa_e       = List[UInt8]()
        self.ec_point    = List[UInt8]()

    def __copyinit__(out self, copy: Self):
        self.tbs_raw     = copy.tbs_raw.copy()
        self.sig_alg     = copy.sig_alg
        self.sig_hash    = copy.sig_hash
        self.sig_bytes   = copy.sig_bytes.copy()
        self.pub_key_alg = copy.pub_key_alg
        self.ec_curve    = copy.ec_curve
        self.rsa_n       = copy.rsa_n.copy()
        self.rsa_e       = copy.rsa_e.copy()
        self.ec_point    = copy.ec_point.copy()

    def __moveinit__(out self, deinit take: Self):
        self.tbs_raw     = take.tbs_raw^
        self.sig_alg     = take.sig_alg^
        self.sig_hash    = take.sig_hash^
        self.sig_bytes   = take.sig_bytes^
        self.pub_key_alg = take.pub_key_alg^
        self.ec_curve    = take.ec_curve^
        self.rsa_n       = take.rsa_n^
        self.rsa_e       = take.rsa_e^
        self.ec_point    = take.ec_point^


# ============================================================================
# Internal helpers
# ============================================================================

def _child_offset(content: List[UInt8], idx: Int) raises -> Int:
    """Return the byte offset of child at index `idx` within `content`."""
    var off = 0
    for _ in range(idx):
        var tmp = der_parse(content, off)
        off = tmp[2]
    return off


# ============================================================================
# cert_parse — parse a DER-encoded X.509 certificate into X509Cert
# ============================================================================

def cert_parse(der: List[UInt8]) raises -> X509Cert:
    """Parse a DER X.509 certificate. Raises on malformed or unsupported input."""

    # Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signature }
    var cert_outer = der_parse(der, 0)
    if cert_outer[0] != TAG_SEQUENCE:
        raise Error("cert: outer not SEQUENCE")
    var outer_content = cert_outer[1].copy()

    # TBSCertificate full TLV — needed for signature hash computation
    var tbs_raw = der_raw_bytes(outer_content, 0)

    var cert_children = der_children(outer_content)
    if len(cert_children) < 3:
        raise Error("cert: Certificate needs 3 children")

    # ── signatureAlgorithm (child 1) ─────────────────────────────────────────
    var alg_elem = cert_children[1].copy()
    if alg_elem.tag != TAG_SEQUENCE:
        raise Error("cert: signatureAlgorithm not SEQUENCE")
    var alg_ch = der_children(alg_elem.content)
    if len(alg_ch) < 1 or alg_ch[0].tag != TAG_OID:
        raise Error("cert: signatureAlgorithm has no OID")
    var sig_alg: String
    var sig_hash: String = String("sha256")
    if der_oid_eq(alg_ch[0].content, OID_SHA1_WITH_RSA):
        sig_alg = String("rsa")
        sig_hash = String("sha1")
    elif der_oid_eq(alg_ch[0].content, OID_SHA256_WITH_RSA):
        sig_alg = String("rsa")
    elif der_oid_eq(alg_ch[0].content, OID_SHA256_WITH_ECDSA):
        sig_alg = String("ecdsa")
    elif der_oid_eq(alg_ch[0].content, OID_SHA384_WITH_RSA):
        sig_alg = String("rsa")
        sig_hash = String("sha384")
    elif der_oid_eq(alg_ch[0].content, OID_SHA384_WITH_ECDSA):
        sig_alg = String("ecdsa")
        sig_hash = String("sha384")
    elif der_oid_eq(alg_ch[0].content, OID_SHA512_WITH_RSA):
        sig_alg = String("rsa")
        sig_hash = String("sha512")
    elif der_oid_eq(alg_ch[0].content, OID_RSA_PSS):
        sig_alg = String("rsa-pss")
        # Parse hash from RSASSA-PSS-params if present ([0] hashAlgorithm)
        if len(alg_ch) >= 2 and alg_ch[1].tag == TAG_SEQUENCE:
            var pss_ch = der_children(alg_ch[1].content)
            if len(pss_ch) >= 1 and pss_ch[0].tag == TAG_CTX0:
                var hash_ctx_ch = der_children(pss_ch[0].content)
                if len(hash_ctx_ch) >= 1 and hash_ctx_ch[0].tag == TAG_SEQUENCE:
                    var hash_oid_ch = der_children(hash_ctx_ch[0].content)
                    if len(hash_oid_ch) >= 1 and hash_oid_ch[0].tag == TAG_OID:
                        if der_oid_eq(hash_oid_ch[0].content, OID_HASH_SHA384):
                            sig_hash = String("sha384")
    else:
        raise Error("cert: unsupported signatureAlgorithm OID")

    # ── signature BIT STRING (child 2) ───────────────────────────────────────
    var sig_elem = cert_children[2].copy()
    if sig_elem.tag != TAG_BIT_STRING:
        raise Error("cert: signature not BIT STRING")
    var sig_bytes = der_bit_str(sig_elem.content)

    # ── TBSCertificate (child 0) → find SubjectPublicKeyInfo ─────────────────
    var tbs_elem = cert_children[0].copy()
    if tbs_elem.tag != TAG_SEQUENCE:
        raise Error("cert: TBSCertificate not SEQUENCE")
    var tbs_ch = der_children(tbs_elem.content)

    # version [0] EXPLICIT is optional; present in v2/v3 certs
    # With version:    0=version, 1=serial, 2=sigAlg, 3=issuer, 4=validity, 5=subject, 6=SPKI
    # Without version: 0=serial,  1=sigAlg, 2=issuer, 3=validity, 4=subject, 5=SPKI
    var spki_idx = 5
    if len(tbs_ch) > 0 and tbs_ch[0].tag == TAG_CTX0:
        spki_idx = 6
    if len(tbs_ch) <= spki_idx:
        raise Error("cert: TBSCertificate too short to contain SPKI")

    # Peek at SPKI AlgorithmIdentifier to determine key type
    # tbs_ch[spki_idx] is DerElem (SEQUENCE); access its content by field reference
    var spki_inner_ch = der_children(tbs_ch[spki_idx].content)
    if len(spki_inner_ch) < 2 or spki_inner_ch[0].tag != TAG_SEQUENCE:
        raise Error("cert: SPKI AlgID not SEQUENCE")
    var spki_alg_ch = der_children(spki_inner_ch[0].content)
    if len(spki_alg_ch) < 1 or spki_alg_ch[0].tag != TAG_OID:
        raise Error("cert: SPKI AlgID has no OID")

    # Extract full SPKI TLV bytes (needed by high-level parsers)
    var spki_off = _child_offset(tbs_elem.content, spki_idx)
    var spki_raw = der_raw_bytes(tbs_elem.content, spki_off)

    var pub_key_alg: String
    var ec_curve: String
    var rsa_n = List[UInt8]()
    var rsa_e = List[UInt8]()
    var ec_point = List[UInt8]()

    if der_oid_eq(spki_alg_ch[0].content, OID_RSA_ENCRYPTION):
        pub_key_alg = String("rsa")
        ec_curve = String("")
        var key_res = asn1_parse_rsa_spki(spki_raw)
        rsa_n = key_res[0].copy()
        rsa_e = key_res[1].copy()
    elif der_oid_eq(spki_alg_ch[0].content, OID_EC_PUBLIC_KEY):
        pub_key_alg = String("ec")
        # Detect curve from AlgorithmIdentifier parameter OID
        if len(spki_alg_ch) >= 2 and spki_alg_ch[1].tag == TAG_OID:
            if der_oid_eq(spki_alg_ch[1].content, OID_P384):
                ec_curve = String("p384")
            else:
                ec_curve = String("p256")
        else:
            ec_curve = String("p256")
        ec_point = asn1_parse_ec_spki(spki_raw)
    else:
        raise Error("cert: unsupported public key algorithm OID")

    var cert = X509Cert()
    cert.tbs_raw     = tbs_raw^
    cert.sig_alg     = sig_alg^
    cert.sig_hash    = sig_hash^
    cert.sig_bytes   = sig_bytes^
    cert.pub_key_alg = pub_key_alg^
    cert.ec_curve    = ec_curve^
    cert.rsa_n       = rsa_n^
    cert.rsa_e       = rsa_e^
    cert.ec_point    = ec_point^
    return cert^


# ============================================================================
# cert_verify_sig — verify cert's signature against issuer's public key
# ============================================================================

def cert_verify_sig(cert: X509Cert, issuer: X509Cert) raises:
    """Verify cert's digital signature using issuer's public key. Raises on invalid."""
    var tbs_hash: List[UInt8]
    if cert.sig_hash == "sha384":
        tbs_hash = sha384(cert.tbs_raw)
    elif cert.sig_hash == "sha1":
        tbs_hash = sha1(cert.tbs_raw)
    elif cert.sig_hash == "sha512":
        raise Error("cert_verify: sha512 signature verification not supported")
    else:
        tbs_hash = sha256(cert.tbs_raw)

    if cert.sig_alg == "rsa":
        if issuer.pub_key_alg != "rsa":
            raise Error("cert_verify: sig is RSA but issuer has no RSA key")
        rsa_pkcs1_verify(issuer.rsa_n, issuer.rsa_e, tbs_hash, cert.sig_bytes)
    elif cert.sig_alg == "rsa-pss":
        if issuer.pub_key_alg != "rsa":
            raise Error("cert_verify: sig is RSA-PSS but issuer has no RSA key")
        var salt_len: Int
        if cert.sig_hash == "sha384":
            salt_len = 48
        else:
            salt_len = 32
        rsa_pss_verify(issuer.rsa_n, issuer.rsa_e, tbs_hash, cert.sig_bytes, salt_len)
    elif cert.sig_alg == "ecdsa":
        if issuer.pub_key_alg != "ec":
            raise Error("cert_verify: sig is ECDSA but issuer has no EC key")
        if issuer.ec_curve == "p384":
            var sig_res = asn1_parse_ecdsa_sig_48(cert.sig_bytes)
            var r = sig_res[0].copy()
            var s = sig_res[1].copy()
            p384_ecdsa_verify(issuer.ec_point, tbs_hash, r, s)
        else:
            var sig_res = asn1_parse_ecdsa_sig(cert.sig_bytes)
            var r = sig_res[0].copy()
            var s = sig_res[1].copy()
            # P-256 uses 32-byte e; truncate hash to 32 bytes if longer
            if len(tbs_hash) > 32:
                var truncated = List[UInt8](capacity=32)
                for i in range(32):
                    truncated.append(tbs_hash[i])
                p256_ecdsa_verify(issuer.ec_point, truncated, r, s)
            else:
                p256_ecdsa_verify(issuer.ec_point, tbs_hash, r, s)
    else:
        raise Error("cert_verify: unknown sig_alg: " + cert.sig_alg)


# ============================================================================
# Internal: parse TBSCertificate children from tbs_raw
# ============================================================================

def _tbs_children(tbs_raw: List[UInt8]) raises -> List[DerElem]:
    """Parse TBSCertificate TLV bytes into its children."""
    var elem = der_parse(tbs_raw, 0)
    if elem[0] != TAG_SEQUENCE:
        raise Error("cert_san: tbs_raw is not SEQUENCE")
    return der_children(elem[1])


def _bytes_to_string(b: List[UInt8]) -> String:
    """Convert byte list to String (assumes valid UTF-8)."""
    var copy = b.copy()
    return String(unsafe_from_utf8=copy^)


def _bytes_lower_eq(a: List[UInt8], b: List[UInt8]) -> Bool:
    """Case-insensitive byte comparison (ASCII only)."""
    if len(a) != len(b):
        return False
    for i in range(len(a)):
        var ca = a[i]
        var cb = b[i]
        # lowercase: if 65-90 (A-Z), add 32
        if ca >= 65 and ca <= 90:
            ca += 32
        if cb >= 65 and cb <= 90:
            cb += 32
        if ca != cb:
            return False
    return True


def _string_lower_bytes(s: String) -> List[UInt8]:
    """Return lowercase ASCII bytes of string."""
    var span = s.as_bytes()
    var out = List[UInt8](capacity=len(span))
    for i in range(len(span)):
        var c = span[i]
        if c >= 65 and c <= 90:
            c += 32
        out.append(c)
    return out^


# ============================================================================
# cert_san_names — return list of dNSName strings from SAN extension
# Falls back to Subject CN if no SAN extension present.
# ============================================================================

def cert_san_names(cert: X509Cert) raises -> List[String]:
    """Parse SubjectAltName dNSName entries. Falls back to Subject CN."""
    var tbs_ch = _tbs_children(cert.tbs_raw)

    # Determine index of subject and extensions based on version presence
    var has_version = len(tbs_ch) > 0 and tbs_ch[0].tag == TAG_CTX0
    var subject_idx = 5 if has_version else 4
    var ext_ctx_idx = 7 if has_version else 6

    # Try to find extensions ([3] EXPLICIT)
    var found_san = False
    var san_names = List[String]()

    if len(tbs_ch) > ext_ctx_idx and tbs_ch[ext_ctx_idx].tag == TAG_CTX3:
        var ext_ctx = tbs_ch[ext_ctx_idx].copy()
        # [3] EXPLICIT { SEQUENCE OF Extension }
        var ext_seq_ch = der_children(ext_ctx.content)
        if len(ext_seq_ch) > 0 and ext_seq_ch[0].tag == TAG_SEQUENCE:
            var extensions = der_children(ext_seq_ch[0].content)
            for i in range(len(extensions)):
                var ext = extensions[i].copy()
                if ext.tag != TAG_SEQUENCE:
                    continue
                var ext_ch = der_children(ext.content)
                if len(ext_ch) < 2 or ext_ch[0].tag != TAG_OID:
                    continue
                if not der_oid_eq(ext_ch[0].content, OID_SUBJECT_ALT_NAME):
                    continue
                # Found SAN extension; value is in last child (OCTET STRING)
                var val_elem = ext_ch[len(ext_ch) - 1].copy()
                if val_elem.tag != TAG_OCTET_STRING:
                    continue
                # The OCTET STRING contains DER: SEQUENCE OF GeneralName
                var san_seq = der_parse(val_elem.content, 0)
                var general_names = der_children(san_seq[1])
                for j in range(len(general_names)):
                    var gn = general_names[j].copy()
                    if gn.tag == TAG_DNS_NAME:
                        san_names.append(_bytes_to_string(gn.content))
                found_san = True
                break

    if found_san:
        return san_names^

    # Fallback: extract Subject CN
    if len(tbs_ch) <= subject_idx:
        raise Error("cert_san_names: TBSCertificate too short to have subject")

    var subject_elem = tbs_ch[subject_idx].copy()
    # Subject is SEQUENCE OF { SET OF { SEQUENCE { OID, value } } }
    var rdns = der_children(subject_elem.content)
    for i in range(len(rdns)):
        var rdn = rdns[i].copy()
        if rdn.tag != TAG_SET:
            continue
        var atv_list = der_children(rdn.content)
        for j in range(len(atv_list)):
            var atv = atv_list[j].copy()
            if atv.tag != TAG_SEQUENCE:
                continue
            var atv_ch = der_children(atv.content)
            if len(atv_ch) < 2 or atv_ch[0].tag != TAG_OID:
                continue
            if der_oid_eq(atv_ch[0].content, OID_COMMON_NAME):
                var cn_elem = atv_ch[1].copy()
                # CN value can be UTF8String, PrintableString, IA5String, etc.
                if cn_elem.tag == TAG_UTF8_STRING or cn_elem.tag == TAG_PRINTABLE_STRING or cn_elem.tag == TAG_IA5_STRING:
                    var cn_result = List[String]()
                    cn_result.append(_bytes_to_string(cn_elem.content))
                    return cn_result^

    raise Error("cert_san_names: no SAN extension and no CN found")


# ============================================================================
# cert_hostname_match — RFC 6125 hostname matching
# ============================================================================

def cert_hostname_match(cert: X509Cert, hostname: String) raises:
    """Verify hostname matches cert SAN/CN. Raises if no match found."""
    var names = cert_san_names(cert)
    var host_lower = _string_lower_bytes(hostname)

    for i in range(len(names)):
        var name = names[i]
        var name_lower = _string_lower_bytes(name)

        # Wildcard match: "*.example.com" matches "foo.example.com" but NOT
        # "foo.bar.example.com" or "example.com"
        if len(name_lower) > 2 and name_lower[0] == 42 and name_lower[1] == 46:
            # name is "*.suffix" — wildcard
            var suffix = List[UInt8](capacity=len(name_lower) - 1)
            for j in range(1, len(name_lower)):
                suffix.append(name_lower[j])
            # host must end with suffix AND have exactly one label before it
            if len(host_lower) > len(suffix):
                # Check that host ends with suffix
                var host_tail_start = len(host_lower) - len(suffix)
                var tail_matches = True
                for j in range(len(suffix)):
                    if host_lower[host_tail_start + j] != suffix[j]:
                        tail_matches = False
                        break
                if tail_matches:
                    # The part before the suffix must be one label (no dots)
                    var prefix = List[UInt8](capacity=host_tail_start)
                    for j in range(host_tail_start):
                        prefix.append(host_lower[j])
                    var has_dot = False
                    for j in range(len(prefix)):
                        if prefix[j] == 46:  # '.'
                            has_dot = True
                            break
                    if not has_dot and len(prefix) > 0:
                        return  # match!
        else:
            # Exact match (case-insensitive)
            if _bytes_lower_eq(name_lower, host_lower):
                return  # match!

    raise Error("cert_hostname_match: hostname '" + hostname + "' does not match certificate")


# ============================================================================
# Certificate validity period checking
# ============================================================================

def _parse_asn1_time(content: List[UInt8], is_generalized: Bool) -> Int64:
    """Parse UTCTime or GeneralizedTime content bytes to Unix epoch seconds.

    UTCTime format:       YYMMDDHHMMSSZ (13 bytes)
    GeneralizedTime format: YYYYMMDDHHMMSSZ (15 bytes)
    """
    # Byte offset into content where MMDDHHMMSS begins
    var off = 4 if is_generalized else 2
    var year: Int
    if is_generalized:
        year = (Int(content[0]) - 48) * 1000 + (Int(content[1]) - 48) * 100 \
             + (Int(content[2]) - 48) * 10  + (Int(content[3]) - 48)
    else:
        var yy = (Int(content[0]) - 48) * 10 + (Int(content[1]) - 48)
        year = (2000 + yy) if yy < 50 else (1900 + yy)
    var month = (Int(content[off])   - 48) * 10 + (Int(content[off+1]) - 48)
    var day   = (Int(content[off+2]) - 48) * 10 + (Int(content[off+3]) - 48)
    var hour  = (Int(content[off+4]) - 48) * 10 + (Int(content[off+5]) - 48)
    var minu  = (Int(content[off+6]) - 48) * 10 + (Int(content[off+7]) - 48)
    var sec   = (Int(content[off+8]) - 48) * 10 + (Int(content[off+9]) - 48)

    # Days per month (non-leap year), months 1-indexed
    var dim = InlineArray[Int, 12](fill=0)
    dim[0] = 31; dim[1] = 28; dim[2] = 31; dim[3] = 30
    dim[4] = 31; dim[5] = 30; dim[6] = 31; dim[7] = 31
    dim[8] = 30; dim[9] = 31; dim[10] = 30; dim[11] = 31

    # Count days from 1970-01-01 to start of year
    var days = 0
    for y in range(1970, year):
        if (y % 4 == 0 and y % 100 != 0) or (y % 400 == 0):
            days += 366
        else:
            days += 365

    # Add days for completed months in current year
    var is_leap = (year % 4 == 0 and year % 100 != 0) or (year % 400 == 0)
    for m in range(1, month):
        var d = dim[m - 1]
        if m == 2 and is_leap:
            d += 1
        days += d

    days += day - 1
    return Int64(days) * 86400 + Int64(hour) * 3600 + Int64(minu) * 60 + Int64(sec)


def _check_cert_validity(tbs_raw: List[UInt8]) raises:
    """Check certificate notBefore/notAfter against current time. Raises if expired."""
    var tbs_elem = der_parse(tbs_raw, 0)
    if tbs_elem[0] != TAG_SEQUENCE:
        return  # malformed TBS — skip gracefully
    var tbs_ch = der_children(tbs_elem[1])
    var has_version = len(tbs_ch) > 0 and tbs_ch[0].tag == TAG_CTX0
    var validity_idx = 4 if has_version else 3
    if len(tbs_ch) <= validity_idx:
        return  # TBS too short — skip

    var validity_elem = tbs_ch[validity_idx].copy()
    if validity_elem.tag != TAG_SEQUENCE:
        return  # validity field not a SEQUENCE
    var validity_ch = der_children(validity_elem.content)
    if len(validity_ch) < 2:
        return  # need notBefore + notAfter

    # ASN.1 time tags: 0x17 = UTCTime, 0x18 = GeneralizedTime
    var not_after_elem = validity_ch[1].copy()
    var not_after: Int64
    if not_after_elem.tag == 0x17:
        not_after = _parse_asn1_time(not_after_elem.content, False)
    elif not_after_elem.tag == 0x18:
        not_after = _parse_asn1_time(not_after_elem.content, True)
    else:
        return  # unknown time format — skip

    var now = external_call["time", Int64](Int(0))
    if now > not_after:
        raise Error("cert_chain_verify: certificate has expired")

    var not_before_elem = validity_ch[0].copy()
    var not_before: Int64
    if not_before_elem.tag == 0x17:
        not_before = _parse_asn1_time(not_before_elem.content, False)
    elif not_before_elem.tag == 0x18:
        not_before = _parse_asn1_time(not_before_elem.content, True)
    else:
        return  # unknown time format — skip

    if now < not_before:
        raise Error("cert_chain_verify: certificate is not yet valid")


# ============================================================================
# cert_chain_verify — verify a certificate chain against trust anchors
# ============================================================================

def cert_chain_verify(
    chain:         List[X509Cert],
    trust_anchors: List[X509Cert],
    hostname:      String,
) raises:
    """Verify a certificate chain.

    1. cert_hostname_match(chain[0], hostname)
    2. For i in 0..len(chain)-1: cert_verify_sig(chain[i], chain[i+1])
    3. If chain[-1] not in trust_anchors by signature: try each anchor
    Raises with descriptive Error on any failure.
    """
    if len(chain) == 0:
        raise Error("cert_chain_verify: empty chain")

    # Step 0: validity period check for each cert in chain
    for i in range(len(chain)):
        _check_cert_validity(chain[i].tbs_raw)

    # Step 1: hostname match on leaf
    cert_hostname_match(chain[0], hostname)

    # Step 2: verify each cert against the next in chain
    for i in range(len(chain) - 1):
        cert_verify_sig(chain[i], chain[i + 1])

    # Step 3: verify root (chain[-1]) against a trust anchor
    var root = chain[len(chain) - 1].copy()

    # Try self-signed first (root signed by itself)
    var self_signed = False
    try:
        cert_verify_sig(root, root)
        self_signed = True
    except:
        pass

    if self_signed:
        # Still must appear in trust_anchors — check by TBS bytes match
        for i in range(len(trust_anchors)):
            if _bytes_lower_eq(trust_anchors[i].tbs_raw, root.tbs_raw):
                return  # trusted
        raise Error("cert_chain_verify: root not in trust anchors")

    # Try each trust anchor to sign the root
    for i in range(len(trust_anchors)):
        var ok = False
        try:
            cert_verify_sig(root, trust_anchors[i])
            ok = True
        except:
            pass
        if ok:
            return  # trusted

    raise Error("cert_chain_verify: chain root not trusted by any anchor")
