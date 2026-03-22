# ============================================================================
# handshake.mojo — TLS 1.3 key schedule and handshake primitives
# ============================================================================
# API (key schedule):
#   tls13_early_secret()                        → 32-byte Early Secret
#   tls13_handshake_secret(early, dhe)           → 32-byte Handshake Secret
#   tls13_master_secret(handshake_secret)        → 32-byte Master Secret
#   tls13_derive_secret(secret, label, hash)     → 32-byte derived secret
#   tls13_traffic_keys(secret, key_len, iv_len)  → (key, iv)
#   tls13_finished_key(secret)                   → 32-byte HMAC key
#   tls13_verify_finished(fkey, transcript_hash, verify_data) → raises if bad
#   tls13_compute_finished(fkey, transcript_hash) → 32-byte verify_data
#
# References: RFC 8446 §7.1 (key schedule), §4.4.4 (Finished)
# ============================================================================

from crypto.hkdf import hkdf_extract, hkdf_expand_label, hkdf_extract_sha384, hkdf_expand_label_sha384
from crypto.hmac import hmac_sha256, hmac_sha384, hmac_equal
from crypto.hash import sha256, sha384


# ============================================================================
# Key Schedule
# ============================================================================

def _zeros32() -> List[UInt8]:
    """32 zero bytes — used as IKM or salt when no real input is available."""
    var z = List[UInt8](capacity=32)
    for _ in range(32):
        z.append(0)
    return z^


def _hash_empty() -> List[UInt8]:
    """SHA-256 of the empty string (= e3b0c44298fc1c...)."""
    return sha256(_zeros32()[:0])  # can't easily get a zero-len List here

def _sha256_empty() -> List[UInt8]:
    """SHA-256 of empty string."""
    var empty = List[UInt8]()
    return sha256(empty)


def tls13_early_secret() -> List[UInt8]:
    """Compute TLS 1.3 Early Secret: HKDF-Extract(0^32, 0^32).

    When no PSK is used (most connections), both salt and IKM are zero.
    Returns 32 bytes.
    """
    return hkdf_extract(_zeros32(), _zeros32())


def tls13_handshake_secret(early_secret: List[UInt8], dhe: List[UInt8]) raises -> List[UInt8]:
    """Compute TLS 1.3 Handshake Secret from Early Secret and ECDHE shared value.

    derived_salt = HKDF-Expand-Label(early_secret, "derived", SHA256(""), 32)
    HS           = HKDF-Extract(derived_salt, dhe)
    Returns 32 bytes.
    """
    var h_empty = _sha256_empty()
    var derived_salt = hkdf_expand_label(early_secret, "derived", h_empty, 32)
    return hkdf_extract(derived_salt, dhe)


def tls13_master_secret(handshake_secret: List[UInt8]) raises -> List[UInt8]:
    """Compute TLS 1.3 Master Secret from Handshake Secret.

    derived_salt = HKDF-Expand-Label(hs, "derived", SHA256(""), 32)
    MS           = HKDF-Extract(derived_salt, 0^32)
    Returns 32 bytes.
    """
    var h_empty = _sha256_empty()
    var derived_salt = hkdf_expand_label(handshake_secret, "derived", h_empty, 32)
    return hkdf_extract(derived_salt, _zeros32())


def tls13_derive_secret(secret: List[UInt8], label: String, transcript_hash: List[UInt8]) raises -> List[UInt8]:
    """Derive-Secret(secret, label, messages_hash) per RFC 8446 §7.1.

    Returns HKDF-Expand-Label(secret, label, transcript_hash, 32).
    """
    return hkdf_expand_label(secret, label, transcript_hash, 32)


def tls13_traffic_keys(
    traffic_secret: List[UInt8],
    key_len:        Int,
    iv_len:         Int,
) raises -> Tuple[List[UInt8], List[UInt8]]:
    """Derive (write_key, write_iv) from a TLS 1.3 traffic secret.

    key = HKDF-Expand-Label(secret, "key", "", key_len)
    iv  = HKDF-Expand-Label(secret, "iv",  "", iv_len)
    """
    var empty = List[UInt8]()
    var key = hkdf_expand_label(traffic_secret, "key", empty, key_len)
    var iv  = hkdf_expand_label(traffic_secret, "iv",  empty, iv_len)
    return (key^, iv^)


def tls13_finished_key(traffic_secret: List[UInt8]) raises -> List[UInt8]:
    """Compute the Finished HMAC key: HKDF-Expand-Label(secret, "finished", "", 32)."""
    var empty = List[UInt8]()
    return hkdf_expand_label(traffic_secret, "finished", empty, 32)


def tls13_compute_finished(finished_key: List[UInt8], transcript_hash: List[UInt8]) -> List[UInt8]:
    """Compute Finished verify_data = HMAC-SHA256(finished_key, transcript_hash)."""
    return hmac_sha256(finished_key, transcript_hash)


def tls13_verify_finished(
    finished_key:    List[UInt8],
    transcript_hash: List[UInt8],
    verify_data:     List[UInt8],
) raises:
    """Verify TLS 1.3 Finished message. Raises on mismatch.

    Expected = HMAC-SHA256(finished_key, transcript_hash)
    """
    var expected = hmac_sha256(finished_key, transcript_hash)
    if not hmac_equal(verify_data, expected):
        raise Error("tls13_verify_finished: Finished MAC mismatch")


# ============================================================================
# CertificateVerify support
# ============================================================================

comptime CERT_VERIFY_SERVER_CTX = "TLS 1.3, server CertificateVerify"
comptime CERT_VERIFY_CLIENT_CTX = "TLS 1.3, client CertificateVerify"


# ============================================================================
# SHA-384 Key Schedule (for TLS_AES_256_GCM_SHA384 / cipher suite 0x1302)
# ============================================================================

def _zeros48() -> List[UInt8]:
    """48 zero bytes — used as IKM or salt for SHA-384 key schedule."""
    var z = List[UInt8](capacity=48)
    for _ in range(48):
        z.append(0)
    return z^


def _sha384_empty() -> List[UInt8]:
    """SHA-384 of empty string."""
    var empty = List[UInt8]()
    return sha384(empty)


def tls13_early_secret_sha384() -> List[UInt8]:
    """Compute TLS 1.3 Early Secret (SHA-384): HKDF-Extract-SHA384(0^48, 0^48).

    Returns 48 bytes.
    """
    return hkdf_extract_sha384(_zeros48(), _zeros48())


def tls13_handshake_secret_sha384(early_secret: List[UInt8], dhe: List[UInt8]) raises -> List[UInt8]:
    """Compute TLS 1.3 Handshake Secret (SHA-384) from Early Secret and DHE.

    derived_salt = HKDF-Expand-Label-SHA384(early_secret, "derived", SHA384(""), 48)
    HS           = HKDF-Extract-SHA384(derived_salt, dhe)
    Returns 48 bytes.
    """
    var h_empty = _sha384_empty()
    var derived_salt = hkdf_expand_label_sha384(early_secret, "derived", h_empty, 48)
    return hkdf_extract_sha384(derived_salt, dhe)


def tls13_master_secret_sha384(handshake_secret: List[UInt8]) raises -> List[UInt8]:
    """Compute TLS 1.3 Master Secret (SHA-384) from Handshake Secret.

    derived_salt = HKDF-Expand-Label-SHA384(hs, "derived", SHA384(""), 48)
    MS           = HKDF-Extract-SHA384(derived_salt, 0^48)
    Returns 48 bytes.
    """
    var h_empty = _sha384_empty()
    var derived_salt = hkdf_expand_label_sha384(handshake_secret, "derived", h_empty, 48)
    return hkdf_extract_sha384(derived_salt, _zeros48())


def tls13_derive_secret_sha384(
    secret: List[UInt8],
    label: String,
    transcript_hash: List[UInt8],
) raises -> List[UInt8]:
    """Derive-Secret (SHA-384): HKDF-Expand-Label-SHA384(secret, label, transcript_hash, 48)."""
    return hkdf_expand_label_sha384(secret, label, transcript_hash, 48)


def tls13_traffic_keys_sha384(
    traffic_secret: List[UInt8],
    key_len:        Int,
    iv_len:         Int,
) raises -> Tuple[List[UInt8], List[UInt8]]:
    """Derive (write_key, write_iv) from a TLS 1.3 SHA-384 traffic secret.

    key = HKDF-Expand-Label-SHA384(secret, "key", "", key_len)
    iv  = HKDF-Expand-Label-SHA384(secret, "iv",  "", iv_len)
    """
    var empty = List[UInt8]()
    var key = hkdf_expand_label_sha384(traffic_secret, "key", empty, key_len)
    var iv  = hkdf_expand_label_sha384(traffic_secret, "iv",  empty, iv_len)
    return (key^, iv^)


def tls13_finished_key_sha384(traffic_secret: List[UInt8]) raises -> List[UInt8]:
    """Compute the Finished HMAC key (SHA-384):
    HKDF-Expand-Label-SHA384(secret, "finished", "", 48)."""
    var empty = List[UInt8]()
    return hkdf_expand_label_sha384(traffic_secret, "finished", empty, 48)


def tls13_compute_finished_sha384(
    finished_key: List[UInt8],
    transcript_hash: List[UInt8],
) -> List[UInt8]:
    """Compute Finished verify_data (SHA-384) = HMAC-SHA384(finished_key, transcript_hash)."""
    return hmac_sha384(finished_key, transcript_hash)


def tls13_verify_finished_sha384(
    finished_key:    List[UInt8],
    transcript_hash: List[UInt8],
    verify_data:     List[UInt8],
) raises:
    """Verify TLS 1.3 Finished message (SHA-384). Raises on mismatch."""
    var expected = hmac_sha384(finished_key, transcript_hash)
    if not hmac_equal(verify_data, expected):
        raise Error("tls13_verify_finished_sha384: Finished MAC mismatch")


# ============================================================================
# CertificateVerify support
# ============================================================================

def tls13_cert_verify_input(context: String, transcript_hash: List[UInt8]) -> List[UInt8]:
    """Build the CertificateVerify message content to be signed/verified.

    Format (RFC 8446 §4.4.3):
      64 bytes of 0x20 (space)
      || context string
      || 0x00
      || SHA-256(handshake transcript)
    """
    var ctx_bytes = context.as_bytes()
    var total = 64 + len(ctx_bytes) + 1 + len(transcript_hash)
    var out = List[UInt8](capacity=total)
    # 64 spaces
    for _ in range(64):
        out.append(0x20)
    # context
    for i in range(len(ctx_bytes)):
        out.append(ctx_bytes[i])
    # separator
    out.append(0x00)
    # transcript hash
    for i in range(len(transcript_hash)):
        out.append(transcript_hash[i])
    return out^
