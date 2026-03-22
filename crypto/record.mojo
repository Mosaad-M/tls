# ============================================================================
# record.mojo — TLS 1.3 record layer (AEAD encryption / decryption)
# ============================================================================
# API:
#   record_seal(cipher, key, iv, seqno, content_type, plaintext) → List[UInt8]
#   record_open(cipher, key, iv, seqno, record)                  → (UInt8, List[UInt8])
#
# Cipher constants:
#   CIPHER_AES_128_GCM       = 0   key must be 16 bytes
#   CIPHER_AES_256_GCM       = 1   key must be 32 bytes
#   CIPHER_CHACHA20_POLY1305 = 2   key must be 32 bytes
#
# TLS 1.3 content type constants (for convenience):
#   CTYPE_CHANGE_CIPHER_SPEC = 0x14
#   CTYPE_ALERT              = 0x15
#   CTYPE_HANDSHAKE          = 0x16
#   CTYPE_APPLICATION_DATA   = 0x17
# ============================================================================

from crypto.gcm import gcm_encrypt, gcm_decrypt
from crypto.poly1305 import chacha20_poly1305_encrypt, chacha20_poly1305_decrypt


# Cipher suite identifiers
comptime CIPHER_AES_128_GCM       : UInt8 = 0
comptime CIPHER_AES_256_GCM       : UInt8 = 1
comptime CIPHER_CHACHA20_POLY1305 : UInt8 = 2

# TLS 1.3 content types
comptime CTYPE_CHANGE_CIPHER_SPEC : UInt8 = 0x14
comptime CTYPE_ALERT              : UInt8 = 0x15
comptime CTYPE_HANDSHAKE          : UInt8 = 0x16
comptime CTYPE_APPLICATION_DATA   : UInt8 = 0x17


# ============================================================================
# Internal helpers
# ============================================================================

def _make_nonce(iv: List[UInt8], seqno: UInt64) -> List[UInt8]:
    """Compute per-record nonce: iv XOR seqno padded to 12 bytes (big-endian)."""
    var nonce = List[UInt8](capacity=12)
    var s = seqno
    # High 4 bytes: iv XOR 0 = iv
    for i in range(4):
        nonce.append(iv[i])
    # Low 8 bytes: iv XOR 8-byte big-endian seqno
    for i in range(8):
        var shift = UInt64(56 - i * 8)
        nonce.append(iv[4 + i] ^ UInt8((s >> shift) & 0xFF))
    return nonce^


def _make_aad(inner_len: Int) -> List[UInt8]:
    """Build TLS 1.3 AAD: opaque_type=0x17, version=0x0303, length=inner+16."""
    var total = inner_len + 16  # includes 16-byte authentication tag
    var aad = List[UInt8](capacity=5)
    aad.append(0x17)  # opaque_type = application_data (always 0x17 in TLS 1.3)
    aad.append(0x03)  # legacy_record_version
    aad.append(0x03)
    aad.append(UInt8((total >> 8) & 0xFF))
    aad.append(UInt8(total & 0xFF))
    return aad^


# ============================================================================
# record_seal — encrypt and authenticate a TLS 1.3 record
# ============================================================================

def record_seal(
    cipher:       UInt8,
    key:          List[UInt8],
    iv:           List[UInt8],
    seqno:        UInt64,
    content_type: UInt8,
    plaintext:    List[UInt8],
) raises -> List[UInt8]:
    """AEAD-encrypt a TLS 1.3 record. Returns full TLS record bytes (header + ciphertext + tag)."""
    if len(iv) != 12:
        raise Error("record_seal: IV must be 12 bytes")

    # Inner plaintext = plaintext || content_type (TLS 1.3 §5.2)
    var inner = List[UInt8](capacity=len(plaintext) + 1)
    for i in range(len(plaintext)):
        inner.append(plaintext[i])
    inner.append(content_type)

    var aad   = _make_aad(len(inner))
    var nonce = _make_nonce(iv, seqno)

    # Encrypt
    var ct: List[UInt8]
    var tag: List[UInt8]
    if cipher == CIPHER_AES_128_GCM or cipher == CIPHER_AES_256_GCM:
        var enc = gcm_encrypt(key, nonce, inner, aad)
        ct  = enc[0].copy()
        tag = enc[1].copy()
    else:  # CIPHER_CHACHA20_POLY1305
        var enc = chacha20_poly1305_encrypt(key, nonce, aad, inner)
        ct  = enc[0].copy()
        tag = enc[1].copy()

    # Build record: header (5 bytes) || ciphertext || tag (16 bytes)
    var record = List[UInt8](capacity=5 + len(ct) + 16)
    for i in range(5):
        record.append(aad[i])
    for i in range(len(ct)):
        record.append(ct[i])
    for i in range(16):
        record.append(tag[i])
    return record^


# ============================================================================
# record_open — decrypt and verify a TLS 1.3 record
# ============================================================================

def record_open(
    cipher: UInt8,
    key:    List[UInt8],
    iv:     List[UInt8],
    seqno:  UInt64,
    record: List[UInt8],
) raises -> Tuple[UInt8, List[UInt8]]:
    """AEAD-decrypt a TLS 1.3 record. Returns (content_type, plaintext). Raises on auth failure."""
    if len(iv) != 12:
        raise Error("record_open: IV must be 12 bytes")
    # Minimum: 5-byte header + 1-byte inner (ctype) + 16-byte tag = 22 bytes
    if len(record) < 22:
        raise Error("record_open: record too short")
    if record[0] != 0x17:
        raise Error("record_open: opaque_type must be 0x17")
    if record[1] != 0x03 or record[2] != 0x03:
        raise Error("record_open: legacy version must be 0x0303")

    var ct_tag_len = len(record) - 5
    if ct_tag_len < 17:  # 1 byte ciphertext + 16 byte tag minimum
        raise Error("record_open: ciphertext+tag too short")
    var ct_len = ct_tag_len - 16

    # Slice ciphertext and tag out of record
    var ciphertext = List[UInt8](capacity=ct_len)
    for i in range(ct_len):
        ciphertext.append(record[5 + i])
    var tag = List[UInt8](capacity=16)
    for i in range(16):
        tag.append(record[5 + ct_len + i])

    # AAD = the record header (first 5 bytes)
    var aad = List[UInt8](capacity=5)
    for i in range(5):
        aad.append(record[i])

    var nonce = _make_nonce(iv, seqno)

    # Decrypt and verify
    var inner: List[UInt8]
    if cipher == CIPHER_AES_128_GCM or cipher == CIPHER_AES_256_GCM:
        inner = gcm_decrypt(key, nonce, ciphertext, tag, aad)
    else:  # CIPHER_CHACHA20_POLY1305
        inner = chacha20_poly1305_decrypt(key, nonce, aad, ciphertext, tag)

    # Inner = actual_plaintext || content_type
    if len(inner) < 1:
        raise Error("record_open: inner plaintext missing content type")
    var content_type = inner[len(inner) - 1]
    var pt_len = len(inner) - 1
    var pt = List[UInt8](capacity=pt_len)
    for i in range(pt_len):
        pt.append(inner[i])

    return (content_type, pt^)


# ============================================================================
# record_seal_12 / record_open_12 — TLS 1.2 AEAD record layer
# ============================================================================
#
# TLS 1.2 AEAD differs from TLS 1.3:
#   nonce    = iv_implicit(4) || explicit_nonce(8)
#              explicit_nonce = seqno as 8-byte big-endian (sent on wire)
#   AAD      = seqno(8) || content_type(1) || 0x03 0x03(2) || plaintext_len(2)
#   on-wire  = explicit_nonce(8) || ciphertext || tag(16)
# ============================================================================

def _make_nonce_12(iv_implicit: List[UInt8], seqno: UInt64) -> List[UInt8]:
    """Build 12-byte TLS 1.2 nonce: iv_implicit(4) || seqno_be8(8)."""
    var nonce = List[UInt8](capacity=12)
    for i in range(4):
        nonce.append(iv_implicit[i])
    for i in range(8):
        var shift = UInt64(56 - i * 8)
        nonce.append(UInt8((seqno >> shift) & 0xFF))
    return nonce^


def _make_explicit_nonce(seqno: UInt64) -> List[UInt8]:
    """Build 8-byte explicit nonce from sequence number (big-endian)."""
    var out = List[UInt8](capacity=8)
    for i in range(8):
        var shift = UInt64(56 - i * 8)
        out.append(UInt8((seqno >> shift) & 0xFF))
    return out^


def _make_aad_12(seqno: UInt64, content_type: UInt8, plaintext_len: Int) -> List[UInt8]:
    """Build TLS 1.2 AAD: seqno(8) || content_type(1) || 0x03 0x03(2) || plaintext_len(2)."""
    var aad = List[UInt8](capacity=13)
    for i in range(8):
        var shift = UInt64(56 - i * 8)
        aad.append(UInt8((seqno >> shift) & 0xFF))
    aad.append(content_type)
    aad.append(0x03)   # legacy_version hi
    aad.append(0x03)   # legacy_version lo
    aad.append(UInt8((plaintext_len >> 8) & 0xFF))
    aad.append(UInt8(plaintext_len & 0xFF))
    return aad^


def record_seal_12(
    cipher:      UInt8,
    key:         List[UInt8],
    iv_implicit: List[UInt8],   # 4-byte implicit IV from key_block
    seqno:       UInt64,
    content_type: UInt8,
    plaintext:   List[UInt8],
) raises -> List[UInt8]:
    """AEAD-encrypt a TLS 1.2 record.

    Returns: explicit_nonce(8) || ciphertext || tag(16)
    The TLS record header is NOT included — caller builds the full record.
    """
    if len(iv_implicit) != 4:
        raise Error("record_seal_12: iv_implicit must be 4 bytes")

    var explicit_nonce = _make_explicit_nonce(seqno)
    var nonce = _make_nonce_12(iv_implicit, seqno)
    var aad   = _make_aad_12(seqno, content_type, len(plaintext))

    var ct: List[UInt8]
    var tag: List[UInt8]
    if cipher == CIPHER_AES_128_GCM or cipher == CIPHER_AES_256_GCM:
        var enc = gcm_encrypt(key, nonce, plaintext, aad)
        ct  = enc[0].copy()
        tag = enc[1].copy()
    else:
        raise Error("record_seal_12: only AES-GCM supported")

    # Output: explicit_nonce || ciphertext || tag
    var out = List[UInt8](capacity=8 + len(ct) + 16)
    for i in range(8):
        out.append(explicit_nonce[i])
    for i in range(len(ct)):
        out.append(ct[i])
    for i in range(16):
        out.append(tag[i])
    return out^


def record_open_12(
    cipher:      UInt8,
    key:         List[UInt8],
    iv_implicit: List[UInt8],   # 4-byte implicit IV from key_block
    seqno:       UInt64,
    content_type: UInt8,
    payload:     List[UInt8],   # explicit_nonce(8) || ciphertext || tag(16)
) raises -> List[UInt8]:
    """AEAD-decrypt a TLS 1.2 record payload.

    Input: explicit_nonce(8) || ciphertext || tag(16)
    Returns: plaintext
    """
    if len(iv_implicit) != 4:
        raise Error("record_open_12: iv_implicit must be 4 bytes")
    if len(payload) < 8 + 16:
        raise Error("record_open_12: payload too short (need at least 24 bytes)")

    # Build full 12-byte nonce from implicit IV + explicit nonce (from wire)
    var nonce = List[UInt8](capacity=12)
    for i in range(4):
        nonce.append(iv_implicit[i])
    for i in range(8):
        nonce.append(payload[i])

    var ct_tag_len = len(payload) - 8
    var ct_len = ct_tag_len - 16

    var ciphertext = List[UInt8](capacity=ct_len)
    for i in range(ct_len):
        ciphertext.append(payload[8 + i])
    var tag = List[UInt8](capacity=16)
    for i in range(16):
        tag.append(payload[8 + ct_len + i])

    var aad = _make_aad_12(seqno, content_type, ct_len)

    if cipher == CIPHER_AES_128_GCM or cipher == CIPHER_AES_256_GCM:
        return gcm_decrypt(key, nonce, ciphertext, tag, aad)
    else:
        raise Error("record_open_12: only AES-GCM supported")
