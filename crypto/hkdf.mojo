# ============================================================================
# crypto/hkdf.mojo — HKDF-SHA256 (RFC 5869) + TLS 1.3 HKDF-Expand-Label
# ============================================================================
#
# HKDF-Extract(salt, IKM) -> PRK = HMAC-H(salt, IKM)
# HKDF-Expand(PRK, info, L) -> OKM
#   T(0) = ""
#   T(i) = HMAC-H(PRK, T(i-1) || info || i)
#   OKM  = T(1) || T(2) || ... truncated to L bytes
#
# HKDF-Expand-Label (TLS 1.3 §7.1):
#   HkdfLabel = Length(uint16) || len(label)(uint8) || label || len(ctx)(uint8) || ctx
#   label = "tls13 " + Label
# ============================================================================

from crypto.hmac import hmac_sha256, hmac_sha384


def hkdf_extract(salt: List[UInt8], ikm: List[UInt8]) -> List[UInt8]:
    """HKDF-Extract using SHA-256. Returns 32-byte PRK.

    If no salt is available, pass salt = 0x00 * 32.
    """
    return hmac_sha256(salt, ikm)


def hkdf_expand(prk: List[UInt8], info: List[UInt8], length: Int) raises -> List[UInt8]:
    """HKDF-Expand using SHA-256. Returns `length` bytes of keying material.

    Requires: length <= 255 * 32 (255 * HashLen).
    """
    var hash_len = 32  # SHA-256 digest size
    if length > 255 * hash_len:
        raise Error("hkdf_expand: requested length exceeds 255 * HashLen")
    var n = (length + hash_len - 1) // hash_len  # ceil(length / hash_len)

    var okm = List[UInt8](capacity=n * hash_len)
    var t = List[UInt8]()  # T(0) = empty

    for i in range(1, n + 1):
        # data = T(i-1) || info || i
        var data = List[UInt8](capacity=len(t) + len(info) + 1)
        for j in range(len(t)):
            data.append(t[j])
        for j in range(len(info)):
            data.append(info[j])
        data.append(UInt8(i))

        t = hmac_sha256(prk, data)
        for j in range(len(t)):
            okm.append(t[j])

    # Truncate to requested length
    var result = List[UInt8](capacity=length)
    for i in range(length):
        result.append(okm[i])
    return result^


def hkdf_expand_label(
    secret: List[UInt8],
    label: String,
    context: List[UInt8],
    length: Int,
) raises -> List[UInt8]:
    """HKDF-Expand-Label as defined in RFC 8446 §7.1 (TLS 1.3).

    HkdfLabel encoding:
      uint16  length       — desired output length in big-endian
      uint8   label_len    — length of ("tls13 " + label)
      bytes   label_bytes  — "tls13 " + label
      uint8   ctx_len      — length of context
      bytes   context      — Hash(message) or ""
    """
    var prefix = "tls13 "
    var full_label_bytes = List[UInt8]()
    for b in prefix.as_bytes():
        full_label_bytes.append(b)
    for b in label.as_bytes():
        full_label_bytes.append(b)

    var hkdf_label = List[UInt8]()
    # uint16 length (big-endian)
    hkdf_label.append(UInt8((length >> 8) & 0xFF))
    hkdf_label.append(UInt8(length & 0xFF))
    # uint8 label_len + label
    hkdf_label.append(UInt8(len(full_label_bytes)))
    for b in full_label_bytes:
        hkdf_label.append(b)
    # uint8 ctx_len + context
    hkdf_label.append(UInt8(len(context)))
    for b in context:
        hkdf_label.append(b)

    return hkdf_expand(secret, hkdf_label, length)


# ============================================================================
# HKDF-SHA384 variants (for TLS_AES_256_GCM_SHA384 / cipher suite 0x1302)
# ============================================================================

def hkdf_extract_sha384(salt: List[UInt8], ikm: List[UInt8]) -> List[UInt8]:
    """HKDF-Extract using SHA-384. Returns 48-byte PRK.

    If no salt is available, pass salt = 0x00 * 48.
    """
    return hmac_sha384(salt, ikm)


def hkdf_expand_sha384(prk: List[UInt8], info: List[UInt8], length: Int) raises -> List[UInt8]:
    """HKDF-Expand using SHA-384. Returns `length` bytes of keying material.

    Requires: length <= 255 * 48 (255 * HashLen).
    """
    var hash_len = 48  # SHA-384 digest size
    if length > 255 * hash_len:
        raise Error("hkdf_expand_sha384: requested length exceeds 255 * HashLen")
    var n = (length + hash_len - 1) // hash_len  # ceil(length / hash_len)

    var okm = List[UInt8](capacity=n * hash_len)
    var t = List[UInt8]()  # T(0) = empty

    for i in range(1, n + 1):
        # data = T(i-1) || info || i
        var data = List[UInt8](capacity=len(t) + len(info) + 1)
        for j in range(len(t)):
            data.append(t[j])
        for j in range(len(info)):
            data.append(info[j])
        data.append(UInt8(i))

        t = hmac_sha384(prk, data)
        for j in range(len(t)):
            okm.append(t[j])

    # Truncate to requested length
    var result = List[UInt8](capacity=length)
    for i in range(length):
        result.append(okm[i])
    return result^


def hkdf_expand_label_sha384(
    secret: List[UInt8],
    label: String,
    context: List[UInt8],
    length: Int,
) raises -> List[UInt8]:
    """HKDF-Expand-Label (SHA-384) as defined in RFC 8446 §7.1 (TLS 1.3).

    HkdfLabel encoding:
      uint16  length       — desired output length in big-endian
      uint8   label_len    — length of ("tls13 " + label)
      bytes   label_bytes  — "tls13 " + label
      uint8   ctx_len      — length of context
      bytes   context      — Hash(message) or ""
    """
    var prefix = "tls13 "
    var full_label_bytes = List[UInt8]()
    for b in prefix.as_bytes():
        full_label_bytes.append(b)
    for b in label.as_bytes():
        full_label_bytes.append(b)

    var hkdf_label = List[UInt8]()
    # uint16 length (big-endian)
    hkdf_label.append(UInt8((length >> 8) & 0xFF))
    hkdf_label.append(UInt8(length & 0xFF))
    # uint8 label_len + label
    hkdf_label.append(UInt8(len(full_label_bytes)))
    for b in full_label_bytes:
        hkdf_label.append(b)
    # uint8 ctx_len + context
    hkdf_label.append(UInt8(len(context)))
    for b in context:
        hkdf_label.append(b)

    return hkdf_expand_sha384(secret, hkdf_label, length)
