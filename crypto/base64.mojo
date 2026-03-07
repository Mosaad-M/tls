# ============================================================================
# crypto/base64.mojo — RFC 4648 Base64 encode/decode
# ============================================================================
# API:
#   base64_encode(data: List[UInt8]) -> String
#   base64_decode(s: String) raises -> List[UInt8]
# ============================================================================

comptime _B64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


fn base64_encode(data: List[UInt8]) -> String:
    """Encode bytes to standard base64 with padding."""
    var n = len(data)
    if n == 0:
        return String("")

    var table = _B64_CHARS.as_bytes()
    var out_len = ((n + 2) // 3) * 4
    var out = List[UInt8](capacity=out_len)

    var i = 0
    while i + 2 < n:
        var b0 = UInt32(data[i])
        var b1 = UInt32(data[i + 1])
        var b2 = UInt32(data[i + 2])
        out.append(table[Int((b0 >> 2) & 0x3F)])
        out.append(table[Int(((b0 << 4) | (b1 >> 4)) & 0x3F)])
        out.append(table[Int(((b1 << 2) | (b2 >> 6)) & 0x3F)])
        out.append(table[Int(b2 & 0x3F)])
        i += 3

    var remaining = n - i
    if remaining == 1:
        var b0 = UInt32(data[i])
        out.append(table[Int((b0 >> 2) & 0x3F)])
        out.append(table[Int((b0 << 4) & 0x3F)])
        out.append(UInt8(61))  # '='
        out.append(UInt8(61))  # '='
    elif remaining == 2:
        var b0 = UInt32(data[i])
        var b1 = UInt32(data[i + 1])
        out.append(table[Int((b0 >> 2) & 0x3F)])
        out.append(table[Int(((b0 << 4) | (b1 >> 4)) & 0x3F)])
        out.append(table[Int((b1 << 2) & 0x3F)])
        out.append(UInt8(61))  # '='

    return String(unsafe_from_utf8=out^)


fn _b64_decode_char(c: UInt8) raises -> UInt8:
    """Decode a single base64 character to its 6-bit value. Raises on invalid."""
    if c >= 65 and c <= 90:    # A-Z
        return c - 65
    if c >= 97 and c <= 122:   # a-z
        return c - 71
    if c >= 48 and c <= 57:    # 0-9
        return c + 4
    if c == 43:                 # '+'
        return 62
    if c == 47:                 # '/'
        return 63
    raise Error("base64_decode: invalid character: " + String(Int(c)))


fn base64_decode(s: String) raises -> List[UInt8]:
    """Decode standard base64 string to bytes. Raises on invalid input."""
    var raw = s.as_bytes()
    var n = len(raw)
    if n == 0:
        return List[UInt8]()
    if n % 4 != 0:
        raise Error("base64_decode: length " + String(n) + " is not a multiple of 4")

    # Count padding
    var pad = 0
    if n >= 1 and raw[n - 1] == 61:   # '='
        pad += 1
    if n >= 2 and raw[n - 2] == 61:   # '='
        pad += 1

    var out_len = (n // 4) * 3 - pad
    var out = List[UInt8](capacity=out_len)

    var i = 0
    while i < n:
        # Last group may have padding
        var c0 = _b64_decode_char(raw[i])
        var c1 = _b64_decode_char(raw[i + 1])
        var is_last = (i + 4 == n)

        # Third char: '=' allowed only in last group
        var c2: UInt8
        if is_last and raw[i + 2] == 61:
            c2 = 0
        else:
            c2 = _b64_decode_char(raw[i + 2])

        # Fourth char: '=' allowed in last group when pad >= 1
        var c3: UInt8
        if is_last and raw[i + 3] == 61:
            c3 = 0
        else:
            c3 = _b64_decode_char(raw[i + 3])

        var b0 = (UInt8(c0) << 2) | (c1 >> 4)
        var b1 = (c1 << 4) | (c2 >> 2)
        var b2 = (c2 << 6) | c3

        out.append(b0)
        if not (is_last and pad >= 2):
            out.append(b1)
        if not (is_last and pad >= 1):
            out.append(b2)

        i += 4

    return out^
