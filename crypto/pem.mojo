# ============================================================================
# crypto/pem.mojo — PEM decoder (strips headers, base64-decodes body)
# ============================================================================
# API:
#   pem_decode(pem: String, label: String) raises -> List[List[UInt8]]
#       Finds all "-----BEGIN label-----" ... "-----END label-----" blocks,
#       strips headers, base64-decodes each block body.
#       Returns list of DER payloads (one element per certificate in a bundle).
# ============================================================================

from crypto.base64 import base64_decode


fn _str_to_bytes(s: String) -> List[UInt8]:
    """Copy String bytes into a List[UInt8]."""
    var span = s.as_bytes()
    var out = List[UInt8](capacity=len(span))
    for i in range(len(span)):
        out.append(span[i])
    return out^


fn pem_decode(pem: String, label: String) raises -> List[List[UInt8]]:
    """Decode all PEM blocks matching `label`. Returns list of DER payloads."""
    var begin_marker = "-----BEGIN " + label + "-----"
    var end_marker   = "-----END " + label + "-----"

    var result = List[List[UInt8]]()
    var pem_bytes = _str_to_bytes(pem)
    var begin_bytes = _str_to_bytes(begin_marker)
    var end_bytes = _str_to_bytes(end_marker)
    var n = len(pem_bytes)
    var pos = 0

    while pos < n:
        # Find begin marker
        var begin_pos = _find_substr(pem_bytes, begin_bytes, pos)
        if begin_pos < 0:
            break

        # Skip to end of begin marker line
        var after_begin = begin_pos + len(begin_bytes)
        # Skip '\n' (and optional '\r')
        while after_begin < n and (pem_bytes[after_begin] == 10 or pem_bytes[after_begin] == 13):
            after_begin += 1

        # Find end marker
        var end_pos = _find_substr(pem_bytes, end_bytes, after_begin)
        if end_pos < 0:
            raise Error("pem_decode: found BEGIN " + label + " but no matching END")

        # Extract body (between begin and end markers)
        var body_bytes = List[UInt8](capacity=end_pos - after_begin)
        for i in range(after_begin, end_pos):
            body_bytes.append(pem_bytes[i])

        # Strip whitespace (newlines, carriage returns, spaces) to get pure base64
        var b64_str = _strip_whitespace(body_bytes)

        # Base64 decode
        var der = base64_decode(b64_str)
        result.append(der^)

        pos = end_pos + len(end_bytes)

    if len(result) == 0:
        raise Error("pem_decode: no BEGIN " + label + " marker found")

    return result^


fn _find_substr(haystack: List[UInt8], needle: List[UInt8], start: Int) -> Int:
    """Find first occurrence of needle in haystack starting at start. Returns -1 if not found."""
    var h = len(haystack)
    var nlen = len(needle)
    if nlen == 0:
        return start
    var i = start
    while i <= h - nlen:
        var ok = True
        for j in range(nlen):
            if haystack[i + j] != needle[j]:
                ok = False
                break
        if ok:
            return i
        i += 1
    return -1


fn _strip_whitespace(data: List[UInt8]) -> String:
    """Remove whitespace (\\n, \\r, space, tab) from byte list, return as String."""
    var out = List[UInt8](capacity=len(data))
    for i in range(len(data)):
        var b = data[i]
        if b != 10 and b != 13 and b != 32 and b != 9:
            out.append(b)
    return String(unsafe_from_utf8=out^)
