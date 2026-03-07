# ============================================================================
# crypto/hmac.mojo — HMAC-SHA256 and HMAC-SHA384 (RFC 2104)
# ============================================================================
#
# HMAC(K, m) = H((K' XOR opad) || H((K' XOR ipad) || m))
#   K'    = H(K) if len(K) > block_size, else K padded with 0x00 to block_size
#   ipad  = 0x36 * block_size
#   opad  = 0x5c * block_size
#
# Security: hmac_equal uses constant-time OR-accumulation to prevent
#           timing attacks on MAC verification.
# ============================================================================

from crypto.hash import sha256, sha384, SHA256, SHA384


fn hmac_sha256(key: List[UInt8], data: List[UInt8]) -> List[UInt8]:
    """Compute HMAC-SHA256. Block size = 64 bytes, digest = 32 bytes."""
    var block_size = 64

    # Step 1: derive key' — hash if longer than block, then zero-pad
    var kp = List[UInt8](capacity=block_size)
    if len(key) > block_size:
        var hk = sha256(key)
        for i in range(len(hk)):
            kp.append(hk[i])
    else:
        for i in range(len(key)):
            kp.append(key[i])
    while len(kp) < block_size:
        kp.append(0x00)

    # Step 2: inner hash — H((K' XOR ipad) || message)
    var inner = SHA256()
    var iblock = List[UInt8](capacity=block_size)
    for i in range(block_size):
        iblock.append(kp[i] ^ 0x36)
    inner.update(iblock)
    inner.update(data)
    var inner_hash = inner.finalize()

    # Step 3: outer hash — H((K' XOR opad) || inner_hash)
    var outer = SHA256()
    var oblock = List[UInt8](capacity=block_size)
    for i in range(block_size):
        oblock.append(kp[i] ^ 0x5C)
    outer.update(oblock)
    outer.update(inner_hash)
    return outer.finalize()


fn hmac_sha384(key: List[UInt8], data: List[UInt8]) -> List[UInt8]:
    """Compute HMAC-SHA384. Block size = 128 bytes, digest = 48 bytes."""
    var block_size = 128

    # Step 1: derive key'
    var kp = List[UInt8](capacity=block_size)
    if len(key) > block_size:
        var hk = sha384(key)
        for i in range(len(hk)):
            kp.append(hk[i])
    else:
        for i in range(len(key)):
            kp.append(key[i])
    while len(kp) < block_size:
        kp.append(0x00)

    # Step 2: inner hash
    var inner = SHA384()
    var iblock = List[UInt8](capacity=block_size)
    for i in range(block_size):
        iblock.append(kp[i] ^ 0x36)
    inner.update(iblock)
    inner.update(data)
    var inner_hash = inner.finalize()

    # Step 3: outer hash
    var outer = SHA384()
    var oblock = List[UInt8](capacity=block_size)
    for i in range(block_size):
        oblock.append(kp[i] ^ 0x5C)
    outer.update(oblock)
    outer.update(inner_hash)
    return outer.finalize()


fn hmac_equal(a: List[UInt8], b: List[UInt8]) -> Bool:
    """Constant-time comparison of two byte sequences.

    Uses OR-accumulation so that comparison time is independent of
    the position of the first mismatch.  Prevents timing side-channels
    on HMAC/AEAD tag verification.

    Returns False immediately if lengths differ (length is not secret).
    """
    if len(a) != len(b):
        return False
    var diff: UInt8 = 0
    for i in range(len(a)):
        diff |= a[i] ^ b[i]
    return diff == 0
