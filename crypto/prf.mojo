# ============================================================================
# crypto/prf.mojo — TLS 1.2 Pseudorandom Function (RFC 5246 §5)
# ============================================================================
#
# P_hash(secret, seed, length):
#   A(0) = seed
#   A(i) = HMAC_H(secret, A(i-1))
#   output = HMAC_H(secret, A(1)||seed) || HMAC_H(secret, A(2)||seed) || ...
#   truncate to `length` bytes
#
# PRF(secret, label, seed, length) = P_SHA256(secret, label||seed, length)
#
# API:
#   p_hash_sha256(secret, seed, length) -> List[UInt8]
#   p_hash_sha384(secret, seed, length) -> List[UInt8]
#   prf_sha256(secret, label, seed, length) -> List[UInt8]
#   prf_sha384(secret, label, seed, length) -> List[UInt8]
#   tls12_master_secret(pre_master, client_random, server_random) -> List[UInt8]
#   tls12_key_block(master, server_random, client_random, length) -> List[UInt8]
#   tls12_verify_data(master, label, handshake_hash) -> List[UInt8]
# ============================================================================

from crypto.hmac import hmac_sha256, hmac_sha384


def _concat(a: List[UInt8], b: List[UInt8]) -> List[UInt8]:
    """Concatenate two byte lists."""
    var out = List[UInt8](capacity=len(a) + len(b))
    for i in range(len(a)):
        out.append(a[i])
    for i in range(len(b)):
        out.append(b[i])
    return out^


def p_hash_sha256(secret: List[UInt8], seed: List[UInt8], length: Int) -> List[UInt8]:
    """RFC 5246 §5 P_hash using HMAC-SHA-256.

    A(0) = seed
    A(i) = HMAC_SHA256(secret, A(i-1))
    output = HMAC(secret, A(1)||seed) || HMAC(secret, A(2)||seed) || ...
    """
    var result = List[UInt8](capacity=length + 32)
    var a = seed.copy()  # A(0) = seed
    while len(result) < length:
        a = hmac_sha256(secret, a)  # A(i) = HMAC(secret, A(i-1))
        var combined = _concat(a, seed)
        var block = hmac_sha256(secret, combined)
        for i in range(len(block)):
            result.append(block[i])
    # Truncate to exactly length bytes
    var out = List[UInt8](capacity=length)
    for i in range(length):
        out.append(result[i])
    return out^


def p_hash_sha384(secret: List[UInt8], seed: List[UInt8], length: Int) -> List[UInt8]:
    """RFC 5246 §5 P_hash using HMAC-SHA-384.

    A(0) = seed
    A(i) = HMAC_SHA384(secret, A(i-1))
    output = HMAC(secret, A(1)||seed) || HMAC(secret, A(2)||seed) || ...
    """
    var result = List[UInt8](capacity=length + 48)
    var a = seed.copy()  # A(0) = seed
    while len(result) < length:
        a = hmac_sha384(secret, a)  # A(i) = HMAC(secret, A(i-1))
        var combined = _concat(a, seed)
        var block = hmac_sha384(secret, combined)
        for i in range(len(block)):
            result.append(block[i])
    # Truncate to exactly length bytes
    var out = List[UInt8](capacity=length)
    for i in range(length):
        out.append(result[i])
    return out^


def prf_sha256(secret: List[UInt8], label: String, seed: List[UInt8], length: Int) -> List[UInt8]:
    """TLS 1.2 PRF using SHA-256: P_SHA256(secret, label || seed, length)."""
    var label_bytes_span = label.as_bytes()
    var label_bytes = List[UInt8](capacity=len(label_bytes_span))
    for i in range(len(label_bytes_span)):
        label_bytes.append(label_bytes_span[i])
    var combined_seed = _concat(label_bytes, seed)
    return p_hash_sha256(secret, combined_seed, length)


def prf_sha384(secret: List[UInt8], label: String, seed: List[UInt8], length: Int) -> List[UInt8]:
    """TLS 1.2 PRF using SHA-384: P_SHA384(secret, label || seed, length)."""
    var label_bytes_span = label.as_bytes()
    var label_bytes = List[UInt8](capacity=len(label_bytes_span))
    for i in range(len(label_bytes_span)):
        label_bytes.append(label_bytes_span[i])
    var combined_seed = _concat(label_bytes, seed)
    return p_hash_sha384(secret, combined_seed, length)


def tls12_master_secret(
    pre_master: List[UInt8],
    client_random: List[UInt8],
    server_random: List[UInt8],
) -> List[UInt8]:
    """Compute TLS 1.2 master secret (48 bytes).

    master_secret = PRF(pre_master, "master secret",
                        client_random || server_random, 48)
    """
    var randoms = _concat(client_random, server_random)
    return prf_sha256(pre_master, "master secret", randoms, 48)


def tls12_key_block(
    master: List[UInt8],
    server_random: List[UInt8],
    client_random: List[UInt8],
    length: Int,
) -> List[UInt8]:
    """Compute TLS 1.2 key block of given length.

    key_material = PRF(master, "key expansion",
                       server_random || client_random, length)
    """
    var randoms = _concat(server_random, client_random)
    return prf_sha256(master, "key expansion", randoms, length)


def tls12_key_block_sha384(
    master: List[UInt8],
    server_random: List[UInt8],
    client_random: List[UInt8],
    length: Int,
) -> List[UInt8]:
    """Compute TLS 1.2 key block using SHA-384 PRF (for _SHA384 cipher suites)."""
    var randoms = _concat(server_random, client_random)
    return prf_sha384(master, "key expansion", randoms, length)


def tls12_verify_data(
    master: List[UInt8],
    label: String,
    handshake_hash: List[UInt8],
) -> List[UInt8]:
    """Compute TLS 1.2 Finished verify_data (12 bytes).

    verify_data = PRF(master, label, handshake_hash, 12)
    label is "client finished" or "server finished"
    """
    return prf_sha256(master, label, handshake_hash, 12)


def tls12_verify_data_sha384(
    master: List[UInt8],
    label: String,
    handshake_hash: List[UInt8],
) -> List[UInt8]:
    """Compute TLS 1.2 Finished verify_data using SHA-384 PRF (12 bytes)."""
    return prf_sha384(master, label, handshake_hash, 12)
