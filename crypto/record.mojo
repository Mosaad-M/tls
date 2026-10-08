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

from crypto.gcm import gcm_encrypt, gcm_decrypt, GcmKey
from crypto.poly1305 import chacha20_poly1305_seal_into, chacha20_poly1305_open_into
from std.ffi import external_call


# Byte copies with memcpy (records are up to 16 KiB; byte loops were a
# large part of the per-record cost once AES-GCM ran in hardware)
def _put(mut out: List[UInt8], src: List[UInt8], start: Int, n: Int):
    """Append src[start:start+n] to out."""
    if n <= 0:
        return
    var have = len(out)
    if have + n > out.capacity():
        out.reserve(max(have + n, out.capacity() * 2))
    out.resize(unsafe_uninit_length=have + n)
    _ = external_call["memcpy", Int](Int(out.unsafe_ptr()) + have, Int(src.unsafe_ptr()) + start, n)


def _slice(src: List[UInt8], start: Int, n: Int) -> List[UInt8]:
    var out = List[UInt8](capacity=n)
    _put(out, src, start, n)
    return out^


def _at(addr: Int, n: Int) -> List[UInt8]:
    """Copy n bytes at addr into a new list."""
    var out = List[UInt8](unsafe_uninit_length=n)
    if n > 0:
        _ = external_call["memcpy", Int](Int(out.unsafe_ptr()), addr, n)
    return out^


def _grow(mut out: List[UInt8], n: Int) -> Int:
    """Extend out by n uninitialized bytes; return their address."""
    var have = len(out)
    if have + n > out.capacity():
        out.reserve(max(have + n, out.capacity() * 2))
    out.resize(unsafe_uninit_length=have + n)
    return Int(out.unsafe_ptr()) + have


def _is_gcm(cipher: UInt8) -> Bool:
    return cipher == CIPHER_AES_128_GCM or cipher == CIPHER_AES_256_GCM


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
# AeadKey — a record key prepared once (AES-GCM key schedule and GHASH key)
# ============================================================================

struct AeadKey(Movable):
    """Caches the prepared AES-GCM key for one direction of a connection.

    TLS keys stay the same for many records, but preparing a bitsliced AES
    key schedule and the GHASH key costs more than sealing a small record.
    ensure() rebuilds only when the cipher or key bytes change, so new
    handshake keys and KeyUpdate are picked up automatically. ChaCha20 has
    no per-key setup worth caching.
    """
    var cipher: UInt8
    var key: List[UInt8]
    var _gcm: List[GcmKey]   # zero or one prepared key

    def __init__(out self):
        self.cipher = 255
        self.key = List[UInt8]()
        self._gcm = List[GcmKey]()

    def __moveinit__(out self, deinit take: Self):
        self.cipher = take.cipher
        self.key = take.key^
        self._gcm = take._gcm^

    def _ensure(mut self, cipher: UInt8, key: List[UInt8]) raises:
        var same = self.cipher == cipher and len(self.key) == len(key) and len(self._gcm) == 1
        if same:
            for i in range(len(key)):
                if self.key[i] != key[i]:
                    same = False
                    break
        if not same:
            self._gcm.clear()
            self._gcm.append(GcmKey(key))
            self.cipher = cipher
            self.key = key.copy()

    def gcm_seal(mut self, cipher: UInt8, key: List[UInt8], nonce: List[UInt8], pt: List[UInt8], aad: List[UInt8]) raises -> Tuple[List[UInt8], List[UInt8]]:
        self._ensure(cipher, key)
        return self._gcm[0].seal(nonce, pt, aad)

    def gcm_open(mut self, cipher: UInt8, key: List[UInt8], nonce: List[UInt8], ct: List[UInt8], tag: List[UInt8], aad: List[UInt8]) raises -> List[UInt8]:
        self._ensure(cipher, key)
        return self._gcm[0].open(nonce, ct, tag, aad)

    def seal_into(
        mut self, cipher: UInt8, key: List[UInt8], nonce: List[UInt8],
        aad_addr: Int, aad_len: Int, src: Int, dst: Int, n: Int,
    ) raises:
        """Encrypt n bytes at src into dst (may equal src); the 16-byte tag
        goes to dst + n. Any cipher."""
        if _is_gcm(cipher):
            self._ensure(cipher, key)
            self._gcm[0].seal_into(nonce, aad_addr, aad_len, src, dst, n)
        else:
            var t = chacha20_poly1305_seal_into(key, nonce, aad_addr, aad_len, src, dst, n)
            Pointer[UInt8, MutAnyOrigin](unsafe_from_address=dst + n).unsafe_store(0, t)

    def open_into(
        mut self, cipher: UInt8, key: List[UInt8], nonce: List[UInt8],
        aad_addr: Int, aad_len: Int, src: Int, dst: Int, n: Int, tag_addr: Int,
    ) raises -> Bool:
        """Decrypt n bytes at src into dst (may equal src) and check the tag
        at tag_addr. Any cipher. False on a mismatch; dst then holds no
        plaintext."""
        if _is_gcm(cipher):
            self._ensure(cipher, key)
            return self._gcm[0].open_into(nonce, aad_addr, aad_len, src, dst, n, tag_addr)
        return chacha20_poly1305_open_into(key, nonce, aad_addr, aad_len, src, dst, n, tag_addr)


# ============================================================================
# record_seal — encrypt and authenticate a TLS 1.3 record
# ============================================================================

def record_seal_k(
    mut ak:       AeadKey,
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

    # Inner plaintext = plaintext || content_type (TLS 1.3 §5.2), written
    # after the header and encrypted in place; the tag follows it
    var n = len(plaintext) + 1
    var aad = _make_aad(n)
    var record = List[UInt8](capacity=5 + n + 16)
    _put(record, aad, 0, 5)
    _put(record, plaintext, 0, len(plaintext))
    record.append(content_type)
    _ = _grow(record, 16)
    var base = Int(record.unsafe_ptr())
    ak.seal_into(cipher, key, _make_nonce(iv, seqno), base, 5, base + 5, base + 5, n)
    return record^


# ============================================================================
# record_open — decrypt and verify a TLS 1.3 record
# ============================================================================

def record_open_into(
    mut ak:   AeadKey,
    cipher:   UInt8,
    key:      List[UInt8],
    iv:       List[UInt8],
    seqno:    UInt64,
    rec_addr: Int,
    rec_len:  Int,
    mut out:  List[UInt8],
) raises -> UInt8:
    """AEAD-decrypt the TLS 1.3 record (header included) at rec_addr and
    append its plaintext to out, decrypting directly into out's storage.
    Returns the inner content type. Raises on any failure, leaving out as
    it was: plaintext of a record that fails authentication is never
    visible."""
    if len(iv) != 12:
        raise Error("record_open: IV must be 12 bytes")
    # Minimum: 5-byte header + 1-byte inner (ctype) + 16-byte tag = 22 bytes
    if rec_len < 22:
        raise Error("record_open: record too short")
    var rec = Pointer[UInt8, MutAnyOrigin](unsafe_from_address=rec_addr)
    if rec[unsafe_offset=0] != 0x17:
        raise Error("record_open: opaque_type must be 0x17")
    if rec[unsafe_offset=1] != 0x03 or rec[unsafe_offset=2] != 0x03:
        raise Error("record_open: legacy version must be 0x0303")
    var ct_len = rec_len - 5 - 16
    # TLSInnerPlaintext may not exceed 2^14 + 1 bytes (RFC 8446 §5.4)
    if ct_len > 16385:
        raise Error("record_open: inner plaintext too long (record_overflow)")

    # AAD = the record header (first 5 bytes)
    var base = len(out)
    var ok: Bool
    try:
        var dst = _grow(out, ct_len)
        ok = ak.open_into(
            cipher, key, _make_nonce(iv, seqno),
            rec_addr, 5, rec_addr + 5, dst, ct_len, rec_addr + 5 + ct_len,
        )
    except e:
        out.resize(unsafe_uninit_length=base)
        raise Error(String(e))
    if not ok:
        out.resize(unsafe_uninit_length=base)
        raise Error("authentication failed")

    # Inner = actual_plaintext || content_type || zeros (RFC 8446 §5.4): the
    # content type is the last non-zero byte.
    var ct_pos = len(out) - 1
    while ct_pos >= base and out[ct_pos] == 0:
        ct_pos -= 1
    if ct_pos < base:
        out.resize(unsafe_uninit_length=base)
        raise Error("record_open: no content type in inner plaintext (unexpected_message)")
    var content_type = out[ct_pos]
    out.resize(unsafe_uninit_length=ct_pos)  # drop type byte and padding in place
    return content_type


def record_open_k(
    mut ak: AeadKey,
    cipher: UInt8,
    key:    List[UInt8],
    iv:     List[UInt8],
    seqno:  UInt64,
    record: List[UInt8],
) raises -> Tuple[UInt8, List[UInt8]]:
    """AEAD-decrypt a TLS 1.3 record. Returns (content_type, plaintext). Raises on auth failure."""
    var inner = List[UInt8](capacity=max(len(record) - 21, 0))
    var content_type = record_open_into(
        ak, cipher, key, iv, seqno, Int(record.unsafe_ptr()), len(record), inner
    )
    return (content_type, inner^)


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


def _seal_12(
    mut ak: AeadKey, cipher: UInt8, key: List[UInt8], iv_implicit: List[UInt8],
    seqno: UInt64, content_type: UInt8, plaintext: List[UInt8], with_header: Bool,
) raises -> List[UInt8]:
    """[header(5) ||] explicit_nonce(8) || ciphertext || tag(16), sealed in
    place in one list."""
    if len(iv_implicit) != 4:
        raise Error("record_seal_12: iv_implicit must be 4 bytes")

    if not _is_gcm(cipher):
        raise Error("record_seal_12: only AES-GCM supported")

    var n = len(plaintext)
    var aad = _make_aad_12(seqno, content_type, n)
    var hdr = 5 if with_header else 0
    var out = List[UInt8](capacity=hdr + 8 + n + 16)
    if with_header:
        var body = 8 + n + 16
        out.append(content_type)
        out.append(0x03)
        out.append(0x03)
        out.append(UInt8((body >> 8) & 0xFF))
        out.append(UInt8(body & 0xFF))
    var explicit_nonce = _make_explicit_nonce(seqno)
    _put(out, explicit_nonce, 0, 8)
    _put(out, plaintext, 0, n)
    _ = _grow(out, 16)
    var base = Int(out.unsafe_ptr()) + hdr
    ak.seal_into(cipher, key, _make_nonce_12(iv_implicit, seqno), Int(aad.unsafe_ptr()), 13, base + 8, base + 8, n)
    _ = len(aad)  # aad is read through its address: keep it alive until here
    return out^


def record_seal_12_k(
    mut ak:      AeadKey,
    cipher:      UInt8,
    key:         List[UInt8],
    iv_implicit: List[UInt8],   # 4-byte implicit IV from key_block
    seqno:       UInt64,
    content_type: UInt8,
    plaintext:   List[UInt8],
) raises -> List[UInt8]:
    """AEAD-encrypt a TLS 1.2 record.

    Returns: explicit_nonce(8) || ciphertext || tag(16)
    The TLS record header is NOT included — record_seal_12_record_k adds it.
    """
    return _seal_12(ak, cipher, key, iv_implicit, seqno, content_type, plaintext, False)


def record_seal_12_record_k(
    mut ak:      AeadKey,
    cipher:      UInt8,
    key:         List[UInt8],
    iv_implicit: List[UInt8],   # 4-byte implicit IV from key_block
    seqno:       UInt64,
    content_type: UInt8,
    plaintext:   List[UInt8],
) raises -> List[UInt8]:
    """AEAD-encrypt a whole TLS 1.2 record, ready to write:
    header(5) || explicit_nonce(8) || ciphertext || tag(16)."""
    return _seal_12(ak, cipher, key, iv_implicit, seqno, content_type, plaintext, True)


def record_open_12_into(
    mut ak:      AeadKey,
    cipher:      UInt8,
    key:         List[UInt8],
    iv_implicit: List[UInt8],   # 4-byte implicit IV from key_block
    seqno:       UInt64,
    content_type: UInt8,
    payload_addr: Int,          # explicit_nonce(8) || ciphertext || tag(16)
    payload_len: Int,
    mut out:     List[UInt8],
) raises:
    """AEAD-decrypt a TLS 1.2 record payload, appending the plaintext to out
    (decrypted directly into out's storage). Raises on any failure, leaving
    out as it was."""
    if len(iv_implicit) != 4:
        raise Error("record_open_12: iv_implicit must be 4 bytes")
    if payload_len < 8 + 16:
        raise Error("record_open_12: payload too short (need at least 24 bytes)")
    if not _is_gcm(cipher):
        raise Error("record_open_12: only AES-GCM supported")

    # Full 12-byte nonce = implicit IV || explicit nonce (from the wire)
    var nonce = List[UInt8](capacity=12)
    _put(nonce, iv_implicit, 0, 4)
    var explicit_nonce = _at(payload_addr, 8)
    _put(nonce, explicit_nonce, 0, 8)

    var ct_len = payload_len - 8 - 16
    var aad = _make_aad_12(seqno, content_type, ct_len)
    var base = len(out)
    var ok: Bool
    try:
        var dst = _grow(out, ct_len)
        ok = ak.open_into(
            cipher, key, nonce, Int(aad.unsafe_ptr()), 13,
            payload_addr + 8, dst, ct_len, payload_addr + 8 + ct_len,
        )
    except e:
        out.resize(unsafe_uninit_length=base)
        raise Error(String(e))
    _ = len(aad)  # aad is read through its address: keep it alive until here
    if not ok:
        out.resize(unsafe_uninit_length=base)
        raise Error("authentication failed")


def record_open_12_k(
    mut ak:      AeadKey,
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
    var out = List[UInt8](capacity=max(len(payload) - 24, 0))
    record_open_12_into(
        ak, cipher, key, iv_implicit, seqno, content_type,
        Int(payload.unsafe_ptr()), len(payload), out,
    )
    return out^


# ============================================================================
# One-off variants (prepare the key per call; for handshake records and tests)
# ============================================================================

def record_seal(
    cipher: UInt8, key: List[UInt8], iv: List[UInt8], seqno: UInt64,
    content_type: UInt8, plaintext: List[UInt8],
) raises -> List[UInt8]:
    var ak = AeadKey()
    return record_seal_k(ak, cipher, key, iv, seqno, content_type, plaintext)


def record_open(
    cipher: UInt8, key: List[UInt8], iv: List[UInt8], seqno: UInt64, record: List[UInt8],
) raises -> Tuple[UInt8, List[UInt8]]:
    var ak = AeadKey()
    return record_open_k(ak, cipher, key, iv, seqno, record)


def record_seal_12(
    cipher: UInt8, key: List[UInt8], iv_implicit: List[UInt8], seqno: UInt64,
    content_type: UInt8, plaintext: List[UInt8],
) raises -> List[UInt8]:
    var ak = AeadKey()
    return record_seal_12_k(ak, cipher, key, iv_implicit, seqno, content_type, plaintext)


def record_open_12(
    cipher: UInt8, key: List[UInt8], iv_implicit: List[UInt8], seqno: UInt64,
    content_type: UInt8, payload: List[UInt8],
) raises -> List[UInt8]:
    var ak = AeadKey()
    return record_open_12_k(ak, cipher, key, iv_implicit, seqno, content_type, payload)
