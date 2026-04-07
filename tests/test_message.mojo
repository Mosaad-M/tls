# ============================================================================
# test_message.mojo — TLS 1.3 wire-format message builder/parser tests
# ============================================================================
# Test vectors generated with Python struct module.
#
# ClientHello:
#   client_random = bytes(range(32))   # 00..1f
#   session_id    = b''
#   key_share_pub = bytes(range(32,64)) # 20..3f
#   sni           = "example.com"
#   Expected hex: 010000840303...
#
# ServerHello:
#   server_random = bytes(range(32,64)) # 20..3f
#   session_id    = 32 bytes of 0xaa
#   cipher_suite  = 0x1301
#   server_pub    = bytes(range(64,96)) # 40..5f
#   Expected hex: 020000760303...
# ============================================================================

from tls.message import (
    build_client_hello, build_finished,
    parse_handshake_msg, parse_server_hello, parse_server_hello_key_share,
    parse_certificate_chain, parse_cert_verify, parse_finished,
    parse_alpn_from_ee,
    HandshakeMsg, ServerHello,
    HS_CLIENT_HELLO, HS_SERVER_HELLO, HS_FINISHED,
    CIPHER_TLS_AES_128_GCM_SHA256, CIPHER_TLS_AES_256_GCM_SHA384, CIPHER_TLS_CHACHA20_POLY1305_SHA256,
    EXT_SERVER_NAME, EXT_KEY_SHARE, EXT_ALPN,
)


def run_test(
    name: String,
    mut passed: Int,
    mut failed: Int,
    test_fn: def () raises -> None,
):
    try:
        test_fn()
        print("  PASS:", name)
        passed += 1
    except e:
        print("  FAIL:", name, "-", String(e))
        failed += 1


def hex_to_bytes(h: String) -> List[UInt8]:
    var raw = h.as_bytes()
    var n = len(raw) // 2
    var out = List[UInt8](capacity=n)
    for i in range(n):
        var hi = raw[i * 2]
        var lo = raw[i * 2 + 1]
        var h_val: UInt8 = (hi - 48) if hi <= 57 else (hi - 87)
        var l_val: UInt8 = (lo - 48) if lo <= 57 else (lo - 87)
        out.append((h_val << 4) | l_val)
    return out^


def bytes_eq(a: List[UInt8], b: List[UInt8]) -> Bool:
    if len(a) != len(b):
        return False
    for i in range(len(a)):
        if a[i] != b[i]:
            return False
    return True


def contains_u16(data: List[UInt8], val: UInt16) -> Bool:
    var hi = UInt8(val >> 8)
    var lo = UInt8(val & 0xFF)
    var i = 0
    while i + 1 < len(data):
        if data[i] == hi and data[i + 1] == lo:
            return True
        i += 1
    return False


def _slice_local(data: List[UInt8], start: Int, end: Int) -> List[UInt8]:
    var out = List[UInt8](capacity=end - start)
    for i in range(start, end):
        out.append(data[i])
    return out^


def extract_ch_extensions(ch: List[UInt8]) -> List[UInt8]:
    """Extract the extensions bytes from a ClientHello (assumes empty session_id).

    Layout: header(4) + version(2) + random(32) + sid_len(1) + sid(0)
            + cs_len(2) + cs(14) + comp_len(1) + comp(1) = 57 bytes fixed
            + extensions_total_len(2) at [57:59]
            + extensions at [59 : 59 + ext_total]
    """
    var ext_total = (Int(ch[57]) << 8) | Int(ch[58])
    return _slice_local(ch, 59, 59 + ext_total)


def find_ext_in_exts(exts: List[UInt8], target: UInt16) -> Tuple[Bool, Int, Int]:
    """Walk extension list, return (found, data_offset, data_len) for target type."""
    var off = 0
    while off + 4 <= len(exts):
        var ext_type = (UInt16(exts[off]) << 8) | UInt16(exts[off + 1])
        var ext_len  = (Int(exts[off + 2]) << 8) | Int(exts[off + 3])
        off += 4
        if ext_type == target:
            return (True, off, ext_len)
        off += ext_len
    return (False, 0, 0)


def make_random() -> List[UInt8]:
    var r = List[UInt8](capacity=32)
    for i in range(32):
        r.append(UInt8(i))
    return r^


def make_key_share() -> List[UInt8]:
    var k = List[UInt8](capacity=32)
    for i in range(32):
        k.append(UInt8(32 + i))
    return k^


# ── ClientHello tests ─────────────────────────────────────────────────────────

def test_ch_type_byte() raises:
    var ch = build_client_hello(make_random(), List[UInt8](), make_key_share(), "example.com")
    if ch[0] != 0x01:
        raise Error("expected type 0x01, got " + String(Int(ch[0])))


def test_ch_legacy_version() raises:
    var ch = build_client_hello(make_random(), List[UInt8](), make_key_share(), "example.com")
    # legacy_version is at offset 4..5 (after 4-byte header)
    if ch[4] != 0x03 or ch[5] != 0x03:
        raise Error("expected 0x0303 at [4:6], got " + String(Int(ch[4])) + " " + String(Int(ch[5])))


def test_ch_random() raises:
    var rand = make_random()
    var ch = build_client_hello(rand, List[UInt8](), make_key_share(), "example.com")
    # random is at offset 6..37
    for i in range(32):
        if ch[6 + i] != rand[i]:
            raise Error("random mismatch at byte " + String(i))


def test_ch_cipher_suites() raises:
    var ch = build_client_hello(make_random(), List[UInt8](), make_key_share(), "example.com")
    # Body starts at offset 4: legacy_version(2) + random(32) + sid_len(1) + sid(0) + cs_len(2) + cs
    # cipher suites start at offset 4+2+32+1+0+2=41
    if not contains_u16(ch, CIPHER_TLS_AES_128_GCM_SHA256):
        raise Error("cipher suite 0x1301 not found")
    if not contains_u16(ch, CIPHER_TLS_CHACHA20_POLY1305_SHA256):
        raise Error("cipher suite 0x1303 not found")
    # 0x1302 (AES-256-GCM-SHA384) now offered (SHA-384 key schedule supported)
    if not contains_u16(ch, CIPHER_TLS_AES_256_GCM_SHA384):
        raise Error("cipher suite 0x1302 not found")


def test_ch_sni() raises:
    var ch = build_client_hello(make_random(), List[UInt8](), make_key_share(), "example.com")
    # SNI extension type = 0x0000; check the hostname bytes are present
    var sni_bytes = "example.com".as_bytes()
    var found = False
    var i = 0
    while i + len(sni_bytes) <= len(ch):
        var ok = True
        for j in range(len(sni_bytes)):
            if ch[i + j] != sni_bytes[j]:
                ok = False
                break
        if ok:
            found = True
            break
        i += 1
    if not found:
        raise Error("SNI hostname bytes not found in ClientHello")


def test_ch_key_share() raises:
    var ks = make_key_share()
    var ch = build_client_hello(make_random(), List[UInt8](), ks, "example.com")
    var found = False
    var i = 0
    while i + 32 <= len(ch):
        var ok = True
        for j in range(32):
            if ch[i + j] != ks[j]:
                ok = False
                break
        if ok:
            found = True
            break
        i += 1
    if not found:
        raise Error("key_share_pub bytes not found in ClientHello")


# ── parse_handshake_msg ────────────────────────────────────────────────────────

def test_parse_handshake_msg() raises:
    var ch = build_client_hello(make_random(), List[UInt8](), make_key_share(), "test.com")
    var result = parse_handshake_msg(ch, 0)
    var msg = result[0].copy()
    if msg.msg_type != HS_CLIENT_HELLO:
        raise Error("expected type 0x01, got " + String(Int(msg.msg_type)))
    # Body length should equal len(ch) - 4
    if len(msg.body) != len(ch) - 4:
        raise Error("body length mismatch: " + String(len(msg.body)) + " vs " + String(len(ch) - 4))


# ── parse_server_hello ────────────────────────────────────────────────────────

def test_parse_server_hello() raises:
    # ServerHello hex from Python: server_random=bytes(32..63), session_id=32xaa, cipher=0x1301, pub=bytes(64..95)
    var sh_bytes = hex_to_bytes("020000760303202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f20aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa130100002e00330024001d0020404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f002b00020304")
    var result = parse_handshake_msg(sh_bytes, 0)
    var msg = result[0].copy()
    if msg.msg_type != HS_SERVER_HELLO:
        raise Error("expected ServerHello type 0x02, got " + String(Int(msg.msg_type)))
    var sh = parse_server_hello(msg.body)
    if sh.cipher_suite != 0x1301:
        raise Error("expected cipher 0x1301, got " + String(Int(sh.cipher_suite)))
    # Check random matches bytes(32..63)
    for i in range(32):
        if sh.random[i] != UInt8(32 + i):
            raise Error("random mismatch at " + String(i))


# ── parse_certificate_chain ───────────────────────────────────────────────────

def test_parse_certificate_chain() raises:
    # Certificate message from Python: 2 certs of 20 bytes each
    var cert_msg = hex_to_bytes("0b00003600000032000014000102030405060708090a0b0c0d0e0f1011121300000000141415161718191a1b1c1d1e1f20212223242526270000")
    var result = parse_handshake_msg(cert_msg, 0)
    var msg = result[0].copy()
    if msg.msg_type != 0x0B:
        raise Error("expected Certificate type 0x0B, got " + String(Int(msg.msg_type)))
    var certs = parse_certificate_chain(msg.body)
    if len(certs) != 2:
        raise Error("expected 2 certs, got " + String(len(certs)))
    # cert1 = bytes(0..19)
    for i in range(20):
        if certs[0][i] != UInt8(i):
            raise Error("cert0[" + String(i) + "] mismatch")
    # cert2 = bytes(20..39)
    for i in range(20):
        if certs[1][i] != UInt8(20 + i):
            raise Error("cert1[" + String(i) + "] mismatch")


# ── parse_cert_verify ─────────────────────────────────────────────────────────

def test_parse_cert_verify() raises:
    # CertVerify from Python: scheme=0x0403, sig=bytes(0..63)
    var cv_bytes = hex_to_bytes("0f00004404030040000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f")
    var result = parse_handshake_msg(cv_bytes, 0)
    var msg = result[0].copy()
    if msg.msg_type != 0x0F:
        raise Error("expected CertificateVerify type 0x0F")
    var cv_result = parse_cert_verify(msg.body)
    var scheme = cv_result[0]
    var sig = cv_result[1].copy()
    if scheme != 0x0403:
        raise Error("expected scheme 0x0403, got " + String(Int(scheme)))
    if len(sig) != 64:
        raise Error("expected 64-byte sig, got " + String(len(sig)))
    for i in range(64):
        if sig[i] != UInt8(i):
            raise Error("sig[" + String(i) + "] mismatch")


# ── parse_finished + build_finished ──────────────────────────────────────────

def test_parse_finished() raises:
    # Finished from Python: verify_data=bytes(0..31)
    var fin_bytes = hex_to_bytes("14000020000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
    var result = parse_handshake_msg(fin_bytes, 0)
    var msg = result[0].copy()
    if msg.msg_type != HS_FINISHED:
        raise Error("expected Finished type 0x14")
    var vd = parse_finished(msg.body)
    if len(vd) != 32:
        raise Error("expected 32-byte verify_data")
    for i in range(32):
        if vd[i] != UInt8(i):
            raise Error("verify_data[" + String(i) + "] mismatch")


def test_build_finished() raises:
    var vd = List[UInt8](capacity=32)
    for i in range(32):
        vd.append(UInt8(i))
    var fin = build_finished(vd)
    if len(fin) != 36:
        raise Error("expected 36 bytes, got " + String(len(fin)))
    if fin[0] != 0x14:
        raise Error("expected type 0x14, got " + String(Int(fin[0])))
    # 3-byte length = 0x000020 = 32
    if fin[1] != 0x00 or fin[2] != 0x00 or fin[3] != 0x20:
        raise Error("expected length 000020")
    for i in range(32):
        if fin[4 + i] != UInt8(i):
            raise Error("verify_data[" + String(i) + "] mismatch in built Finished")


# ── ALPN extension builder tests ─────────────────────────────────────────────

def test_build_ch_no_alpn_no_ext() raises:
    # With empty protocols list, EXT_ALPN must NOT appear as an extension type
    var ch = build_client_hello(make_random(), List[UInt8](), make_key_share(), "example.com", List[String]())
    var exts = extract_ch_extensions(ch)
    var result = find_ext_in_exts(exts, EXT_ALPN)
    if result[0]:
        raise Error("EXT_ALPN (0x0010) found in extensions when no protocols given")


def test_build_ch_alpn_h2_present() raises:
    # protocols=["h2"] → ALPN extension type 0x0010 must appear with "h2" protocol
    var protocols = List[String]()
    protocols.append("h2")
    var ch = build_client_hello(make_random(), List[UInt8](), make_key_share(), "example.com", protocols)
    var exts = extract_ch_extensions(ch)
    var result = find_ext_in_exts(exts, EXT_ALPN)
    if not result[0]:
        raise Error("EXT_ALPN (0x0010) not found in extensions with protocols=['h2']")
    var data_off = result[1]
    var data_len = result[2]
    # ext_data: 2-byte ProtocolList len + protocol entries
    # ProtocolList len should be 3 (02 68 32)
    if data_len < 5:
        raise Error("ALPN ext data too short: " + String(data_len))
    var pl_len = (Int(exts[data_off]) << 8) | Int(exts[data_off + 1])
    if pl_len != 3:
        raise Error("expected ProtocolList len 3 for ['h2'], got " + String(pl_len))
    # First entry: len=2, 'h', '2'
    if exts[data_off + 2] != 2 or exts[data_off + 3] != 0x68 or exts[data_off + 4] != 0x32:
        raise Error("ALPN 'h2' bytes not correctly encoded")


def test_build_ch_alpn_multi_lengths() raises:
    # protocols=["h2","http/1.1"]
    # ProtocolList = 02 68 32 (3) + 08 68 74 74 70 2f 31 2e 31 (9) = 12 bytes
    # ext data = 00 0c (2 bytes) + 12 bytes = 14 bytes total
    var protocols = List[String]()
    protocols.append("h2")
    protocols.append("http/1.1")
    var ch = build_client_hello(make_random(), List[UInt8](), make_key_share(), "example.com", protocols)
    var exts = extract_ch_extensions(ch)
    var result = find_ext_in_exts(exts, EXT_ALPN)
    if not result[0]:
        raise Error("EXT_ALPN not found")
    var data_off = result[1]
    var data_len = result[2]
    # ext data length = 2 (ProtocolList len field) + 12 (protocol bytes) = 14
    if data_len != 14:
        raise Error("expected ext data length 14 for ['h2','http/1.1'], got " + String(data_len))
    # ProtocolList length at data_off should be 12
    var pl_len = (Int(exts[data_off]) << 8) | Int(exts[data_off + 1])
    if pl_len != 12:
        raise Error("expected ProtocolList length 12, got " + String(pl_len))


# ── parse_alpn_from_ee tests ──────────────────────────────────────────────────

def test_parse_alpn_from_ee_http11() raises:
    # EE body with ALPN ext containing "http/1.1"
    # "http/1.1" entry: 08 68 74 74 70 2f 31 2e 31 (9 bytes)
    # ProtocolList length: 00 09
    # ext data: 00 0b (11 bytes)
    # ALPN ext: 00 10 00 0b 00 09 08 68 74 74 70 2f 31 2e 31 (15 bytes)
    # extensions_total_length: 00 0f
    var body = hex_to_bytes("000f" + "0010" + "000b" + "0009" + "0868747470" + "2f312e31")
    var proto = parse_alpn_from_ee(body)
    if proto != "http/1.1":
        raise Error("expected 'http/1.1', got '" + proto + "'")


def test_parse_alpn_from_ee_h2() raises:
    # EE body with ALPN ext containing "h2"
    # "h2" entry: 02 68 32 (3 bytes)
    # ProtocolList length: 00 03
    # ext data: 00 05 (5 bytes)
    # ALPN ext: 00 10 00 05 00 03 02 68 32 (9 bytes)
    # extensions_total_length: 00 09
    var body = hex_to_bytes("0009" + "0010" + "0005" + "0003" + "026832")
    var proto = parse_alpn_from_ee(body)
    if proto != "h2":
        raise Error("expected 'h2', got '" + proto + "'")


def test_parse_alpn_from_ee_absent() raises:
    # EE body with supported_groups (0x000a) only, no ALPN
    # ext: 00 0a 00 00 (4 bytes)
    # extensions_total_length: 00 04
    var body = hex_to_bytes("0004" + "000a" + "0000")
    var proto = parse_alpn_from_ee(body)
    if proto != "":
        raise Error("expected empty string when ALPN absent, got '" + proto + "'")


def test_parse_alpn_from_ee_empty_body() raises:
    # Empty EncryptedExtensions (no extensions at all)
    var body = hex_to_bytes("0000")
    var proto = parse_alpn_from_ee(body)
    if proto != "":
        raise Error("expected empty string for empty EE body, got '" + proto + "'")


def main() raises:
    var passed = 0
    var failed = 0

    print("=== TLS Message Tests ===")
    print()

    run_test("build_client_hello type byte = 0x01", passed, failed, test_ch_type_byte)
    run_test("build_client_hello legacy_version = 0x0303", passed, failed, test_ch_legacy_version)
    run_test("build_client_hello random at [6:38]", passed, failed, test_ch_random)
    run_test("build_client_hello cipher suites: 1301+1302+1303 all offered", passed, failed, test_ch_cipher_suites)
    run_test("build_client_hello SNI extension contains hostname", passed, failed, test_ch_sni)
    run_test("build_client_hello key_share contains pub key", passed, failed, test_ch_key_share)
    run_test("parse_handshake_msg: correct type + body", passed, failed, test_parse_handshake_msg)
    run_test("parse_server_hello: cipher_suite + random", passed, failed, test_parse_server_hello)
    run_test("parse_certificate_chain: 2 DER blobs", passed, failed, test_parse_certificate_chain)
    run_test("parse_cert_verify: scheme + sig", passed, failed, test_parse_cert_verify)
    run_test("parse_finished: 32-byte verify_data", passed, failed, test_parse_finished)
    run_test("build_finished: correct 4-byte header + body", passed, failed, test_build_finished)
    run_test("build_client_hello: no ALPN ext when protocols empty", passed, failed, test_build_ch_no_alpn_no_ext)
    run_test("build_client_hello: ALPN ext present with ['h2']", passed, failed, test_build_ch_alpn_h2_present)
    run_test("build_client_hello: ALPN ['h2','http/1.1'] lengths correct", passed, failed, test_build_ch_alpn_multi_lengths)
    run_test("parse_alpn_from_ee: 'http/1.1' returned", passed, failed, test_parse_alpn_from_ee_http11)
    run_test("parse_alpn_from_ee: 'h2' returned", passed, failed, test_parse_alpn_from_ee_h2)
    run_test("parse_alpn_from_ee: absent -> empty string", passed, failed, test_parse_alpn_from_ee_absent)
    run_test("parse_alpn_from_ee: empty EE body -> empty string", passed, failed, test_parse_alpn_from_ee_empty_body)

    print()
    print("Results:", passed, "passed,", failed, "failed")
    if failed > 0:
        raise Error(String(failed) + " test(s) failed")
