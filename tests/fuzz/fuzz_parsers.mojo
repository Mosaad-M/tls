# ============================================================================
# fuzz_parsers.mojo — deterministic mutation fuzzer for every parser that
# sees attacker-controlled bytes
# ============================================================================
# Usage: fuzz_parsers <target|all> <seed> <iterations> [current-input path]
#        fuzz_parsers list                   (one target name per line)
#        fuzz_parsers replay <target> <file> (run one saved input)
#
# Each target starts from valid seed inputs and applies random mutations
# (bit flips, interesting bytes, insertions, deletions, truncation, length
# fields set to small or huge values, splices). Parsers may raise; that is
# expected. An out-of-bounds read aborts the process (Mojo List bounds
# checks), and that is the bug this hunts. Before each call the input is
# written to the current-input file, so tests/fuzz/run_fuzz.sh can keep the
# input that crashed; `run_fuzz.sh replay` (in `pixi run test`) feeds every
# saved crasher back through replay mode.
# ============================================================================

from std.ffi import external_call
from std.memory import alloc
from std.sys import argv
from crypto.cert import cert_parse, cert_chain_verify, cert_hostname_match, parse_ip_literal, X509Cert
from crypto.asn1 import (
    asn1_parse_ec_spki, asn1_parse_rsa_spki, asn1_parse_ecdsa_sig, asn1_parse_ecdsa_sig_48,
)
from tls.message import (
    parse_hello_retry_request, validate_encrypted_extensions, parse_certificate_chain,
    parse_certificate_request13, parse_cert_verify, parse_new_session_ticket,
)
from tls.message12 import (
    parse_server_hello_version, parse_server_hello_tls12_exts, parse_server_key_exchange,
    parse_certificate_request12, parse_finished_body,
)
from tls.connection import tls_handle_incoming_alert, HandshakeReader
from tls.socket import TlsSocket
from path_fixtures import ROOT, INTER, LEAF_OK, LEAF_IPSAN, INTER_NCD, RSA2048_LEAF
from sha512_fixtures import PSS_LEAF, EC384_LEAF


def targets() -> List[String]:
    return [
        "cert", "spki", "ecdsa_sig", "server_hello", "hrr", "ee", "certmsg",
        "certreq13", "cert_verify", "nst", "ske", "certreq12", "finished12",
        "alert", "ip", "post_handshake", "hs_reader",
    ]


# ── PRNG and mutations ──────────────────────────────────────────────────────

struct Rng(Movable):
    var s: UInt64

    def __init__(out self, seed: UInt64):
        self.s = seed * 0x9E3779B97F4A7C15 + 0x2545F4914F6CDD1D
        if self.s == 0:
            self.s = 1

    def next(mut self) -> UInt64:
        var x = self.s
        x ^= x << 13
        x ^= x >> 7
        x ^= x << 17
        self.s = x
        return x

    def below(mut self, n: Int) -> Int:
        if n <= 0:
            return 0
        return Int(self.next() % UInt64(n))


def mutate(seed: List[UInt8], other: List[UInt8], mut rng: Rng) -> List[UInt8]:
    var b = seed.copy()
    var rounds = 1 + rng.below(4)
    for _ in range(rounds):
        var op = rng.below(9)
        var n = len(b)
        if op == 0 and n > 0:                       # flip a bit
            var i = rng.below(n)
            b[i] ^= UInt8(1) << UInt8(rng.below(8))
        elif op == 1 and n > 0:                     # interesting byte
            var vals: List[UInt8] = [0x00, 0x01, 0x7F, 0x80, 0xFF, 0x20, 0x81, 0x82]
            b[rng.below(n)] = vals[rng.below(len(vals))]
        elif op == 2:                               # insert random bytes
            var at = rng.below(n + 1)
            var k = 1 + rng.below(8)
            var out = List[UInt8]()
            for i in range(at):
                out.append(b[i])
            for _ in range(k):
                out.append(UInt8(rng.next() & 0xFF))
            for i in range(at, n):
                out.append(b[i])
            b = out^
        elif op == 3 and n > 0:                     # delete a run
            var at = rng.below(n)
            var k = 1 + rng.below(min(16, n - at))
            var out = List[UInt8]()
            for i in range(n):
                if i < at or i >= at + k:
                    out.append(b[i])
            b = out^
        elif op == 4 and n > 0:                     # truncate
            var keep = rng.below(n)
            var out = List[UInt8]()
            for i in range(keep):
                out.append(b[i])
            b = out^
        elif op == 5 and n > 1:                     # 1-3 byte length field: small or huge
            var w = 1 + rng.below(3)
            var at = rng.below(n)
            var big = rng.below(2) == 1
            for j in range(w):
                if at + j < n:
                    b[at + j] = 0xFF if big else UInt8(rng.below(4))
        elif op == 6 and n > 0:                     # duplicate a run
            var at = rng.below(n)
            var k = 1 + rng.below(min(32, n - at))
            var out = List[UInt8]()
            for i in range(at + k):
                out.append(b[i])
            for i in range(at, at + k):
                out.append(b[i])
            for i in range(at + k, n):
                out.append(b[i])
            b = out^
        elif op == 7 and len(other) > 0:            # splice with another seed
            var cut = rng.below(n + 1)
            var from_other = rng.below(len(other))
            var out = List[UInt8]()
            for i in range(cut):
                out.append(b[i])
            for i in range(from_other, len(other)):
                out.append(other[i])
            b = out^
        elif n > 0:                                 # random byte
            b[rng.below(n)] = UInt8(rng.next() & 0xFF)
    return b^


# ── Structure-aware DER mutation ────────────────────────────────────────────
# Byte-level mutations nearly always break DER framing, so they rarely reach
# fields deep inside a certificate. Here a seed is decoded into its TLV tree,
# one element is changed (empty or tiny content, a new tag, a dropped or
# duplicated child, truncation) and the tree is re-encoded with consistent
# lengths: well-formed DER carrying semantic anomalies. (This finds the
# empty-EC-point abort of tls 1.5.0 from valid certificates.)

struct _Tlv(Copyable, Movable):
    var tag: UInt8
    var content: List[UInt8]       # primitive content (if not constructed)
    var children: List[Int]        # indexes into the node list
    var constructed: Bool

    def __init__(out self, tag: UInt8, content: List[UInt8], constructed: Bool):
        self.tag = tag
        self.content = content.copy()
        self.children = List[Int]()
        self.constructed = constructed


def _der_len(b: List[UInt8], off: Int) -> Tuple[Int, Int]:
    """(length, header bytes after the tag), or (-1, 0) if malformed."""
    if off >= len(b):
        return (-1, 0)
    var first = Int(b[off])
    if first < 0x80:
        return (first, 1)
    var n = first & 0x7F
    if n == 0 or n > 3 or off + n >= len(b) + 0:
        return (-1, 0)
    var v = 0
    for i in range(n):
        if off + 1 + i >= len(b):
            return (-1, 0)
        v = (v << 8) | Int(b[off + 1 + i])
    return (v, 1 + n)


def _der_decode(b: List[UInt8], start: Int, end: Int, mut nodes: List[_Tlv], depth: Int) -> List[Int]:
    """Decode the TLVs in b[start:end] into nodes; return their indexes."""
    var ids = List[Int]()
    var off = start
    while off < end:
        var tag = b[off]
        var lh = _der_len(b, off + 1)
        if lh[0] < 0:
            break
        var cstart = off + 1 + lh[1]
        var cend = cstart + lh[0]
        if cend > end:
            break
        var content = List[UInt8]()
        for i in range(cstart, cend):
            content.append(b[i])
        var constructed = (tag & 0x20) != 0 and depth < 12
        var node = _Tlv(tag, content, constructed)
        var idx = len(nodes)
        nodes.append(node^)
        if constructed:
            var kids = _der_decode(b, cstart, cend, nodes, depth + 1)
            nodes[idx].children = kids^
        ids.append(idx)
        off = cend
    return ids^


def _der_encode(nodes: List[_Tlv], idx: Int) -> List[UInt8]:
    var body: List[UInt8]
    if nodes[idx].constructed:
        body = List[UInt8]()
        for i in range(len(nodes[idx].children)):
            var k = _der_encode(nodes, nodes[idx].children[i])
            for j in range(len(k)):
                body.append(k[j])
    else:
        body = nodes[idx].content.copy()
    var out: List[UInt8] = [nodes[idx].tag]
    var n = len(body)
    if n < 0x80:
        out.append(UInt8(n))
    elif n < 0x100:
        out.append(0x81)
        out.append(UInt8(n))
    elif n < 0x10000:
        out.append(0x82)
        out.append(UInt8(n >> 8))
        out.append(UInt8(n & 0xFF))
    else:
        out.append(0x83)
        out.append(UInt8(n >> 16))
        out.append(UInt8((n >> 8) & 0xFF))
        out.append(UInt8(n & 0xFF))
    for j in range(n):
        out.append(body[j])
    return out^


def der_mutate(seed: List[UInt8], mut rng: Rng) -> List[UInt8]:
    var nodes = List[_Tlv]()
    var roots = _der_decode(seed, 0, len(seed), nodes, 0)
    if len(roots) == 0 or len(nodes) == 0:
        return seed.copy()
    for _ in range(1 + rng.below(2)):
        var i = rng.below(len(nodes))
        var op = rng.below(8)
        if op == 0:                                 # empty primitive content
            if not nodes[i].constructed:
                nodes[i].content = List[UInt8]()
        elif op == 1:                               # one byte of content
            if not nodes[i].constructed:
                var c = List[UInt8]()
                if len(nodes[i].content) > 0 and rng.below(2) == 0:
                    c.append(nodes[i].content[0])
                else:
                    c.append(UInt8(rng.next() & 0xFF))
                nodes[i].content = c^
        elif op == 2:                               # truncate content
            if not nodes[i].constructed and len(nodes[i].content) > 0:
                var keep = rng.below(len(nodes[i].content))
                var c = List[UInt8]()
                for j in range(keep):
                    c.append(nodes[i].content[j])
                nodes[i].content = c^
        elif op == 3:                               # change the tag
            var tags: List[UInt8] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x0C, 0x13, 0x17, 0x18, 0x30, 0x31, 0xA0, 0xA3, 0x82, 0x87]
            nodes[i].tag = tags[rng.below(len(tags))]
        elif op == 4:                               # drop a child
            if nodes[i].constructed and len(nodes[i].children) > 0:
                var drop = rng.below(len(nodes[i].children))
                var kids = List[Int]()
                for j in range(len(nodes[i].children)):
                    if j != drop:
                        kids.append(nodes[i].children[j])
                nodes[i].children = kids^
        elif op == 5:                               # duplicate a child
            if nodes[i].constructed and len(nodes[i].children) > 0:
                nodes[i].children.append(nodes[i].children[rng.below(len(nodes[i].children))])
        elif op == 6:                               # empty a constructed element
            if nodes[i].constructed:
                nodes[i].children = List[Int]()
        else:                                       # flip a content bit
            if not nodes[i].constructed and len(nodes[i].content) > 0:
                var j = rng.below(len(nodes[i].content))
                nodes[i].content[j] ^= UInt8(1) << UInt8(rng.below(8))
    var out = List[UInt8]()
    for r in range(len(roots)):
        var e = _der_encode(nodes, roots[r])
        for j in range(len(e)):
            out.append(e[j])
    return out^


# ── Seeds ───────────────────────────────────────────────────────────────────

def unhex(h: String) -> List[UInt8]:
    var raw = h.as_bytes()
    var out = List[UInt8](capacity=len(raw) // 2)
    for i in range(0, len(raw) - 1, 2):
        var hi = raw[i]
        var lo = raw[i + 1]
        var a: UInt8 = (hi - 48) if hi <= 57 else ((hi - 87) if hi >= 97 else (hi - 55))
        var c: UInt8 = (lo - 48) if lo <= 57 else ((lo - 87) if lo >= 97 else (lo - 55))
        out.append((a << 4) | c)
    return out^


def cat(*parts: List[UInt8]) -> List[UInt8]:
    var out = List[UInt8]()
    for i in range(len(parts)):
        for j in range(len(parts[i])):
            out.append(parts[i][j])
    return out^


def filled(n: Int, v: UInt8) -> List[UInt8]:
    var out = List[UInt8]()
    for _ in range(n):
        out.append(v)
    return out^


def u16(v: Int) -> List[UInt8]:
    return [UInt8((v >> 8) & 0xFF), UInt8(v & 0xFF)]


def u24(v: Int) -> List[UInt8]:
    return [UInt8((v >> 16) & 0xFF), UInt8((v >> 8) & 0xFF), UInt8(v & 0xFF)]


def hs_msg(t: UInt8, body: List[UInt8]) -> List[UInt8]:
    var out: List[UInt8] = [t]
    return cat(out, u24(len(body)), body)


def record(t: UInt8, body: List[UInt8]) -> List[UInt8]:
    var head: List[UInt8] = [t, 3, 3]
    return cat(head, u16(len(body)), body)


def server_hello13() -> List[UInt8]:
    # supported_versions 0304; key_share x25519 with a 32-byte key
    var exts = cat(unhex("002b00020304" + "0033002400" + "1d0020"), filled(32, 7))
    return cat(unhex("0303"), filled(32, 1), unhex("00130100"), u16(len(exts)), exts)


def server_hello12() -> List[UInt8]:
    var exts = unhex("0000000000170000ff01000100")
    return cat(unhex("0303"), filled(32, 2), unhex("20"), filled(32, 3), unhex("c02b00"), u16(len(exts)), exts)


def hrr() -> List[UInt8]:
    var r = unhex("cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c")
    # supported_versions 0304; key_share selected_group secp256r1; cookie "abc"
    var exts = unhex("002b00020304" + "003300020017" + "002c00050003616263")
    return cat(unhex("0303"), r, unhex("00130100"), u16(len(exts)), exts)


def cert_message() -> List[UInt8]:
    var c = unhex(LEAF_OK)
    var entry = cat(u24(len(c)), c, unhex("0000"))
    return cat(unhex("00"), u24(len(entry)), entry)


def seeds_for(target: String) -> List[List[UInt8]]:
    var s = List[List[UInt8]]()
    if target == "cert":
        s.append(unhex(LEAF_OK))
        s.append(unhex(INTER))
        s.append(unhex(LEAF_IPSAN))
        s.append(unhex(INTER_NCD))
        s.append(unhex(RSA2048_LEAF))
        s.append(unhex(PSS_LEAF))     # RSASSA-PSS params
        s.append(unhex(EC384_LEAF))   # P-384 key, ecdsa-with-SHA512
    elif target == "spki":
        s.append(unhex("3059301306072a8648ce3d020106082a8648ce3d03010703420004" + "11" * 64))
    elif target == "ecdsa_sig":
        s.append(cat(unhex("3044022011"), filled(31, 0x22), unhex("022033"), filled(31, 0x44)))
        s.append(cat(unhex("3064023011"), filled(47, 0x22), unhex("023033"), filled(47, 0x44)))
    elif target == "server_hello":
        s.append(server_hello13())
        s.append(server_hello12())
    elif target == "hrr":
        s.append(hrr())
    elif target == "ee":
        s.append(unhex("0000"))
        s.append(unhex("0009001000050003026832"))
        s.append(unhex("000d0000000000100005000302683200"))
    elif target == "certmsg":
        s.append(cert_message())
    elif target == "certreq13":
        s.append(unhex("000008000d000400020403"))
        s.append(unhex("0201020008000d000400020403"))
    elif target == "cert_verify":
        s.append(cat(unhex("04030046"), filled(70, 0x30)))
    elif target == "nst":
        s.append(unhex("0000003c01020304010900040a0b0c0d0000"))
        # with an early_data extension (max_early_data_size 1024)
        s.append(unhex("0000003c01020304" + "0109" + "00040a0b0c0d" + "0008002a000400000400"))
    elif target == "ske":
        s.append(cat(unhex("03001d20"), filled(32, 9), unhex("04030004aabbccdd")))
        s.append(cat(unhex("03001741"), unhex("04"), filled(64, 9), unhex("08040004aabbccdd")))
    elif target == "certreq12":
        # types [ecdsa_sign], sig algs [0403], no CA names
        s.append(unhex("0140" + "00020403" + "0000"))
        s.append(cat(unhex("0201400004040308040006000430023000"), List[UInt8]()))
    elif target == "finished12":
        s.append(cat(unhex("1400000c"), filled(12, 5)))
    elif target == "alert":
        s.append(unhex("0228"))
        s.append(unhex("0100"))
    elif target == "ip":
        for t in ["192.0.2.1", "2001:db8::1", "::1", "fe80::1:2:3:4", "1.2.3.4.5", "10.0.0.256"]:
            var b = List[UInt8]()
            for c in t.as_bytes():
                b.append(c)
            s.append(b^)
    elif target == "post_handshake":
        s.append(unhex("04000012" + "0000003c01020304010900040a0b0c0d0000"))
        s.append(unhex("1800000100"))
        s.append(cat(unhex("04000012" + "0000003c01020304010900040a0b0c0d0000"), unhex("1800000101")))
    elif target == "hs_reader":
        s.append(cat(record(0x16, hs_msg(2, server_hello12())), record(0x16, hs_msg(11, cert_message()))))
        var m = cat(hs_msg(2, server_hello12()), hs_msg(11, cert_message()))
        s.append(cat(record(0x16, m), unhex("140303000101")))
    return s^


# ── Targets (raising is fine; aborting is the bug) ──────────────────────────

def run_target(target: String, b: List[UInt8], anchors: List[X509Cert]) raises:
    if target == "cert":
        var c = cert_parse(b)
        try:
            cert_hostname_match(c, "ok.example")
        except:
            pass
        var chain = List[X509Cert]()
        chain.append(c^)
        chain.append(cert_parse(unhex(INTER)))
        cert_chain_verify(chain, anchors, "ok.example")
    elif target == "spki":
        try:
            _ = asn1_parse_ec_spki(b)
        except:
            pass
        _ = asn1_parse_rsa_spki(b)
    elif target == "ecdsa_sig":
        try:
            _ = asn1_parse_ecdsa_sig(b)
        except:
            pass
        _ = asn1_parse_ecdsa_sig_48(b)
    elif target == "server_hello":
        try:
            _ = parse_server_hello_tls12_exts(b)
        except:
            pass
        _ = parse_server_hello_version(b)
    elif target == "hrr":
        _ = parse_hello_retry_request(b)
    elif target == "ee":
        var offered = List[String]()
        offered.append("h2")
        offered.append("http/1.1")
        _ = validate_encrypted_extensions(b, offered)
    elif target == "certmsg":
        _ = parse_certificate_chain(b)
    elif target == "certreq13":
        _ = parse_certificate_request13(b)
    elif target == "cert_verify":
        _ = parse_cert_verify(b)
    elif target == "nst":
        _ = parse_new_session_ticket(b)
    elif target == "ske":
        _ = parse_server_key_exchange(b)
    elif target == "certreq12":
        _ = parse_certificate_request12(b)
    elif target == "finished12":
        _ = parse_finished_body(b)
    elif target == "alert":
        tls_handle_incoming_alert(b)
    elif target == "ip":
        var ascii = List[UInt8]()
        for i in range(len(b)):
            ascii.append(b[i] & 0x7F)
        _ = parse_ip_literal(String(unsafe_from_utf8=ascii^))
    elif target == "post_handshake":
        var s = TlsSocket(Int32(-1))
        s._keys.server_app_secret = filled(32, 1)
        s._keys.client_app_secret = filled(32, 2)
        s._keys.server_write_key = filled(16, 3)
        s._keys.server_write_iv = filled(12, 4)
        s._keys.client_write_key = filled(16, 5)
        s._keys.client_write_iv = filled(12, 6)
        s._hs_rx = b.copy()
        s._process_post_handshake()
    elif target == "hs_reader":
        _hs_reader(b)
    else:
        raise Error("unknown target")


def _hs_reader(b: List[UInt8]) raises:
    var fds = alloc[Int32](2)
    if external_call["socketpair", Int32](Int32(1), Int32(1), Int32(0), fds) != 0:
        fds.unsafe_free()
        raise Error("socketpair")
    var mine = fds[unsafe_offset=0]
    var peer = fds[unsafe_offset=1]
    fds.unsafe_free()
    var n = len(b)
    var buf = alloc[UInt8](max(n, 1))
    for i in range(n):
        buf[unsafe_offset=i] = b[i]
    _ = external_call["write", Int](Int(peer), buf, n)
    buf.unsafe_free()
    _ = external_call["close", Int32](peer)
    var reader = HandshakeReader(mine, False)
    try:
        for _ in range(8):
            _ = reader.next_message()
    except e:
        _ = external_call["close", Int32](mine)
        raise e^
    _ = external_call["close", Int32](mine)


# ── Current-input file (kept when the process aborts) ───────────────────────

def open_current(path: String) -> Int32:
    var p = path
    return external_call["creat", Int32](p.as_c_string_slice().unsafe_ptr(), Int32(420))


def read_file(path: String) raises -> List[UInt8]:
    """Read a whole file through libc, with the open/read signatures tls uses
    (Mojo's open() declares errno access differently from tls, and a program
    may hold only one declaration per C function)."""
    var p = path
    var fd = external_call["open", Int32](p.as_c_string_slice().unsafe_ptr(), Int32(0))
    if fd < 0:
        raise Error("cannot open " + path)
    var out = List[UInt8]()
    var buf = alloc[UInt8](4096)
    while True:
        var got = external_call["read", Int](fd, buf, 4096)
        if got <= 0:
            break
        for i in range(got):
            out.append(buf[unsafe_offset=i])
    buf.unsafe_free()
    _ = external_call["close", Int32](fd)
    return out^


def save_current(fd: Int32, b: List[UInt8]):
    _ = external_call["lseek", Int](fd, Int(0), Int32(0))
    _ = external_call["ftruncate", Int32](fd, Int(0))
    var n = len(b)
    if n == 0:
        return
    var buf = alloc[UInt8](n)
    for i in range(n):
        buf[unsafe_offset=i] = b[i]
    _ = external_call["write", Int](Int(fd), buf, n)
    buf.unsafe_free()


def fuzz(target: String, seed: UInt64, iterations: Int, fd: Int32, anchors: List[X509Cert]) raises:
    var seeds = seeds_for(target)
    var rng = Rng(seed)
    var raised = 0
    var der_target = target == "cert" or target == "spki" or target == "ecdsa_sig"
    # seeds themselves first, then mutations
    for i in range(len(seeds)):
        save_current(fd, seeds[i])
        try:
            run_target(target, seeds[i], anchors)
        except:
            raised += 1
    for _ in range(iterations):
        var a = rng.below(len(seeds))
        var c = rng.below(len(seeds))
        var input: List[UInt8]
        if der_target and rng.below(2) == 0:
            input = der_mutate(seeds[a], rng)
        else:
            input = mutate(seeds[a], seeds[c], rng)
        save_current(fd, input)
        try:
            run_target(target, input, anchors)
        except:
            raised += 1
    print("fuzz", target, "seed", seed, ":", iterations, "inputs,", raised, "rejected, no crash")


def main() raises:
    var args = argv()
    if len(args) == 2 and String(args[1]) == "list":
        var all = targets()
        for i in range(len(all)):
            print(all[i])
        return
    if len(args) == 4 and String(args[1]) == "replay":
        var target = String(args[2])
        var data = read_file(String(args[3]))
        var anchors = List[X509Cert]()
        anchors.append(cert_parse(unhex(ROOT)))
        try:
            run_target(target, data, anchors)
            print("accepted")
        except e:
            print("rejected:", String(e))
        return
    if len(args) < 4:
        print("usage: fuzz_parsers <target|all> <seed> <iterations> [current-input path]")
        print("       fuzz_parsers list")
        print("       fuzz_parsers replay <target> <file>")
        return
    var target = String(args[1])
    var seed = UInt64(Int(String(args[2])))
    var iterations = Int(String(args[3]))
    var path = String(args[4]) if len(args) > 4 else String("fuzz_current.bin")
    var fd = open_current(path)
    if fd < 0:
        raise Error("cannot create " + path)
    var anchors = List[X509Cert]()
    anchors.append(cert_parse(unhex(ROOT)))
    if target == "all":
        var all = targets()
        for i in range(len(all)):
            print("target", all[i], flush=True)
            fuzz(all[i], seed + UInt64(i), iterations, fd, anchors)
    else:
        fuzz(target, seed, iterations, fd, anchors)
    _ = external_call["close", Int32](fd)
