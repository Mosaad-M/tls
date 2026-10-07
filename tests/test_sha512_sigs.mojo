# ============================================================================
# test_sha512_sigs.mojo — SHA-512 signatures (tls 1.6.1)
# ============================================================================
# Fixtures from tests/gen_sha512_fixtures.sh (OpenSSL): certificate chains
# signed with sha512WithRSAEncryption, RSASSA-PSS (SHA-512) and
# ecdsa-with-SHA512 (P-256, P-384), and SHA-512 signatures over MSG made with
# the leaf keys. tls 1.6.0 rejected all of them.
#
# Covers the primitives, cert_verify_sig / cert_chain_verify, TLS 1.3
# CertificateVerify (rsa_pss_rsae_sha512), TLS 1.2 ServerKeyExchange
# (rsa_pkcs1_sha512, rsa_pss_rsae_sha512) and the offered
# signature_algorithms. ecdsa_secp521r1_sha512 (0x0603) is neither offered nor
# accepted: P-521 is unsupported, and the TLS 1.2 meaning of 0x0603 (SHA-512
# with any ECDSA curve) shares the code point.
# ============================================================================

from crypto.asn1 import asn1_parse_ecdsa_sig, asn1_parse_ecdsa_sig_48
from crypto.cert import X509Cert, cert_parse, cert_verify_sig, cert_chain_verify
from crypto.hash import sha512
from crypto.p256 import p256_ecdsa_verify
from crypto.p384 import p384_ecdsa_verify
from crypto.rsa import rsa_pkcs1_verify, rsa_pss_verify
from tls.connection import _verify_cert_verify_sig
from tls.connection12 import _verify_ske_signature
from tls.message import build_client_hello
from sha512_fixtures import (
    MSG, RSA_PKCS1_SIG, RSA_PSS_SIG, P256_SIG, P384_SIG,
    RSA_CA, RSA_LEAF, PSS_CA, PSS_LEAF, EC256_CA, EC256_LEAF, EC384_CA, EC384_LEAF,
)


def hex_to_bytes(hex: String) -> List[UInt8]:
    var raw = hex.as_bytes()
    var n = len(raw) // 2
    var out = List[UInt8](capacity=n)
    for i in range(n):
        var hi = raw[i * 2]
        var lo = raw[i * 2 + 1]
        var h_val: UInt8 = (hi - 48) if hi <= 57 else (hi - 87)
        var l_val: UInt8 = (lo - 48) if lo <= 57 else (lo - 87)
        out.append((h_val << 4) | l_val)
    return out^


def msg_bytes() -> List[UInt8]:
    var out = List[UInt8]()
    for b in String(MSG).as_bytes():
        out.append(b)
    return out^


def flip(data: List[UInt8], i: Int) -> List[UInt8]:
    var out = data.copy()
    out[i] ^= 0x01
    return out^


def prefix(data: List[UInt8], n: Int) -> List[UInt8]:
    var out = List[UInt8](capacity=n)
    for i in range(n):
        out.append(data[i])
    return out^


def cert(hex: String) raises -> X509Cert:
    return cert_parse(hex_to_bytes(hex))


def expect_raise(what: String, err: String) raises:
    """Raise unless err (from a failed call) is non-empty."""
    if err == "":
        raise Error(what + " was accepted")


def run_test[test_fn: def() thin raises -> None](
    name: String,
    mut passed: Int,
    mut failed: Int,
):
    try:
        test_fn()
        print("  PASS:", name)
        passed += 1
    except e:
        print("  FAIL:", name, "-", String(e))
        failed += 1


# ── Primitives ──────────────────────────────────────────────────────────────

def test_rsa_pkcs1_sha512() raises:
    var leaf = cert(RSA_LEAF)
    var h = sha512(msg_bytes())
    var sig = hex_to_bytes(RSA_PKCS1_SIG)
    rsa_pkcs1_verify(leaf.rsa_n, leaf.rsa_e, h, sig)
    var err = String("")
    try:
        rsa_pkcs1_verify(leaf.rsa_n, leaf.rsa_e, flip(h, 63), sig)
    except e:
        err = String(e)
    expect_raise("PKCS#1 SHA-512 with a wrong hash", err)
    # The same signature checked as SHA-384 (a 48-byte prefix) must fail
    err = String("")
    try:
        rsa_pkcs1_verify(leaf.rsa_n, leaf.rsa_e, prefix(h, 48), sig)
    except e:
        err = String(e)
    expect_raise("PKCS#1 SHA-512 signature as SHA-384", err)


def test_rsa_pss_sha512() raises:
    var leaf = cert(PSS_LEAF)
    var h = sha512(msg_bytes())
    var sig = hex_to_bytes(RSA_PSS_SIG)
    rsa_pss_verify(leaf.rsa_n, leaf.rsa_e, h, sig, 64)
    var err = String("")
    try:
        rsa_pss_verify(leaf.rsa_n, leaf.rsa_e, h, flip(sig, 100), 64)
    except e:
        err = String(e)
    expect_raise("PSS SHA-512 with a tampered signature", err)
    err = String("")
    try:
        rsa_pss_verify(leaf.rsa_n, leaf.rsa_e, h, sig, 32)
    except e:
        err = String(e)
    expect_raise("PSS SHA-512 with the wrong salt length", err)


def test_ecdsa_p256_sha512() raises:
    # ECDSA uses the leftmost 256 bits of the SHA-512 hash on P-256
    var leaf = cert(EC256_LEAF)
    var h = sha512(msg_bytes())
    var rs = asn1_parse_ecdsa_sig(hex_to_bytes(P256_SIG))
    p256_ecdsa_verify(leaf.ec_point, prefix(h, 32), rs[0].copy(), rs[1].copy())
    var err = String("")
    try:
        p256_ecdsa_verify(leaf.ec_point, prefix(flip(h, 0), 32), rs[0].copy(), rs[1].copy())
    except e:
        err = String(e)
    expect_raise("P-256 SHA-512 with a wrong hash", err)


def test_ecdsa_p384_sha512() raises:
    var leaf = cert(EC384_LEAF)
    var h = sha512(msg_bytes())
    var rs = asn1_parse_ecdsa_sig_48(hex_to_bytes(P384_SIG))
    p384_ecdsa_verify(leaf.ec_point, prefix(h, 48), rs[0].copy(), rs[1].copy())


# ── Certificates ────────────────────────────────────────────────────────────

def check_chain(ca_hex: String, leaf_hex: String, host: String, alg: String) raises:
    var ca = cert(ca_hex)
    var leaf = cert(leaf_hex)
    if leaf.sig_hash != "sha512" or ca.sig_hash != "sha512":
        raise Error("sig_hash: " + leaf.sig_hash + " / " + ca.sig_hash)
    if leaf.sig_alg != alg:
        raise Error("sig_alg: " + leaf.sig_alg)
    cert_verify_sig(ca, ca)
    cert_verify_sig(leaf, ca)
    var chain = List[X509Cert]()
    chain.append(leaf.copy())
    var trust = List[X509Cert]()
    trust.append(ca.copy())
    cert_chain_verify(chain, trust, host)
    # A one-bit change in the signed part (the TBS's last byte, in the SAN
    # name; the TBS follows the 4-byte outer header) must break the signature
    var der = hex_to_bytes(leaf_hex)
    var bad = cert_parse(flip(der, 4 + len(leaf.tbs_raw) - 1))
    var err = String("")
    try:
        cert_verify_sig(bad, ca)
    except e:
        err = String(e)
    expect_raise("tampered " + alg + " SHA-512 leaf", err)


def test_chain_rsa_sha512() raises:
    check_chain(RSA_CA, RSA_LEAF, "rsa.example", "rsa")


def test_chain_pss_sha512() raises:
    check_chain(PSS_CA, PSS_LEAF, "pss.example", "rsa-pss")


def test_chain_ecdsa_p256_sha512() raises:
    check_chain(EC256_CA, EC256_LEAF, "ec256.example", "ecdsa")


def test_chain_ecdsa_p384_sha512() raises:
    check_chain(EC384_CA, EC384_LEAF, "ec384.example", "ecdsa")


# ── TLS 1.3 CertificateVerify ───────────────────────────────────────────────

def test_tls13_cert_verify_pss_sha512() raises:
    var leaf = cert(PSS_LEAF)
    var sig = hex_to_bytes(RSA_PSS_SIG)
    _verify_cert_verify_sig(leaf, 0x0806, sig, msg_bytes())
    var err = String("")
    try:
        _verify_cert_verify_sig(leaf, 0x0806, sig, flip(msg_bytes(), 0))
    except e:
        err = String(e)
    expect_raise("CertificateVerify 0x0806 over other data", err)
    # rsa_pkcs1_sha512 is forbidden in TLS 1.3 CertificateVerify
    err = String("")
    try:
        _verify_cert_verify_sig(cert(RSA_LEAF), 0x0601, hex_to_bytes(RSA_PKCS1_SIG), msg_bytes())
    except e:
        err = String(e)
    expect_raise("CertificateVerify 0x0601 (PKCS#1)", err)
    err = String("")
    try:
        _verify_cert_verify_sig(cert(EC384_LEAF), 0x0603, hex_to_bytes(P384_SIG), msg_bytes())
    except e:
        err = String(e)
    expect_raise("CertificateVerify 0x0603 (secp521r1)", err)


# ── TLS 1.2 ServerKeyExchange ───────────────────────────────────────────────

def test_tls12_ske_sha512() raises:
    _verify_ske_signature(cert(RSA_LEAF), 6, 1, hex_to_bytes(RSA_PKCS1_SIG), msg_bytes())
    _verify_ske_signature(cert(PSS_LEAF), 8, 6, hex_to_bytes(RSA_PSS_SIG), msg_bytes())
    var err = String("")
    try:
        _verify_ske_signature(cert(RSA_LEAF), 6, 1, hex_to_bytes(RSA_PKCS1_SIG), flip(msg_bytes(), 3))
    except e:
        err = String(e)
    expect_raise("SKE rsa_pkcs1_sha512 over other data", err)
    # (sha512, ecdsa) is not offered, so it is not accepted either
    err = String("")
    try:
        _verify_ske_signature(cert(EC256_LEAF), 6, 3, hex_to_bytes(P256_SIG), msg_bytes())
    except e:
        err = String(e)
    expect_raise("SKE 0x0603 (not offered)", err)


# ── ClientHello signature_algorithms ────────────────────────────────────────

def offered_sig_algs(hello: List[UInt8]) raises -> List[UInt16]:
    var p = 4 + 2 + 32
    p += 1 + Int(hello[p])                                    # session_id
    p += 2 + ((Int(hello[p]) << 8) | Int(hello[p + 1]))       # cipher_suites
    p += 1 + Int(hello[p])                                    # compression
    var end = p + 2 + ((Int(hello[p]) << 8) | Int(hello[p + 1]))
    p += 2
    while p + 4 <= end:
        var t = (Int(hello[p]) << 8) | Int(hello[p + 1])
        var n = (Int(hello[p + 2]) << 8) | Int(hello[p + 3])
        if t == 0x000D:
            var out = List[UInt16]()
            var q = p + 6
            while q < p + 4 + n:
                out.append(UInt16((Int(hello[q]) << 8) | Int(hello[q + 1])))
                q += 2
            return out^
        p += 4 + n
    raise Error("no signature_algorithms extension")


def test_client_hello_offers_sha512() raises:
    var rnd = List[UInt8](length=32, fill=1)
    var sid = List[UInt8](length=32, fill=2)
    var pub = List[UInt8](length=32, fill=3)
    var algs = offered_sig_algs(build_client_hello(rnd, sid, pub, "example.com"))
    var has_0806 = False
    var has_0601 = False
    for a in algs:
        if a == 0x0806:
            has_0806 = True
        if a == 0x0601:
            has_0601 = True
        if a == 0x0603:
            raise Error("0x0603 offered")
    if not has_0806 or not has_0601:
        raise Error("rsa_pss_rsae_sha512 / rsa_pkcs1_sha512 not offered")


def main() raises:
    var passed = 0
    var failed = 0
    print("test_sha512_sigs")
    run_test[test_rsa_pkcs1_sha512]("RSA PKCS#1 v1.5 SHA-512", passed, failed)
    run_test[test_rsa_pss_sha512]("RSA-PSS SHA-512 (salt 64)", passed, failed)
    run_test[test_ecdsa_p256_sha512]("ECDSA P-256 with SHA-512 (truncated)", passed, failed)
    run_test[test_ecdsa_p384_sha512]("ECDSA P-384 with SHA-512 (truncated)", passed, failed)
    run_test[test_chain_rsa_sha512]("chain: sha512WithRSAEncryption", passed, failed)
    run_test[test_chain_pss_sha512]("chain: RSASSA-PSS SHA-512", passed, failed)
    run_test[test_chain_ecdsa_p256_sha512]("chain: ecdsa-with-SHA512 (P-256)", passed, failed)
    run_test[test_chain_ecdsa_p384_sha512]("chain: ecdsa-with-SHA512 (P-384)", passed, failed)
    run_test[test_tls13_cert_verify_pss_sha512]("TLS 1.3 CertificateVerify 0x0806", passed, failed)
    run_test[test_tls12_ske_sha512]("TLS 1.2 ServerKeyExchange SHA-512", passed, failed)
    run_test[test_client_hello_offers_sha512]("ClientHello offers 0x0806 and 0x0601", passed, failed)
    print("Results:", passed, "passed,", failed, "failed")
    if failed > 0:
        raise Error("test_sha512_sigs: " + String(failed) + " failed")
