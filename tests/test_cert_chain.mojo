# ============================================================================
# test_cert_chain.mojo — Certificate chain verification tests
# ============================================================================
# 3-cert chain: ROOT → INTER → LEAF (SAN ok.example)
# 2-cert chain: ROOT → LEAF2 (SAN direct-root.example)
# Both from tests/path_fixtures.mojo (gen_path_fixtures.sh, valid to 2125);
# ECDSA P-256 / SHA-256. The cross-signed fixtures below are valid to 2045.
# ============================================================================

from crypto.cert import X509Cert, cert_parse, cert_chain_verify
from path_fixtures import (
    ROOT as ROOT_HEX, INTER as INTER_HEX, LEAF_OK as LEAF_HEX,
    LEAF_DIRECT as LEAF2_HEX, STRAY_ROOT as UNRELATED_ROOT_HEX,
)

comptime ROOT2_HEX = ROOT_HEX  # LEAF2 is issued directly by the root


def _tampered(h: String) -> String:
    """Flip the last hex digit (inside the signature)."""
    var b = h.as_bytes()
    var out = String(h[byte=0:len(b) - 1])
    out += "0" if b[len(b) - 1] != 48 else "1"
    return out^


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


# ── 3-cert chain (ROOT→INTER→LEAF) ──────────────────────────────────────────



# Tampered INTER (last byte flipped c0→bf — invalid ECDSA sig)

# ── 2-cert chain (ROOT2→LEAF2) ───────────────────────────────────────────────



# ── Cross-signed root (like GTS Root R4 cross-signed by GlobalSign Root CA) ──
# XCROSS has XNEW_ROOT's subject and key but is issued by XOLD_ROOT. A server
# sends [XLEAF, XINTER, XCROSS]; a client that trusts only XNEW_ROOT (the old
# root having been removed from its CA bundle) must still accept the chain.
# Valid 2025-2045. Generated with the Python cryptography library.
comptime XNEW_ROOT_HEX = "308201323081d9a003020102020201f4300a06082a8648ce3d04030230183116301406035504030c0d54657374204e657720526f6f74301e170d3235303130313030303030305a170d3435303130313030303030305a30183116301406035504030c0d54657374204e657720526f6f743059301306072a8648ce3d020106082a8648ce3d03010703420004c56e1d8aaae92c06c34fed27d01b2c0f6f969c0b30ea3606f2886fd09997c473d23adab882106fdd5c80c6af54697a3e724d8f82e911eea3bfafd21e1626bcbea3133011300f0603551d130101ff040530030101ff300a06082a8648ce3d04030203480030450220354167f7b5133c51a34fc1a58759f4e98ccda0a4c09fc74914c8b8649c2e4816022100a5081dc8a955bcaec2c59c010a351b85b681674be48cfbc2453611632d6c5db4"
comptime XOLD_ROOT_HEX = "308201313081d9a003020102020201f5300a06082a8648ce3d04030230183116301406035504030c0d54657374204f6c6420526f6f74301e170d3235303130313030303030305a170d3435303130313030303030305a30183116301406035504030c0d54657374204f6c6420526f6f743059301306072a8648ce3d020106082a8648ce3d030107034200046dc08e34c013fc3341dcfba76e40bc9d4ec4c382a887fe4116c79bdc77009d8f158ecf21a86edb941d14fa0ea560bd7e35b48c9de932cfdfc7adafb6eaef8c48a3133011300f0603551d130101ff040530030101ff300a06082a8648ce3d04030203470030440220590714cde48d10452b849dfd3f09f8c2df5d923a1be3f34c05fdc01d277ae27e02200ddeb80e7df228537d9cd79c9f1b51e8c0202311a3b07833dfd0a41c7deab110"
comptime XCROSS_HEX = "308201323081d9a003020102020201f6300a06082a8648ce3d04030230183116301406035504030c0d54657374204f6c6420526f6f74301e170d3235303130313030303030305a170d3435303130313030303030305a30183116301406035504030c0d54657374204e657720526f6f743059301306072a8648ce3d020106082a8648ce3d03010703420004c56e1d8aaae92c06c34fed27d01b2c0f6f969c0b30ea3606f2886fd09997c473d23adab882106fdd5c80c6af54697a3e724d8f82e911eea3bfafd21e1626bcbea3133011300f0603551d130101ff040530030101ff300a06082a8648ce3d0403020348003045022100b92f7addafca94609b55d616db649763fa2e766c240db1140d648b7f80e13722022048f99057f0b54b30be9a6cc392ac88d2ee7abfc1d31b73b0841d84e5bb482867"
comptime XINTER_HEX = "308201353081dca003020102020201f7300a06082a8648ce3d04030230183116301406035504030c0d54657374204e657720526f6f74301e170d3235303130313030303030305a170d3435303130313030303030305a301b3119301706035504030c10546573742043726f737320496e7465723059301306072a8648ce3d020106082a8648ce3d03010703420004a19b9fd319c39f9f3bf5fe6f50375a19f4cf5fbe48213c53827e3a64766b2e960fe0fbb4d2e49f0e40c4300dffe23f6cfdcded7f9e3ba3bb3be18712c1a09a50a3133011300f0603551d130101ff040530030101ff300a06082a8648ce3d040302034800304502202a2684b51dff435da71bfcf146797007b48d9f1313cd916c3c8e8c6cfb0c98d8022100d9317441152485124226f6cae6d44afeba630fcd400d87209dbf51a9a3f79dc4"
comptime XLEAF_HEX = "308201463081eda003020102020201f8300a06082a8648ce3d040302301b3119301706035504030c10546573742043726f737320496e746572301e170d3235303130313030303030305a170d3435303130313030303030305a301c311a301806035504030c1163726f73732e6578616d706c652e636f6d3059301306072a8648ce3d020106082a8648ce3d03010703420004e15843c4658d16c17cbf5524a21fef0a82de26cccc4649199662e43d532d032f6f610cf872c47cd95f01c8a7c5800e7f27370302bd60155cbe735ae31e164d54a320301e301c0603551d1104153013821163726f73732e6578616d706c652e636f6d300a06082a8648ce3d0403020348003045022070b9d123bdd472904a189c8fc00e742e0f4150136514f143776c6d602e9d4b87022100feb31b4d5852bb5aa3926f184aca170fbf9d99b6644946be628f51c603b4c068"


# ── Tests ─────────────────────────────────────────────────────────────────────

def test_valid_2cert_chain() raises:
    var root2 = cert_parse(hex_to_bytes(ROOT2_HEX))
    var leaf2 = cert_parse(hex_to_bytes(LEAF2_HEX))
    var chain = List[X509Cert]()
    chain.append(leaf2^)
    chain.append(root2.copy())
    var anchors = List[X509Cert]()
    anchors.append(root2^)
    cert_chain_verify(chain, anchors, "direct-root.example")


def test_valid_3cert_chain() raises:
    var root = cert_parse(hex_to_bytes(ROOT_HEX))
    var inter = cert_parse(hex_to_bytes(INTER_HEX))
    var leaf = cert_parse(hex_to_bytes(LEAF_HEX))
    var chain = List[X509Cert]()
    chain.append(leaf^)
    chain.append(inter^)
    chain.append(root.copy())
    var anchors = List[X509Cert]()
    anchors.append(root^)
    cert_chain_verify(chain, anchors, "ok.example")


def test_hostname_mismatch() raises:
    var root2 = cert_parse(hex_to_bytes(ROOT2_HEX))
    var leaf2 = cert_parse(hex_to_bytes(LEAF2_HEX))
    var chain = List[X509Cert]()
    chain.append(leaf2^)
    chain.append(root2.copy())
    var anchors = List[X509Cert]()
    anchors.append(root2^)
    var raised = False
    try:
        cert_chain_verify(chain, anchors, "wrong.com")
    except:
        raised = True
    if not raised:
        raise Error("expected raise for hostname mismatch")


def test_tampered_intermediate() raises:
    var root = cert_parse(hex_to_bytes(ROOT_HEX))
    var tampered_inter = cert_parse(hex_to_bytes(_tampered(INTER_HEX)))
    var leaf = cert_parse(hex_to_bytes(LEAF_HEX))
    var chain = List[X509Cert]()
    chain.append(leaf^)
    chain.append(tampered_inter^)
    chain.append(root.copy())
    var anchors = List[X509Cert]()
    anchors.append(root^)
    var raised = False
    try:
        cert_chain_verify(chain, anchors, "ok.example")
    except:
        raised = True
    if not raised:
        raise Error("expected raise for tampered intermediate signature")


def test_unrelated_trust_anchor() raises:
    # Use ROOT (from 3-cert chain) as TA for LEAF2+ROOT2 chain — should fail
    var root = cert_parse(hex_to_bytes(UNRELATED_ROOT_HEX))    # unrelated anchor
    var root2 = cert_parse(hex_to_bytes(ROOT2_HEX))
    var leaf2 = cert_parse(hex_to_bytes(LEAF2_HEX))
    var chain = List[X509Cert]()
    chain.append(leaf2^)
    chain.append(root2^)
    var anchors = List[X509Cert]()
    anchors.append(root^)
    var raised = False
    try:
        cert_chain_verify(chain, anchors, "direct-root.example")
    except:
        raised = True
    if not raised:
        raise Error("expected raise for unrelated trust anchor")


def _cross_chain() raises -> List[X509Cert]:
    var chain = List[X509Cert]()
    chain.append(cert_parse(hex_to_bytes(XLEAF_HEX)))
    chain.append(cert_parse(hex_to_bytes(XINTER_HEX)))
    chain.append(cert_parse(hex_to_bytes(XCROSS_HEX)))
    return chain^


def test_cross_signed_root_trusted_by_key() raises:
    """Only the new root is trusted: the chain's last cert (XCROSS) is not
    signed by it, but carries its key, so the chain is anchored there."""
    var anchors = List[X509Cert]()
    anchors.append(cert_parse(hex_to_bytes(XNEW_ROOT_HEX)))
    cert_chain_verify(_cross_chain(), anchors, "cross.example.com")


def test_cross_signed_root_trusted_via_old_root() raises:
    var anchors = List[X509Cert]()
    anchors.append(cert_parse(hex_to_bytes(XOLD_ROOT_HEX)))
    cert_chain_verify(_cross_chain(), anchors, "cross.example.com")


def test_cross_signed_chain_unrelated_anchor() raises:
    var anchors = List[X509Cert]()
    anchors.append(cert_parse(hex_to_bytes(UNRELATED_ROOT_HEX)))
    var raised = False
    try:
        cert_chain_verify(_cross_chain(), anchors, "cross.example.com")
    except:
        raised = True
    if not raised:
        raise Error("expected raise for cross-signed chain with unrelated anchor")


def main() raises:
    var passed = 0
    var failed = 0

    print("=== Certificate Chain Verification Tests ===")
    print()

    run_test[test_valid_2cert_chain]("valid 2-cert chain", passed, failed)
    run_test[test_valid_3cert_chain]("valid 3-cert chain (root→inter→leaf)", passed, failed)
    run_test[test_hostname_mismatch]("hostname mismatch raises", passed, failed)
    run_test[test_tampered_intermediate]("tampered intermediate raises", passed, failed)
    run_test[test_unrelated_trust_anchor]("unrelated trust anchor raises", passed, failed)
    run_test[test_cross_signed_root_trusted_by_key]("cross-signed root trusted by key", passed, failed)
    run_test[test_cross_signed_root_trusted_via_old_root]("cross-signed root trusted via old root", passed, failed)
    run_test[test_cross_signed_chain_unrelated_anchor]("cross-signed chain, unrelated anchor raises", passed, failed)

    print()
    print("Results:", passed, "passed,", failed, "failed")
    if failed > 0:
        raise Error(String(failed) + " test(s) failed")
