# ============================================================================
# test_cert_chain.mojo — Certificate chain verification tests
# ============================================================================
# 3-cert chain: ROOT (serial 100) → INTER (serial 200) → LEAF (serial 300)
#   LEAF SAN: www.example.com
# 2-cert chain: ROOT2 (serial 100) → LEAF2 (serial 400)
#   LEAF2 SAN: leaf2.example.com
# Both chains use ECDSA P-256 / SHA-256.
# Test vectors generated with Python cryptography library.
# ============================================================================

from crypto.cert import X509Cert, cert_parse, cert_chain_verify


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


# ── 3-cert chain (ROOT→INTER→LEAF) ──────────────────────────────────────────
comptime ROOT_HEX = "3082012f3081d6a003020102020164300a06082a8648ce3d04030230173115301306035504030c0c5465737420526f6f74204341301e170d3235303130313030303030305a170d3330303130313030303030305a30173115301306035504030c0c5465737420526f6f742043413059301306072a8648ce3d020106082a8648ce3d03010703420004ae4d39aae1e4305fe43bca31fe17d99a0ec74186284472f867e68bf13782baa3176d00bd80eaca15bfc30faae7fb86a927d5c53bef7f2fce94e970ec07aa7abfa3133011300f0603551d130101ff040530030101ff300a06082a8648ce3d040302034800304502201c370f09520f276db9ac3034d71ee27a7ed2864e9a10ab0a602cf59cf52ec854022100ca1d3c4caf3fac392fa6db4c7ba20c6e6d0a8104703299a4546b7022b31d13ed"

comptime INTER_HEX = "3082013b3081e2a003020102020200c8300a06082a8648ce3d04030230173115301306035504030c0c5465737420526f6f74204341301e170d3235303130313030303030305a170d3238303130313030303030305a301f311d301b06035504030c145465737420496e7465726d6564696174652043413059301306072a8648ce3d020106082a8648ce3d030107034200045e11f6ae4eeb75874c85625e0cbd8fe3bdc9373173c40d9efe00c622bf3eaf6f6c8c2886eea6938eb1b1127261173cf89eca80e247301bbaa44f55ced207367aa316301430120603551d130101ff040830060101ff020100300a06082a8648ce3d0403020348003045022100d126fd31acdda0d72d6cfe6964835e73ab7ed7a9d6bc2f24ae0eec89292d2d51022030e9d62e446a29c73c11627087dac8e65b59be5661ff59375eca8b33980babc0"

comptime LEAF_HEX = "308201453081eda0030201020202012c300a06082a8648ce3d040302301f311d301b06035504030c145465737420496e7465726d656469617465204341301e170d3235303130313030303030305a170d3237303130313030303030305a301a3118301606035504030c0f7777772e6578616d706c652e636f6d3059301306072a8648ce3d020106082a8648ce3d03010703420004d491d750a6097fcf4b06b80788e0a15f38b4da20a78bc290b05920b203897da5bb8077088aef99462f11916aba76fabff64f940f321642313cc543c34e6cc801a31e301c301a0603551d1104133011820f7777772e6578616d706c652e636f6d300a06082a8648ce3d0403020347003044022042d5dfe4590e5bdaf4906afd9cd522f096a1c064fd10f703b2346f23d7df21f702202bfd7a9af9fe32bd0897460a2e19d551880f055fc4125a21a5a59a5b50b19a7f"

# Tampered INTER (last byte flipped c0→bf — invalid ECDSA sig)
comptime TAMPERED_INTER_HEX = "3082013b3081e2a003020102020200c8300a06082a8648ce3d04030230173115301306035504030c0c5465737420526f6f74204341301e170d3235303130313030303030305a170d3238303130313030303030305a301f311d301b06035504030c145465737420496e7465726d6564696174652043413059301306072a8648ce3d020106082a8648ce3d030107034200045e11f6ae4eeb75874c85625e0cbd8fe3bdc9373173c40d9efe00c622bf3eaf6f6c8c2886eea6938eb1b1127261173cf89eca80e247301bbaa44f55ced207367aa316301430120603551d130101ff040830060101ff020100300a06082a8648ce3d0403020348003045022100d126fd31acdda0d72d6cfe6964835e73ab7ed7a9d6bc2f24ae0eec89292d2d51022030e9d62e446a29c73c11627087dac8e65b59be5661ff59375eca8b33980babbf"

# ── 2-cert chain (ROOT2→LEAF2) ───────────────────────────────────────────────
comptime ROOT2_HEX = "3082012e3081d6a003020102020164300a06082a8648ce3d04030230173115301306035504030c0c5465737420526f6f74204341301e170d3235303130313030303030305a170d3330303130313030303030305a30173115301306035504030c0c5465737420526f6f742043413059301306072a8648ce3d020106082a8648ce3d0301070342000455d66ce8c1ad2dac3af06f613571d8d65c4528d0e1cf93ef8629f3ffd6f7f4116630ed1d38512d2a369ff18da313f8d361374686d4423e11807813f000431d30a3133011300f0603551d130101ff040530030101ff300a06082a8648ce3d0403020347003044022012de498233d446f4b48ccdae53b88f83d9535f10dccbb64b244ab0dccfe4322902202e2ecdede9872c76c397baa6f50b3f3a3085492906f703f10ab668de1a9a8c30"

comptime LEAF2_HEX = "308201423081e9a00302010202020190300a06082a8648ce3d04030230173115301306035504030c0c5465737420526f6f74204341301e170d3235303130313030303030305a170d3237303130313030303030305a301c311a301806035504030c116c656166322e6578616d706c652e636f6d3059301306072a8648ce3d020106082a8648ce3d030107034200041c834be110c76454f6233467ae6e9df97780abe52f5afb11f9d2fc3a8e76e7eac5b3c098e40b704835cbf11e7ef4d12eda85dfea91fbdd9423b9853af2065bafa320301e301c0603551d110415301382116c656166322e6578616d706c652e636f6d300a06082a8648ce3d0403020348003045022100c0deba71917ba9b605eb377feadd2cd59652cc6e25bbfb380824e56598bdabb00220256032a7a33305bddb0aeaa7de018d215549d5facce3779a319df5bc1ee808da"


# ── Tests ─────────────────────────────────────────────────────────────────────

def test_valid_2cert_chain() raises:
    var root2 = cert_parse(hex_to_bytes(ROOT2_HEX))
    var leaf2 = cert_parse(hex_to_bytes(LEAF2_HEX))
    var chain = List[X509Cert]()
    chain.append(leaf2^)
    chain.append(root2.copy())
    var anchors = List[X509Cert]()
    anchors.append(root2^)
    cert_chain_verify(chain, anchors, "leaf2.example.com")


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
    cert_chain_verify(chain, anchors, "www.example.com")


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
    var tampered_inter = cert_parse(hex_to_bytes(TAMPERED_INTER_HEX))
    var leaf = cert_parse(hex_to_bytes(LEAF_HEX))
    var chain = List[X509Cert]()
    chain.append(leaf^)
    chain.append(tampered_inter^)
    chain.append(root.copy())
    var anchors = List[X509Cert]()
    anchors.append(root^)
    var raised = False
    try:
        cert_chain_verify(chain, anchors, "www.example.com")
    except:
        raised = True
    if not raised:
        raise Error("expected raise for tampered intermediate signature")


def test_unrelated_trust_anchor() raises:
    # Use ROOT (from 3-cert chain) as TA for LEAF2+ROOT2 chain — should fail
    var root = cert_parse(hex_to_bytes(ROOT_HEX))    # unrelated anchor
    var root2 = cert_parse(hex_to_bytes(ROOT2_HEX))
    var leaf2 = cert_parse(hex_to_bytes(LEAF2_HEX))
    var chain = List[X509Cert]()
    chain.append(leaf2^)
    chain.append(root2^)
    var anchors = List[X509Cert]()
    anchors.append(root^)
    var raised = False
    try:
        cert_chain_verify(chain, anchors, "leaf2.example.com")
    except:
        raised = True
    if not raised:
        raise Error("expected raise for unrelated trust anchor")


def main() raises:
    var passed = 0
    var failed = 0

    print("=== Certificate Chain Verification Tests ===")
    print()

    run_test("valid 2-cert chain", passed, failed, test_valid_2cert_chain)
    run_test("valid 3-cert chain (root→inter→leaf)", passed, failed, test_valid_3cert_chain)
    run_test("hostname mismatch raises", passed, failed, test_hostname_mismatch)
    run_test("tampered intermediate raises", passed, failed, test_tampered_intermediate)
    run_test("unrelated trust anchor raises", passed, failed, test_unrelated_trust_anchor)

    print()
    print("Results:", passed, "passed,", failed, "failed")
    if failed > 0:
        raise Error(String(failed) + " test(s) failed")
