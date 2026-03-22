# ============================================================================
# test_cert_sha384.mojo — SHA-384 cert signatures + RSA-PSS OID tests
# ============================================================================
# Test vectors generated with Python cryptography library (SHA-384 certs)
# and OpenSSL (RSA-PSS certs with standard RSA keys, PSS signing).
# ============================================================================

from crypto.cert import X509Cert, cert_parse, cert_verify_sig, cert_chain_verify


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


# ── SHA-384 RSA CA (sha384WithRSAEncryption, self-signed) ───────────────────
# Generated: Python cryptography library, RSA-2048, sha384WithRSA
comptime RSA_CA_SHA384 = "308202be308201a6a003020102020101300d06092a864886f70d01010c050030183116301406035504030c0d52534120534841333834204341301e170d3235303130313030303030305a170d3330303130313030303030305a30183116301406035504030c0d5253412053484133383420434130820122300d06092a864886f70d01010105000382010f003082010a0282010100bc4388da4abdbc050c9a1188a749ae8694e6abeaf3415bb99744915dc7e3b63811a877d183e228ff36dda2a7f238f5d901c12ad0b53678286813937814290185219c1284d6e3327dcd23e3fef3cb8f4e93b9b4702bb60d6805b52687b0991e941d902f5d5c8f568c844811aba9f7a611978894e8b413d09110662337e92220fb3929c62b584bc83485d800d80feef447d534da4c39e4e4b8c898324b8ea0edb5d3ef6c2b5a34d176f7d0e6c774948dd5be0f384dac402a1e3dbaeef069b93a99d62b9d1c639e66d5d7d5bddcc64a22efccedec5a8ae984723321474ccb94ac00111709fc942085119fceb401fd1c7eef8ed03dc26e4ee713e0a8318000bc8d610203010001a3133011300f0603551d130101ff040530030101ff300d06092a864886f70d01010c0500038201010045435bf611d151fbb35bdf508ab30d5d1240ed69542027aed216984a44718d054ee3095de18c20d1864232b7318630d9638989bcf89645d68928bce330059cab3deb09622a8ff8cabb1acbcaa7ff56f76fa78f0905237fc61c2f2389af6cd25729bdc5f53a9cfafec296c433ec734903ce576b71307cf868d81075f53b43a279a8a8d7963b50ef7ce927ae30bc6d96d2304aae2991ce5529e7bf65e17ebd0ab9c9f39c2280fdfd76f70966fc8690b739fa37d52a588262fcddd358a4789c38910209ce1af90789a5b64e45c11d2eae473a9bbeb6d3be166feb96134dc0f4e99d34622c0c5baf6c424a5e154a3e6f02c82d81f98797792f3189004b92fdd89623"

# ── SHA-384 RSA leaf (signed by RSA_CA_SHA384) ───────────────────────────────
# SAN: rsa-sha384.example.com
comptime RSA_LEAF_SHA384 = "308202d9308201c1a003020102020102300d06092a864886f70d01010c050030183116301406035504030c0d52534120534841333834204341301e170d3235303130313030303030305a170d3330303130313030303030305a3021311f301d06035504030c167273612d7368613338342e6578616d706c652e636f6d30820122300d06092a864886f70d01010105000382010f003082010a0282010100d07fb63ee9b14da0b0f6e8ede7b98f5d37648a5c06fd5e4dda582f5cfaa598f40b21f26f5a97f12c927d12ae74f13342c92f13980e6047df3702124f055bf4faa4c354351590a8cf5b3f7841a5d0186a7e4e2a25761cb8ba95cea90845d001d79142ce275ed4e2dc0347a76b7fe3e56453d1495e268aeabe9cb2bcee9d3e9f50588a5a7ec2a73f8c50bdbacc261789ef77dda37316759fe36830929d71697fadad8c75325be7055ad9a727d19d27de7d26c8f16a565391b5a2315c5521d5f2c549d990f481c899e1a2e5d3ccb2735b006e018bac1dadd01fad742a5d5bc9ed6ad34c31184c4ba7b29c70d1a9aee19650813a8624f260d6e119a633320f65d1810203010001a325302330210603551d11041a301882167273612d7368613338342e6578616d706c652e636f6d300d06092a864886f70d01010c050003820101008509fed2aecfb03be8ba07b67adc45d7f9327adb6409c8e0956de7aa8f0d576ed96016d282acd7d2a2fa70034c75c997773445e1f2a836c5e4dd51550b66440993bae7840549227ef3fdca19eae6eaeddf8c036ac147e0be9c73418cd0e662ab53b7dbc35f1d00bc8d5e15048070cf5f07d81d12e121ccadbd83941cafcf832013f5eea6e560bfdc72f0c70374481f32d36c4138d1f14ffa869f84a80cdd10cf46edb5839e2d584d2d1d46a5d12b7e95e9d5d7a4851c3d6a0ea51f2f4859d6c8922c688aba2e76131127d17c1dffc8a7ab5c96f1014e5aa1bf9e4b5b04352722fa9f60da52a07a2b891364c1bc9455402daebd6596529d43f761aec0fd661660"

# ── SHA-384 EC CA (ecdsa-with-SHA384, P-256, self-signed) ───────────────────
comptime EC_CA_SHA384 = "3082012e3081d6a003020102020103300a06082a8648ce3d04030330173115301306035504030c0c454320534841333834204341301e170d3235303130313030303030305a170d3330303130313030303030305a30173115301306035504030c0c4543205348413338342043413059301306072a8648ce3d020106082a8648ce3d0301070342000427311f49ef8d8739555d5560103f504a85a43c4e4a4d3fd6f270a33deea7f6fbb6b02559c2292be317ef8938704591d02b35438834f71acd83596fd6097f3078a3133011300f0603551d130101ff040530030101ff300a06082a8648ce3d04030303470030440220623d02ff69c1ddff18b32f8fc0a1624c73412a9325cf9c3f98f1809ab1cad89c0220775281bb584ca5d58984d5deb880173f0df9c07048dc690e647de2f7fb7d2bd6"

# ── SHA-384 EC leaf (signed by EC_CA_SHA384) ─────────────────────────────────
# SAN: ec-sha384.example.com
comptime EC_LEAF_SHA384 = "308201493081f0a003020102020104300a06082a8648ce3d04030330173115301306035504030c0c454320534841333834204341301e170d3235303130313030303030305a170d3330303130313030303030305a3020311e301c06035504030c1565632d7368613338342e6578616d706c652e636f6d3059301306072a8648ce3d020106082a8648ce3d03010703420004467435ff5dae3a7c4977865d6e823a5eb4cd181b41523fd8c877a1fdf4f6640e0568d3ee1e1596d191b64c8c18710901ae112f3f5be04a12eeb5a1ff758fe98fa324302230200603551d1104193017821565632d7368613338342e6578616d706c652e636f6d300a06082a8648ce3d0403030348003045022100cd44d5af4d4aa6bd4aabc93b42083e0e968b6d62738a195308a9d9f05d9803c10220461e5ae33fe59a84d0dea874c81e0461559cca0a44bf556066bc7091a5dd1a07"

# ── RSA-PSS CA (rsassa-pss + sha256, standard RSA-2048 SPKI) ─────────────────
# Generated: openssl req -x509 -sigopt rsa_padding_mode:pss -sha256
comptime RSA_PSS_CA = "3082036b30820223a00302010202142cc3b145ca30fec286b5ceaef889e4e8a29acab4303d06092a864886f70d01010a3030a00d300b0609608648016503040201a11a301806092a864886f70d010108300b0609608648016503040201a20302012030153113301106035504030c0a52534120505353204341301e170d3236303330323033343030355a170d3336303232383033343030355a30153113301106035504030c0a5253412050535320434130820122300d06092a864886f70d01010105000382010f003082010a0282010100c9cca467dae16dfb359ada38945c16074db4f0a7d07f3c571a0294bffb5c42a6328b4ad9ecc74ff270539366d161f3db98db72ffb2c50d5ecc1aacbae18b0182a96861ec6da982479d94d1a3af88c05f3fbacca5ede5f59790c03f0dd1e76dd7a831df81e3f042551f3542868e162d0bf5c7ca85c5bab069ca5ac42813df0b0ba59ea91d14f1801bd6fbb3f1c905277af8f280165ae3710b8d70345762ab1c7eb93fa23e78ec81aca9afc6a41b93122ae8dc39a4073f38e7bce159b0892b0693363c0a5dcc03f7ee20182b3968e8afc757ced0b9a7d194b0653e3add7805ce508248f37bbb23bf16fa0eefc5876ba7eeb8887efb0a05897a159c5b9a575d9aaf0203010001a3533051301d0603551d0e0416041440a0cfa225f54af4a9cd8e0b6014b059ff963eac301f0603551d2304183016801440a0cfa225f54af4a9cd8e0b6014b059ff963eac300f0603551d130101ff040530030101ff303d06092a864886f70d01010a3030a00d300b0609608648016503040201a11a301806092a864886f70d010108300b0609608648016503040201a20302012003820101007050975a26f19b94233fd67efd6b3efb55505c0589f0017a9a1f7e35cffc3b55a5a66147ed0531448c4f7d91e2ab88eb59e5344a29648c72cc6abae5d4cd4bf33da7838108941e7e2669b2adc1a64c945c3aeac6f0274d24f7741bf06a06e738d76b0a68fdb1f266aa8c359cb817e0b47c7f7e7997c12f1feb21884433e53285c75b3a8caa28f339ade1e63d9509dc6ac4018a74cc37024bd37f4b83d19be855883f641bfee2376604fcc974615bd1e402b9fa874c1200f21bd3b9898a7fcb5978827dd2a4d55cb923f306dd424e81775430b806dd75d1cce3ac0caa9ddc5707d27dbef8911ba88430298a8d892d804287815878ed3a7e6ab02ce1a74f9947b2"

# ── RSA-PSS leaf (signed by RSA_PSS_CA, rsassa-pss + sha256) ─────────────────
# CN=pss-leaf.example.com (no SAN; cert_san_names falls back to CN)
comptime RSA_PSS_LEAF = "3082031b308201d302145f883361efa34c31cd238646e63a36c3007234f7303d06092a864886f70d01010a3030a00d300b0609608648016503040201a11a301806092a864886f70d010108300b0609608648016503040201a20302012030153113301106035504030c0a52534120505353204341301e170d3236303330323033343330325a170d3336303232383033343330325a301f311d301b06035504030c147073732d6c6561662e6578616d706c652e636f6d30820122300d06092a864886f70d01010105000382010f003082010a0282010100af936b43ace9d329e239b82b60a7f6a2960fb834d63bd1ff3e814bb29d08e3a1659c138616fc47daaeed77e18d2db90638b0dff9399d8ef930a333ab7d5d7ec0251262cbae90bc8c37d0c2118e7f4ac3f1bb438a5a68ae7f5fdba638bf97ffb3774d08df3fb321ae32c434eb8072f4e7dfee04dfb1c74b44b6d00cf4c273443f512db0ddc536bc428e6c3e39d1085cc35498da0928e33660c9597cbe995c76045454a73e8ae46493cdc9e3cdf7f958f512a137bace8b5cb6f790f3d4b34f0b99821e7b22011be49d81a599b1ea57d1c8b715bd430d16038d656a0237c5bf0dd3e3ac6a7fa401f8c3a8eda8a1e13a8852e4830d9faee23947abe4f51dfee672ef0203010001303d06092a864886f70d01010a3030a00d300b0609608648016503040201a11a301806092a864886f70d010108300b0609608648016503040201a20302012003820101006382c4faea7cc32455f2abe2993ac7af7e232759290ffe079ef133992c0de35819024ceec645ce5323848d238448e1d1c31e6f4adf69b98b113c964f0c25a22ff3b47f1c09b46321e4ecfb1739558aae54d6667f43ef65e501035442f3193a146427564a03e09cecc8b0a46f8229533b1ad3a93faa34189a3484f233fda5c5e71be19fca2483d43e728fd31b4c3b61b0f1205a40d0e036f552635704e168a418c91c21814245d954f6d0e622758595ffc6af31dee829002a8ea1fb88928cdc17b37daeca55fa87747f817c143a35ab1fcdaf78cee88a047b35ed2c40999f25ab9cd8c5dbe248e5a3b4b7408d0367c3281eedd49f549fc0f166264c1bcb2d99fc"


# ── Tests ─────────────────────────────────────────────────────────────────────

def test1_parse_sha384_rsa_cert() raises:
    var der = hex_to_bytes(RSA_CA_SHA384)
    var cert = cert_parse(der)
    if cert.sig_alg != "rsa":
        raise Error("expected sig_alg=rsa, got " + cert.sig_alg)
    if cert.sig_hash != "sha384":
        raise Error("expected sig_hash=sha384, got " + cert.sig_hash)
    if cert.pub_key_alg != "rsa":
        raise Error("expected pub_key_alg=rsa, got " + cert.pub_key_alg)


def test2_parse_sha384_ecdsa_cert() raises:
    var der = hex_to_bytes(EC_CA_SHA384)
    var cert = cert_parse(der)
    if cert.sig_alg != "ecdsa":
        raise Error("expected sig_alg=ecdsa, got " + cert.sig_alg)
    if cert.sig_hash != "sha384":
        raise Error("expected sig_hash=sha384, got " + cert.sig_hash)
    if cert.pub_key_alg != "ec":
        raise Error("expected pub_key_alg=ec, got " + cert.pub_key_alg)


def test3_parse_rsa_pss_cert() raises:
    var der = hex_to_bytes(RSA_PSS_CA)
    var cert = cert_parse(der)
    if cert.sig_alg != "rsa-pss":
        raise Error("expected sig_alg=rsa-pss, got " + cert.sig_alg)
    if cert.sig_hash != "sha256":
        raise Error("expected sig_hash=sha256 (from PSS params), got " + cert.sig_hash)
    if cert.pub_key_alg != "rsa":
        raise Error("expected pub_key_alg=rsa, got " + cert.pub_key_alg)


def test4_verify_sha384_rsa_chain() raises:
    var ca_der = hex_to_bytes(RSA_CA_SHA384)
    var leaf_der = hex_to_bytes(RSA_LEAF_SHA384)
    var ca = cert_parse(ca_der)
    var leaf = cert_parse(leaf_der)
    # leaf signed by ca with sha384WithRSAEncryption
    cert_verify_sig(leaf, ca)


def test5_verify_sha384_ecdsa_chain() raises:
    var ca_der = hex_to_bytes(EC_CA_SHA384)
    var leaf_der = hex_to_bytes(EC_LEAF_SHA384)
    var ca = cert_parse(ca_der)
    var leaf = cert_parse(leaf_der)
    # leaf signed by ca with ecdsa-with-SHA384 (P-256, hash truncated to 32 bytes)
    cert_verify_sig(leaf, ca)


def test6_chain_verify_sha384_rsa() raises:
    var ca_der = hex_to_bytes(RSA_CA_SHA384)
    var leaf_der = hex_to_bytes(RSA_LEAF_SHA384)
    var ca = cert_parse(ca_der)
    var leaf = cert_parse(leaf_der)
    var chain = List[X509Cert]()
    chain.append(leaf.copy())
    chain.append(ca.copy())
    var trust = List[X509Cert]()
    trust.append(ca.copy())
    cert_chain_verify(chain, trust, "rsa-sha384.example.com")


def test7_chain_verify_rsa_pss() raises:
    var ca_der = hex_to_bytes(RSA_PSS_CA)
    var leaf_der = hex_to_bytes(RSA_PSS_LEAF)
    var ca = cert_parse(ca_der)
    var leaf = cert_parse(leaf_der)
    var chain = List[X509Cert]()
    chain.append(leaf.copy())
    chain.append(ca.copy())
    var trust = List[X509Cert]()
    trust.append(ca.copy())
    cert_chain_verify(chain, trust, "pss-leaf.example.com")


def main() raises:
    var passed = 0
    var failed = 0
    print("=== SHA-384 Cert Signature + RSA-PSS Tests ===")
    print()
    run_test("parse sha384WithRSAEncryption cert", passed, failed, test1_parse_sha384_rsa_cert)
    run_test("parse ecdsa-with-SHA384 cert", passed, failed, test2_parse_sha384_ecdsa_cert)
    run_test("parse rsassa-pss cert", passed, failed, test3_parse_rsa_pss_cert)
    run_test("cert_verify_sig sha384WithRSA chain", passed, failed, test4_verify_sha384_rsa_chain)
    run_test("cert_verify_sig sha384WithECDSA chain", passed, failed, test5_verify_sha384_ecdsa_chain)
    run_test("cert_chain_verify 2-cert SHA-384 RSA chain", passed, failed, test6_chain_verify_sha384_rsa)
    run_test("cert_chain_verify RSA-PSS root", passed, failed, test7_chain_verify_rsa_pss)
    print()
    print("Results:", passed, "passed,", failed, "failed")
    if failed > 0:
        raise Error(String(failed) + " test(s) failed")
