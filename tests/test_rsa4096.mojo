from crypto.rsa import rsa_pkcs1_verify

fn hex_to_bytes(h: String) -> List[UInt8]:
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

fn main() raises:
    # USERTrust RSA CA 4096-bit key (n, e)
    var n = hex_to_bytes(
        "80126517360ec3db08b3d0ac570d76ed"
        "cd27d34cad508361e2aa204d092d6409"
        "dcce899fcc3da9ecf6cfc1dcf1d3b1d6"
        "7b3728112b47da39c6bc3a19b45fa6bd"
        "7d9da36342b676f2a93b2b91f8e26fd0"
        "ec162090093ee2e874c918b491d46264"
        "db7fa306f188186a90223cbcfe13f087"
        "147bf6e41f8ed4e451c61167460851cb"
        "8614543fbc33fe7e6c9cff169d18bd51"
        "8e35a6a766c87267db2166b1d49b7803"
        "c0503ae8ccf0dcbc9e4cfeaf0596351f"
        "575ab7ffcef93db72cb6f654ddc8e712"
        "3a4dae4c8ab75c9ab4b7203dca7f2234"
        "ae7e3b68660144e7014e46539b3360f7"
        "94be5337907343f332c353efdbaafe74"
        "4e69c76b8c6093dec4c70cdfe132aecc"
        "933b517895678bee3d56fe0cd0690f1b"
        "0ff325266b336df76e47fa7343e57e0e"
        "a566b1297c3284635589c40dc1935430"
        "1913acd37d37a7eb5d3a6c355cdb41d7"
        "12daa9490bdfd8808a0993628eb566cf"
        "2588cd84b8b13fa4390fd9029eeb124c"
        "957cf36b05a95e1683ccb867e2e8139d"
        "cc5b82d34cb3ed5bffdee573ac233b2d"
        "00bf3555740949d849581a7f9236e651"
        "920ef3267d1c4d17bcc9ec4326d0bf41"
        "5f40a94444f499e757879e501f5754a8"
        "3efd74632fb1506509e658422e431a4c"
        "b4f0254759fa041e93d426464a5081b2"
        "debe78b7fc6715e1c957841e0f63d6e9"
        "62bad65f552eea5cc62808042539b80e"
        "2ba9f24c971c073f0d52f5edef2f820f"
    )
    var e = hex_to_bytes("010001")
    # Sectigo RSA DV CA signature (signed with USERTrust's 4096-bit key)
    var sig = hex_to_bytes(
        "32bf61bd0e48c34fc7ba474df89c7819"
        "01dc131d806ffcc370b4529a31339a57"
        "52fb319e6ba4ef54aa898d401768f811"
        "107cd2cab1f15586c7eeb3369186f639"
        "51bf46bf0fa0bab4f77e49c42a36179e"
        "e468397aaf944e566fb27b3bbf0a86bd"
        "cdc5771c03b838b1a21f5f7edb8adc46"
        "48b6680acfb2b5b4e234e467a9386609"
        "5ed2b8fc9d283a174027c2724e29fd21"
        "3c7ccf13fb962cc53144fd13edd59ba9"
        "6968777ceee1ffa4f93638085339a284"
        "349c19f3be0eacd52437eb23a878d0d3"
        "e7ef924764623922efc6f711be2285c6"
        "664424268e10328dc893ae079e833e2f"
        "d9f9f5468e63bec1e6b4dca6cd21a886"
        "0a95d92e85261afdfcb1b657426d95d1"
        "33f6391406824138f58f58dc805ba4d5"
        "7d9578fda79bfffdc5a869ab26e7a7a4"
        "05875ba9b7b8a3200b97a94585ddb38b"
        "e589378e290dfc0617f638400e42e412"
        "06fb7bf3c6116862dfe398f413d8154f"
        "8bb169d91060bc642aea31b7e4b5a33a"
        "149b26e30b7bfd028eb699c138975936"
        "f6a874a286b65eebc664eacfa0a3f96e"
        "9eba2d11b6869808582dc9ac2564f25e"
        "75b438c1ae7f5a4683ea51cab6f19911"
        "356ba56a7bc600b0e7f8be64b2adc8c2"
        "f1ace351eaa493e079c8e18140c90a5b"
        "e1123cc1602ae397c08942ca94cf4698"
        "1269bb98d0c2d30d724b476ee593c432"
        "28638743e4b0323e0ad34bbf239b1429"
        "412b9a041f932df1c739483cad5a127f"
    )
    # SHA-384 of Sectigo's TBSCertificate
    var hash = hex_to_bytes(
        "8b612b2190a95b28b866b9be5d0b95f3"
        "68c17534ab1da61a42dfb32766f9ae29"
        "08fe6bfd1669be140eddaf0d33e95235"
    )

    print("Testing RSA-4096 PKCS#1 v1.5 SHA-384 verification...")
    try:
        rsa_pkcs1_verify(n, e, hash, sig)
        print("PASS: RSA-4096 verification OK")
    except err:
        print("FAIL:", String(err))
