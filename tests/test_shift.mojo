"""Test arithmetic vs logical right shift for Int64 in Mojo."""

fn main():
    # Test: does Int64 >> use arithmetic (sign-preserving) or logical (zero-fill) right shift?
    var neg1: Int64 = -1
    var shifted = neg1 >> 21
    print("Int64(-1) >> 21 =", shifted)  # arithmetic: -1, logical: 0x7FFFFFFFFFFFF
    print("Expected (arithmetic): -1")

    # Also test the floor carry formula:
    var s: Int64 = -356510  # negative limb that needs floor carry
    var c = s >> 21
    print("Int64(-356510) >> 21 =", c)  # arithmetic: -1, logical: large positive
    print("Expected (arithmetic): -1")

    # Balanced carry formula:
    var s2: Int64 = -356510
    var c2 = (s2 + Int64(1 << 20)) >> 21
    print("Int64(-356510 + 2^20) >> 21 =", c2)  # should be 0 for balanced carry
    print("Expected: 0")

    # Test case where balanced carry gives -1:
    var s3: Int64 = -1048577  # just beyond -2^20
    var c3 = (s3 + Int64(1 << 20)) >> 21
    print("Int64(-1048577 + 2^20) >> 21 =", c3)  # should be -1
    print("Expected: -1")
