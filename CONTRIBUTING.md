# Contributing

## Layout

```
crypto/  primitives and X.509
  aes, gcm, chacha20, poly1305           AEAD ciphers (constant time)
  aes_hw                                 AES-GCM on AES-NI/PCLMULQDQ or ARMv8 AES/PMULL
  hash (SHA-256/384/512), sha1, hmac, hkdf, prf (TLS 1.2 PRF)
  curve25519, p256, p384, ec_ct (constant-time P-256/P-384), rsa, bigint, ed25519 (not used by TLS)
  asn1, pem, base64, cert                X.509 parsing and path validation
  random                                 OS randomness (/dev/urandom)
  record, handshake                      record protection, TLS 1.3 key schedule
tls/     protocol
  socket                                 TlsSocket, the public API
  connection, connection12               TLS 1.3 and 1.2 handshakes
  message, message12                     handshake message encoding and parsing
```

## Development

```bash
pixi run test               # unit tests (run in CI on Linux and macOS)
pixi run test-connection    # TLS 1.3 against a local Python server
pixi run test-connection12  # TLS 1.2 against a local Python server
pixi run test-socket        # TlsSocket against a local Python server
pixi run test-interop       # handshakes against openssl s_server (also run in CI)
pixi run bench              # primitive benchmarks
pixi run bench-io           # TLS send/receive throughput against openssl s_server (AES-GCM paths + ChaCha20)
pixi run bench-handshake    # handshake latency against openssl s_server (ECDSA/RSA, TLS 1.3/1.2) vs Python
pixi run test-soft-aes      # tests on the software AES-GCM path (also in CI)
pixi run fuzz 20000 1 2     # fuzz every parser: <inputs per target> <seeds...>
pixi run ct-check           # dudect-style timing-leak check (manual; noisy)
mojo run -I . -I <path to tcp> tests/live_sites.mojo   # real sites + badssl.com (network)
```

The three local-server tests need certificates: run `bash tests/gen_test_certs.sh` and
paste the printed CA hex into the test files as the script describes.
`tests/gen_path_fixtures.sh` and `tests/gen_sha512_fixtures.sh` regenerate the
certificate fixtures.

The fuzzer (`tests/fuzz/fuzz_parsers.mojo`) mutates valid inputs, structure-aware for
DER, and feeds them to each parser. Raising is fine; an out-of-bounds read aborts the
process through Mojo's bounds checks. `pixi run fuzz` saves a crashing input to
`tests/fuzz/crashers/`. Commit it with the fix, and `pixi run test` replays it from then
on. CI runs fixed seeds on every pull request and random seeds nightly.
