# Changelog

Release history for tls. The README describes the current behaviour.

## Releases

- 1.12.0: `set_timeout_ms`.
- 1.11.0: reads the ALPN protocol from a TLS 1.2 ServerHello (`negotiated_protocol()`
  used to report "" there), honours `SSL_CERT_FILE`, tries the other Linux bundle paths,
  and adds `load_ca_bundle(path)`.
- 1.10.0: builds on Mojo 1.2.0, which is now the floor. On Mojo 1.0 or 1.1, use 1.9.1.
- 1.7.0: tls works next to Mojo's standard library (see "Using tls with other code" in the
  README). Before this, a program that used tls and called `open()` failed to compile with
  "existing function with conflicting signature". Sockets use `recv` and `send` on every
  platform. The system CA bundle is no longer cut off at 2 MB; larger bundles
  used to lose their last certificates silently.

## Security fixes by release

Use 1.4.4 or later. Before 1.4.3, tls did not check that a certificate's issuer was a CA,
so the holder of any publicly trusted certificate could impersonate any host.

- 1.6.0: a certificate with an empty EC public key aborted the process (the fuzzer finds it on 1.5.0 within seconds), and any server or
  attacker on the path could send one before authentication. Handshake messages were
  buffered without limit (several GB in seconds); they are now capped at 64 KiB each and
  256 KiB per handshake. Handshake state machines are strict: messages are reassembled
  across records and processed in the order RFC 8446 and RFC 5246 require, and unexpected,
  duplicate or misplaced messages and ChangeCipherSpec records are fatal. That also fixes
  servers that fragment handshake messages (facebook.com, instagram.com, TLS 1.3 servers
  with large chains), servers that send a CertificateRequest, and records that carry
  ServerHello together with the next message. Certificate and protocol validation was
  tightened (ServerHello, HelloRetryRequest, EncryptedExtensions, ALPN, Finished, record
  and alert sizes; the ServerKeyExchange signature type must match the cipher suite).
  Signature checks became strict: RSA signatures below the modulus, strict RSA-PSS
  padding, minimal-DER ECDSA signatures, in-range ECDSA public keys. After a fatal
  error the connection stays failed and sends a fatal alert; `close()` can be called
  twice; post-handshake messages are reassembled; at most 8 session tickets are kept;
  the client updates its keys before the AES-GCM record limit. TLS 1.2 client
  certificates over `*_SHA384` suites signed the wrong hash and always failed.
- 1.5.0: HelloRetryRequest support (a server that does not accept X25519 can ask for
  P-256 or P-384, constant time). TLS 1.2 offers extended master secret and
  renegotiation_info (RFC 7627, RFC 5746), uses EMS when the server agrees, and rejects a
  non-empty renegotiation_info. TLS 1.2 SHA-384 suites used the SHA-256 PRF for the master
  secret, so `*-AES256-GCM-SHA384` servers failed the handshake. The P-384 signature
  scheme was advertised with DSA's codepoint and TLS 1.2 tied the ECDSA hash to the
  curve, so servers with P-384 certificates could not connect; secp384r1 is now offered
  and P-384 key exchange is constant time.
- 1.4.6: AES is bitsliced (no S-box tables), GHASH uses a table-free carry-less multiply,
  and P-256 operations on secrets (key generation, ECDH, signing; P-384 key exchange
  since 1.5.0) use fixed-width Montgomery arithmetic, complete point formulas and a
  fixed-length ladder. X25519, ChaCha20-Poly1305 and the tag and Finished comparisons
  were already constant time. Signature verification and RSA handle only public data.
- 1.4.5: a server rotating its TLS 1.3 traffic keys (KeyUpdate) no longer breaks the
  connection. Socket timeouts are reported as such and are resumable for reads, SIGPIPE
  is suppressed, EINTR is retried, and `set_timeout()` was added.
- 1.4.4: only an authenticated `close_notify` ends `recv_all()`, and plaintext or
  undecryptable alerts after the handshake are rejected. The TLS 1.3 downgrade sentinel
  in a TLS 1.2 ServerHello is detected. An all-zero X25519 shared secret and X25519 keys
  that are not 32 bytes are rejected. TLS 1.3 record padding is removed correctly. An
  out-of-bounds read on malformed RSA PKCS#1 signatures is fixed, and PKCS#1 v1.5 is no
  longer accepted in TLS 1.3 CertificateVerify. RSA-PSS works in TLS 1.2
  ServerKeyExchange, `rsa_pkcs1_sha512` (which could not be verified) is no longer
  offered, and `*.com`-style wildcards are rejected.
- 1.4.3: CA constraints in path validation (critical), fail-closed validity parsing,
  validity no longer checked above the trust anchor, and no signature checks before the
  path is anchored.

## Performance work

- 1.9.0: signature verification was nearly the whole cost of a handshake (20 ms for
  ECDSA, 38 ms for RSA in 1.8.2). Elliptic-curve arithmetic now uses 64-bit Montgomery
  limbs (key generation, ECDH and signing too, which stay constant time; verification
  adds Shamir's trick), and RSA uses Montgomery exponentiation on 64-bit limbs. Handshakes with real servers fell from 123-457 ms to 25-40 ms (www.google.com 220 to 40 ms, github.com 139 to 36, www.wikipedia.org 285 to 40, www.debian.org 457 to 35, www.apple.com 123 to 25). RSA-2048 / RSA-4096 verify went from 36.5 / 134.6 ms to 0.08 / 0.32 ms, P-256 ECDSA verify from 18.5 to 0.24 ms, and P-256 key generation, ECDH and signing from 2.9-3.0 ms to 0.27-0.29 ms. A handshake with an ECDSA P-256 certificate took 20.0 ms before and 1.1 ms after, and with RSA-2048 38.1 ms before and 1.7 ms after.
- 1.8.2: ChaCha20 computes 16 blocks per step on SIMD vectors, Poly1305 uses 44-bit
  limbs and absorbs two blocks per step, and the AEAD streams AAD, ciphertext and
  lengths into Poly1305 and seals and opens records in place. All of it is portable
  Mojo with no intrinsics, constant time, and the same on ARM and x86. ChaCha20-Poly1305
  went from 37 MB/s to 930 MB/s. TLS 1.2 records are built whole in one buffer.
- 1.8.1: AES-GCM runs AES-CTR and GHASH in one pass over each 128-byte group, and GHASH
  folds eight blocks per reduction (3.2 GB/s alone, now 11 GB/s). Records are decrypted
  where they arrive and sealed in place, and `send` no longer copies each record byte by
  byte (AES-256-GCM seal / open 1.8 / 1.9 to 4.8 / 4.5 GB/s; `recv(64 KiB)` loop 1,007 to 1,230 MB/s; `recv_all` 719 to 1,140 MB/s; `send(16 KiB)` loop 446 to 1,790 MB/s; `recv_exact(5)` + `recv_exact(59)` 0.21 to 0.16 us). A record that fails authentication leaves nothing behind: its plaintext is zeroed
  and never reaches `recv`.
- 1.8.0: AES-GCM runs on the CPU's AES and carry-less-multiply instructions where the
  build target has them (ARMv8 crypto extension, x86 AES-NI with PCLMULQDQ). They take
  the same time whatever the key and data, so this path is constant time like the
  software one that other targets still use (`-D TLS_SOFT_AES=true` forces it). The
  receive path no longer copies byte by byte or rebuilds its buffer on every read.
  `recv_all` was quadratic before (1 MB/s) because it reallocated its result for every
  record, and `recv_exact(n)` no longer reserves `n` bytes before the data arrives. With hardware AES, `recv(64 KiB)` went from 34 MB/s (1.7.0) to 1,007 MB/s and `recv_all` from 1 MB/s to 719 MB/s; `recv_exact(5)` + `recv_exact(59)` from 22 us to 0.21 us. The software AES path runs at 49-50 MB/s (`recv_exact` 1.4 us). Python's OpenSSL client reached 1,277 MB/s on the `recv(64 KiB)` loop.
- 1.6.1: AES-GCM expands each key once per connection instead of once per record, and
  adds SHA-512 signatures. A 64-byte record went from 4.9 to 2.9 us, and bulk transfer from 41 to 52 MB/s.
