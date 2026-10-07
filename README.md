# tls — TLS 1.3 and 1.2 client in pure Mojo

A TLS client written entirely in [Mojo](https://www.modular.com/mojo): no OpenSSL, no C
wrappers. The record layer, the handshakes, X.509 path validation and every cryptographic
primitive (AES-GCM, ChaCha20-Poly1305, SHA-2, X25519, P-256/P-384, RSA) are implemented in
this repository.

> **Upgrade to 1.4.4 or later.** Versions before 1.4.3 did not check that a
> certificate's issuer was a CA, so the holder of any publicly trusted certificate could
> impersonate any host. 1.4.4 closes truncation and several protocol-level gaps. See
> [Security status](#security-status) for what is and is not yet hardened.

## Install

With [mojo-pkg](https://github.com/Mosaad-M/mojo-pkg), add the dependency to
`mojoproject.toml`, then install and pass the generated include flags to `mojo`:

```toml
[dependencies]
tls = { git = "Mosaad-M/tls", version = ">=1.7.0" }
tcp = { git = "Mosaad-M/tcp", version = ">=1.1.0" }   # optional: DNS + connect helper
```

```bash
mojo-pkg install
mojo build app.mojo $(cat .mojo_flags)
```

Or clone the repository and build with `-I path/to/tls`.

**Requirements:** Mojo >= 1.0.0, on linux-64 or osx-arm64.

**Using tls with other code.** A Mojo program may declare each C function with
only one signature. Since 1.7.0, tls declares none of the C functions that Mojo's
standard library declares (file I/O, errno, `getenv`, clocks), so it works next to
`open()`, `std.os` and `std.time`. Before 1.7.0, a program that used tls and also
called `open()` failed to compile with "existing function with conflicting
signature". Its socket calls (`recv`, `send`, `setsockopt`, `close`) use the same
signatures as the [tcp](https://github.com/Mosaad-M/tcp) package. If your own code
calls these C functions, declare them the same way: see `tests/test_ffi_compat.mojo`.
Use websocket >= 1.2.0, requests >= 1.3.0 and pg >= 1.6.0 with tls 1.7.0: older
releases declare errno access themselves and clash with it.

## Usage

```mojo
from tcp import TcpSocket
from tls.socket import TlsSocket, load_system_ca_bundle


def main() raises:
    # Parse the system CA bundle once and reuse it for every connection
    var trust_anchors = load_system_ca_bundle()

    var tcp = TcpSocket()
    tcp.connect("example.com", 443)

    # Handshake: negotiates TLS 1.3 or 1.2 and validates the certificate
    # chain and hostname; raises if anything fails
    var tls = TlsSocket(tcp.fd)
    tls.connect("example.com", trust_anchors)

    var request = String(
        "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"
    )
    var bytes = List[UInt8]()
    for b in request.as_bytes():
        bytes.append(b)
    _ = tls.send(bytes)
    # Reads until the server's authenticated close_notify (see below)
    var response = tls.recv_all()
    print(String(unsafe_from_utf8=response^))

    tls.close()
```

`TlsSocket` works on any connected TCP socket file descriptor; the `tcp` package is just a
convenient way to resolve a hostname and connect.

## API

```mojo
struct TlsSocket(Movable):
    def __init__(out self, tcp_fd: Int32 = 0)

    # Handshake (TLS 1.3 or 1.2). Raises on any protocol or validation failure.
    def connect(mut self, hostname: String, trust_anchors: List[X509Cert],
                alpn_protocols: List[String] = List[String]()) raises

    # TLS 1.2 handshake with a P-256 ECDSA client certificate (mTLS).
    # client_cert: DER leaf certificate; client_key: 32-byte P-256 private scalar.
    # Raises if the server negotiates TLS 1.3.
    def connect_with_client_cert(mut self, hostname: String,
                                 trust_anchors: List[X509Cert],
                                 client_cert: List[UInt8], client_key: List[UInt8],
                                 alpn_protocols: List[String] = List[String]()) raises

    def send(mut self, data: List[UInt8]) raises -> Int
    def recv(mut self, max_bytes: Int) raises -> List[UInt8]                # up to max_bytes
    def recv_exact(mut self, n: Int) raises -> List[UInt8]                  # exactly n bytes
    def recv_all(mut self, max_size: Int = 16777216,                       # until close_notify
                 allow_truncation: Bool = False) raises -> List[UInt8]
    def close_notify_received(self) -> Bool            # authenticated end of stream seen
    def set_timeout(mut self, seconds: Int) raises     # receive/send timeout; 0 = none
    def close(mut self) raises                         # sends close_notify, closes the fd

    def negotiated_protocol(self) -> String            # ALPN result (TLS 1.3), or ""
    def session_tickets(self) -> List[SessionTicket]   # tickets received (TLS 1.3)

def load_system_ca_bundle() raises -> List[X509Cert]
```

### End of stream

TLS marks the end of the data with an encrypted `close_notify` alert. A TCP close alone
does not prove the stream is complete, because anyone on the network path can close the
connection. So:

- `recv_all()` returns only after an authenticated `close_notify`. If TCP closes without
  one it raises `tls: truncated: connection closed without close_notify`. Pass
  `allow_truncation=True` to accept that instead, when the protocol carries its own
  lengths (HTTP `Content-Length` or chunked encoding) or for servers that skip
  `close_notify`. In an October 2026 sample of 18 popular sites, Google and YouTube did.
- `recv()` and `recv_exact()` raise `tls: connection closed without close_notify` at a
  bare TCP close, and `tls: close_notify` after an authenticated one.
  `close_notify_received()` tells the two apart.
- A record cut off part-way (`tls: truncated record`), a plaintext alert after the
  handshake, or an alert that fails to decrypt is always an error.

### Timeouts and errors

Sockets from the `tcp` package already have send and receive timeouts (its
`timeout_secs`, 30 s by default); for another file descriptor, call `set_timeout`.

- A receive timeout raises `tls: read timed out`. Nothing is lost: a partly received
  record is kept, so `recv()` can simply be called again.
- A send timeout raises `tls: write timed out`, and a peer that has gone away raises
  `tls: connection closed by peer (write failed)`. Either way part of a record may have
  been sent, so later sends raise `tls: connection broken by an earlier write failure`.
- Writing to a closed connection never raises SIGPIPE, and system calls interrupted by
  a signal (EINTR) are retried.

`load_system_ca_bundle` reads `/etc/ssl/certs/ca-certificates.crt` on Linux and
`/etc/ssl/cert.pem` on macOS (bundles up to 2 MB). Certificates it cannot parse are
skipped. For your own trust anchors, parse DER certificates with `cert_parse` from
`crypto.cert`.

## What it supports

| | TLS 1.3 | TLS 1.2 |
|---|---|---|
| Cipher suites | AES-128-GCM, ChaCha20-Poly1305, AES-256-GCM | ECDHE-RSA and ECDHE-ECDSA with AES-128-GCM or AES-256-GCM |
| Key exchange | X25519; P-256 or P-384 after a HelloRetryRequest | X25519, P-256, P-384 |
| Server signatures | ECDSA P-256 and P-384, RSA-PSS (SHA-256/384/512) | ECDSA (SHA-256/384, either curve), RSA-PSS and RSA PKCS#1 v1.5 (SHA-256/384/512) |
| SNI | yes | yes |
| ALPN | yes | offered; the result is not reported |
| Client certificates | no | P-256 ECDSA |

Not supported: TLS 1.1 and older, CBC or non-ECDHE cipher suites (never offered),
session resumption (tickets are collected but not used), 0-RTT and post-handshake
authentication. TLS 1.3 KeyUpdate is supported in both directions: the client follows
the server's key changes and answers when the server asks it to update its own keys.

### Certificate validation

Every handshake validates the server's chain against the trust anchors you pass, and
there is no option to skip it.

- **Path:** the chain must lead to a trust anchor. A certificate carrying an anchor's key
  counts as the anchor, which handles roots that a server sends cross-signed by an older
  root. Signatures are verified top-down, and only after the path is anchored.
- **Issuers:** must be CAs (basicConstraints `cA`) that may sign certificates
  (`keyCertSign` when keyUsage is present), within their `pathLenConstraint`, with issuer
  and subject names that chain.
- **Leaf:** must allow server authentication (`serverAuth` when extendedKeyUsage is
  present) and signing (`digitalSignature` when keyUsage is present).
- **Validity:** every certificate below the anchor must be within its validity period;
  malformed dates are rejected.
- **Extensions:** certificates with critical extensions that are not processed are
  rejected. This includes `nameConstraints`, which is not enforced.
- **Hostname:** matched case-insensitively against subjectAltName dNSName entries, or
  the subject CN when there are none. A wildcard covers exactly one leftmost label, needs
  at least two labels after it (`*.com` matches nothing), and never matches an IP address.
- **Algorithms:** RSA (PKCS#1 v1.5 and PSS) and ECDSA (P-256, P-384) certificate
  signatures with SHA-256, SHA-384 or SHA-512. SHA-1 signatures are rejected.

## Security status

This library has not had an external audit. Two internal reviews (October 2026) have
been done; every finding is fixed as of 1.6.0, listed below by release. Known
limitations, by design for now: no certificate revocation checking (OCSP/CRL), name
constraints are enforced for DNS and IP names only (chains constraining other name
forms are rejected), no session resumption or 0-RTT, and no client certificates in
TLS 1.3.

Since 1.6.1 every parser that reads bytes from the peer (certificates, handshake
messages, alerts, record reassembly) is fuzzed on each pull request and nightly; see
[Development](#development). The fuzzer, run against 1.5.0, finds the empty-EC-point
crash below within seconds. 1.6.1 also adds SHA-512 signatures and expands each
AES-GCM key once per connection rather than once per record (a 64-byte record went
from 4.9 to 2.9 µs, bulk transfer from 41 to 52 MB/s on an Apple M1 Pro).

1.7.0 makes tls usable alongside Mojo's standard library (see
[Install](#install)). Sockets use `recv`/`send` on every platform. The system CA
bundle is no longer cut off at 2 MB: larger bundles used to lose their last
certificates silently.

Fixed in 1.6.0 (second review, three independent reviewers):
- **Crash:** a certificate with an empty EC public key aborted the process; it could be
  sent by any server, or an attacker on the path, before authentication.
- **Memory exhaustion before authentication:** handshake messages were buffered without
  limit (several GB in seconds). Messages are now capped at 64 KiB and a handshake at
  256 KiB.
- **Strict handshake state machines:** messages are reassembled across records and
  processed in the order RFC 8446 / RFC 5246 require; unexpected, duplicate or
  misplaced messages and ChangeCipherSpec records are fatal. This also fixes servers
  that fragment handshake messages (e.g. facebook.com, instagram.com, and TLS 1.3
  servers with large certificate chains), TLS 1.3 servers that send a
  CertificateRequest, and records that carry ServerHello together with the next
  message.
- **Certificate validation:** nameConstraints are enforced (DNS and IP; they were
  ignored unless marked critical); an intermediate's extendedKeyUsage must allow
  serverAuth; RSA keys must be at least 2048 bits; IP addresses match only iPAddress
  SANs; certificates with unsupported curves, non-minimal DER, trailing data,
  mismatched signature algorithms or impossible dates are rejected.
- **Protocol validation:** ServerHello (version, session ID echo, compression,
  cipher suite, unsolicited extensions), HelloRetryRequest (cookie-only now accepted),
  EncryptedExtensions and ALPN, Certificate and Finished messages, record and alert
  sizes; the ServerKeyExchange signature type must match the cipher suite.
- **Signatures:** RSA signatures must be below the modulus, RSA-PSS padding is checked
  strictly, ECDSA signatures must be minimal DER, ECDSA public keys must be in range.
- **Connection lifecycle:** after a fatal error the connection stays failed (and a
  fatal alert is sent); `close()` can be called twice; post-handshake messages are
  reassembled; at most 8 session tickets are kept; the client updates its keys
  before the AES-GCM record limit; no SNI is sent for IP addresses.
- **TLS 1.2 client certificates** over `*_SHA384` cipher suites signed the wrong hash
  and always failed.

Fixed in 1.5.0:
- **HelloRetryRequest:** a TLS 1.3 server that does not accept X25519 can ask for P-256
  or P-384; the key exchange for both is constant time.
- **TLS 1.2 extended master secret and renegotiation_info** (RFC 7627, RFC 5746) are
  offered; EMS is used when the server agrees, and a non-empty renegotiation_info is
  rejected.
- **TLS 1.2 SHA-384 cipher suites** used the SHA-256 PRF for the master secret, so
  servers that chose `*-AES256-GCM-SHA384` failed the handshake.
- **P-384 ECDSA servers:** the P-384 signature scheme was advertised with the wrong
  codepoint (DSA's), and TLS 1.2 tied the ECDSA hash to the curve, so servers with P-384
  certificates could not connect. secp384r1 is now offered, and P-384 key exchange is
  supported (constant time).

Fixed in 1.4.6:
- **Timing side channels:** AES is bitsliced (no S-box tables), GHASH uses a table-free
  carry-less multiply, and P-256 operations on secrets (key generation, ECDH, ECDSA
  signing; P-384 key exchange since 1.5.0) use fixed-width Montgomery arithmetic,
  complete point formulas and a fixed-length ladder. All three are also faster than before. Remaining primitives were
  already constant time: X25519 (Montgomery ladder), ChaCha20-Poly1305 (no tables),
  tag and Finished comparisons. Signature verification and RSA handle only public data.

Fixed in 1.4.5:
- **KeyUpdate:** a server rotating its TLS 1.3 traffic keys no longer breaks the
  connection; update requests are answered.
- **Socket I/O:** timeouts are reported as such and are resumable for reads; SIGPIPE is
  suppressed; EINTR is retried; `set_timeout()` was added.

Fixed in 1.4.4:
- **Truncation:** only an authenticated `close_notify` ends `recv_all()` (see
  [End of stream](#end-of-stream)). Plaintext or undecryptable alerts after the handshake
  are rejected.
- **Downgrade protection:** the TLS 1.3 downgrade sentinel in a TLS 1.2 ServerHello is
  detected.
- **Key exchange:** an all-zero X25519 shared secret (low-order point) is rejected, as
  are X25519 keys that are not 32 bytes.
- **Record padding:** TLS 1.3 record padding is removed correctly.
- **Signatures:** an out-of-bounds read on malformed RSA PKCS#1 signatures is fixed, and
  PKCS#1 v1.5 is no longer accepted in TLS 1.3 CertificateVerify.
- **Interoperability:** RSA-PSS is supported in TLS 1.2 ServerKeyExchange, and
  rsa_pkcs1_sha512, which could not be verified, is no longer offered.
- **Hostnames:** `*.com`-style wildcards are rejected.

Fixed in 1.4.3: CA constraints in path validation (critical), fail-closed validity
parsing, validity no longer checked above the trust anchor, and no signature checks
before the path is anchored.

## Layout

```
crypto/  primitives and X.509
  aes, gcm, chacha20, poly1305           AEAD ciphers (constant time)
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
`tests/fuzz/crashers/`; commit it with the fix, and `pixi run test` replays it from
then on. CI runs fixed seeds on every pull request and random seeds nightly.

## License

MIT — see [LICENSE](LICENSE).
