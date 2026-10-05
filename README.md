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
tls = { git = "Mosaad-M/tls", version = ">=1.4.4" }
tcp = { git = "Mosaad-M/tcp", version = ">=1.1.0" }   # optional: DNS + connect helper
```

```bash
mojo-pkg install
mojo build app.mojo $(cat .mojo_flags)
```

Or clone the repository and build with `-I path/to/tls`.

**Requirements:** Mojo >= 1.0.0, on linux-64 or osx-arm64.

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

`load_system_ca_bundle` reads `/etc/ssl/certs/ca-certificates.crt` on Linux and
`/etc/ssl/cert.pem` on macOS (bundles up to 2 MB). Certificates it cannot parse are
skipped. For your own trust anchors, parse DER certificates with `cert_parse` from
`crypto.cert`.

## What it supports

| | TLS 1.3 | TLS 1.2 |
|---|---|---|
| Cipher suites | AES-128-GCM, ChaCha20-Poly1305, AES-256-GCM | ECDHE-RSA and ECDHE-ECDSA with AES-128-GCM or AES-256-GCM |
| Key exchange | X25519 | X25519, P-256 |
| Server signatures | ECDSA P-256 and P-384, RSA-PSS (SHA-256/384) | same, plus RSA PKCS#1 v1.5 (SHA-256/384) |
| SNI | yes | yes |
| ALPN | yes | offered; the result is not reported |
| Client certificates | no | P-256 ECDSA |

Not supported: TLS 1.1 and older, CBC or non-ECDHE cipher suites (never offered),
HelloRetryRequest (a TLS 1.3 server that does not accept X25519 fails the handshake),
session resumption (tickets are collected but not used), 0-RTT, KeyUpdate and
post-handshake authentication.

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
  signatures with SHA-256 or SHA-384. SHA-1 and SHA-512 signatures are rejected.

## Security status

This library has not had an external audit. An internal review (October 2026) found the
following, which are **not yet fixed**:

- **Timing side channels:** AES and GHASH use secret-indexed lookup tables, and P-256
  signing (used only for TLS 1.2 client certificates) uses variable-time arithmetic.
- **TLS 1.2 extensions:** extended master secret (RFC 7627) and renegotiation_info are
  not sent or checked.
- **Robustness:** no socket timeouts, and SIGPIPE is not suppressed.

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
  aes, gcm, chacha20, poly1305           AEAD ciphers
  hash (SHA-256/384/512), sha1, hmac, hkdf, prf (TLS 1.2 PRF)
  curve25519, p256, p384, rsa, bigint, ed25519 (not used by TLS)
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
pixi run bench              # primitive benchmarks
mojo run -I . -I <path to tcp> tests/live_sites.mojo   # real sites + badssl.com (network)
```

The three local-server tests need certificates: run `bash tests/gen_test_certs.sh` and
paste the printed CA hex into the test files as the script describes.
`tests/gen_path_fixtures.sh` regenerates the path-validation fixtures.

## License

MIT — see [LICENSE](LICENSE).
