# tls — TLS 1.3 and 1.2 client in pure Mojo

A TLS client written entirely in [Mojo](https://www.modular.com/mojo): no OpenSSL, no C
wrappers. The record layer, the handshakes, X.509 path validation and every cryptographic
primitive (AES-GCM, ChaCha20-Poly1305, SHA-2, X25519, P-256/P-384, RSA) are implemented in
this repository.

> **Upgrade to 1.4.3 or later.** Earlier versions did not check that a certificate's
> issuer was a CA, so the holder of any publicly trusted certificate could impersonate
> any host. See [Security status](#security-status) for what is and is not yet hardened.

## Install

With [mojo-pkg](https://github.com/Mosaad-M/mojo-pkg), add the dependency to
`mojoproject.toml`, then install and pass the generated include flags to `mojo`:

```toml
[dependencies]
tls = { git = "Mosaad-M/tls", version = ">=1.4.3" }
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
    def recv_all(mut self, max_size: Int = 16777216) raises -> List[UInt8]  # until close
    def close(mut self) raises                         # sends close_notify, closes the fd

    def negotiated_protocol(self) -> String            # ALPN result (TLS 1.3), or ""
    def session_tickets(self) -> List[SessionTicket]   # tickets received (TLS 1.3)

def load_system_ca_bundle() raises -> List[X509Cert]
```

`load_system_ca_bundle` reads `/etc/ssl/certs/ca-certificates.crt` on Linux and
`/etc/ssl/cert.pem` on macOS (bundles up to 2 MB). Certificates it cannot parse are
skipped. For your own trust anchors, parse DER certificates with `cert_parse` from
`crypto.cert`.

## What it supports

| | TLS 1.3 | TLS 1.2 |
|---|---|---|
| Cipher suites | AES-128-GCM, ChaCha20-Poly1305, AES-256-GCM | ECDHE-RSA and ECDHE-ECDSA with AES-128-GCM or AES-256-GCM |
| Key exchange | X25519 | X25519, P-256 |
| Server signatures | ECDSA P-256 and P-384, RSA-PSS (SHA-256), RSA PKCS#1 v1.5 (SHA-256/384/512) | same |
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
  the subject CN when there are none. A wildcard covers exactly one leftmost label.
- **Algorithms:** RSA (PKCS#1 v1.5 and PSS) and ECDSA (P-256, P-384) certificate
  signatures with SHA-256/384/512. SHA-1 signatures are rejected.

## Security status

This library has not had an external audit. An internal review (October 2026) found the
following, which are **not yet fixed**:

- **Truncation:** `recv_all()` treats an unauthenticated close_notify, or a plain TCP close,
  as the end of the stream, so a network attacker can cut a response short undetected.
  Protocols that carry their own length (such as HTTP `Content-Length`) can detect it.
- **Timing side channels:** AES and GHASH use secret-indexed lookup tables, and P-256
  signing (used only for TLS 1.2 client certificates) uses variable-time arithmetic.
- **Missing protocol checks:** the TLS 1.3 downgrade sentinel, TLS 1.2 extended master
  secret and renegotiation_info, rejection of an all-zero X25519 shared secret, and
  removal of TLS 1.3 record padding.
- **Hostname wildcards** such as `*.com` are not rejected.
- **Robustness:** no socket timeouts, and SIGPIPE is not suppressed.

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
