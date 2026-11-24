# tls

A TLS 1.3 and 1.2 client in pure [Mojo](https://www.modular.com/mojo): no OpenSSL and no
C wrappers. The record layer, both handshakes, X.509 path validation and every
cryptographic primitive (AES-GCM, ChaCha20-Poly1305, SHA-2, X25519, P-256 and P-384,
RSA) live in this repository.

## Install

With [mojo-pkg](https://github.com/Mosaad-M/mojo-pkg), add the dependency to
`mojoproject.toml`, then install and pass the generated include flags to `mojo`:

```toml
[dependencies]
tls = { git = "Mosaad-M/tls", version = ">=1.12.0" }
tcp = { git = "Mosaad-M/tcp", version = ">=2.0.0" }   # optional: DNS + connect helper
```

```bash
mojo-pkg install
mojo build app.mojo $(cat .mojo_flags)
```

Or clone the repository and build with `-I path/to/tls`. Release history is in
[CHANGELOG.md](CHANGELOG.md).

Requires Mojo >= 1.2.0 on linux-64 or osx-arm64. CI runs the tests on Mojo 1.2.0 and on
the newest Mojo release.

### Using tls with other code

A Mojo program may declare each C function with only one signature. tls declares none
of the C functions that Mojo's standard library declares, so it works next to `open()`,
`std.os` and `std.time`. Its socket calls match tcp's; if your own code calls them, see
`tests/test_ffi_compat.mojo`. Use websocket >= 1.2.0, requests >= 1.3.0 and pg >= 1.6.0
with it.

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
    # chain and hostname; raises if anything fails. detach() hands the
    # socket over: since tcp 2.0.0 a TcpSocket closes its fd when destroyed,
    # and the TlsSocket now owns and closes it.
    var tls = TlsSocket(tcp.detach())
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

`TlsSocket` works on any connected TCP socket file descriptor. The `tcp` package is just
a convenient way to resolve a hostname and connect.

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
    def set_timeout_ms(mut self, ms: Int) raises       # same, in milliseconds (kernel tick, a few ms)
    def close(mut self) raises                         # sends close_notify, closes the fd

    def negotiated_protocol(self) -> String            # ALPN result (TLS 1.2 and 1.3), or ""
    def session_tickets(self) -> List[SessionTicket]   # tickets received (TLS 1.3)

def load_system_ca_bundle() raises -> List[X509Cert]
def load_ca_bundle(path: String) raises -> List[X509Cert]   # any PEM file
```

### End of stream

TLS marks the end of the data with an encrypted `close_notify` alert. A TCP close alone
does not prove the stream is complete, because anyone on the network path can close the
connection. So:

- `recv_all()` returns only after an authenticated `close_notify`. If TCP closes without
  one it raises `tls: truncated: connection closed without close_notify`. Pass
  `allow_truncation=True` to accept that when the protocol carries its own lengths (HTTP
  `Content-Length` or chunked encoding) or the server skips `close_notify`. In an
  October 2026 sample of 18 popular sites, Google and YouTube skipped it.
- `recv()` and `recv_exact()` raise `tls: connection closed without close_notify` at a
  bare TCP close, and `tls: close_notify` after an authenticated one.
  `close_notify_received()` tells the two apart.
- A record cut off part-way (`tls: truncated record`), a plaintext alert after the
  handshake, or an alert that fails to decrypt is always an error.

### Timeouts and errors

Sockets from the `tcp` package already have send and receive timeouts (its
`timeout_secs`, 30 s by default). For another file descriptor, call `set_timeout`.
`set_timeout_ms` does the same in milliseconds: a 200 ms receive timeout
fires after about 200 ms, and a huge value means "very long" instead of wrapping.

- A receive timeout raises `tls: read timed out`. Nothing is lost: a partly received
  record is kept, so you can call `recv()` again.
- A send timeout raises `tls: write timed out`, and a peer that has gone away raises
  `tls: connection closed by peer (write failed)`. Either way part of a record may have
  been sent, so later sends raise `tls: connection broken by an earlier write failure`.
- Writing to a closed connection never raises SIGPIPE, and system calls interrupted by a
  signal (EINTR) are retried.

### Trust anchors

`load_system_ca_bundle` reads the file named by `$SSL_CERT_FILE` when it is set (a missing
file raises). Otherwise it reads `/etc/ssl/cert.pem` on macOS and, on Linux, the first of
`/etc/ssl/certs/ca-certificates.crt` (Debian, Ubuntu), `/etc/pki/tls/certs/ca-bundle.crt`
(Fedora, RHEL), `/etc/ssl/ca-bundle.pem` (openSUSE) and `/etc/ssl/cert.pem` (Alpine) that
exists. `load_ca_bundle(path)` does the same for any PEM file. Certificates it cannot
parse are skipped. For your own trust anchors, parse DER certificates with `cert_parse`
from `crypto.cert`.

macOS's `/etc/ssl/cert.pem` is a trimmed export of the system keychain and lacks some
roots, such as Comodo's AAA Certificate Services, which cross-signs the chain of
`example.com`. A site whose chain ends at a missing root fails with `cert_chain_verify:
chain not trusted (no path to a trust anchor)`, although curl, which reads the keychain,
connects. Set `SSL_CERT_FILE` to a fuller bundle, such as Mozilla's.

## What it supports

| | TLS 1.3 | TLS 1.2 |
|---|---|---|
| Cipher suites | AES-128-GCM, ChaCha20-Poly1305, AES-256-GCM | ECDHE-RSA and ECDHE-ECDSA with AES-128-GCM or AES-256-GCM |
| Key exchange | X25519; P-256 or P-384 after a HelloRetryRequest | X25519, P-256, P-384 |
| Server signatures | ECDSA P-256 and P-384, RSA-PSS (SHA-256/384/512) | ECDSA (SHA-256/384, either curve), RSA-PSS and RSA PKCS#1 v1.5 (SHA-256/384/512) |
| SNI | yes | yes |
| ALPN | yes | yes |
| Client certificates | no | P-256 ECDSA |

Not supported: TLS 1.1 and older, CBC and non-ECDHE cipher suites (never offered),
session resumption (tickets are collected but not used), 0-RTT and post-handshake
authentication. TLS 1.3 KeyUpdate works in both directions: the client follows the
server's key changes and answers when the server asks it to update its own keys.

### Certificate validation

Every handshake validates the server's chain against the trust anchors you pass. There is
no option to skip it.

- Path: the chain must lead to a trust anchor. A certificate carrying an anchor's key
  counts as the anchor, which handles roots that a server sends cross-signed by an older
  root. Signatures are verified top-down, and only after the path is anchored.
- Issuers: must be CAs (basicConstraints `cA`) that may sign certificates (`keyCertSign`
  when keyUsage is present), within their `pathLenConstraint`, with issuer and subject
  names that chain. An intermediate's extendedKeyUsage must allow serverAuth.
- Leaf: must allow server authentication (`serverAuth` when extendedKeyUsage is present)
  and signing (`digitalSignature` when keyUsage is present).
- Validity: every certificate below the anchor must be within its validity period, and
  malformed dates are rejected. Certificates above the anchor are ignored, so an expired
  cross-sign does not break a valid chain.
- Extensions: certificates with critical extensions that are not processed are rejected,
  including `policyConstraints` and `inhibitAnyPolicy`. `nameConstraints` are enforced for
  DNS and IP names, and a chain constraining other name forms is rejected.
- Hostname: matched case-insensitively against subjectAltName dNSName entries, or the
  subject CN when there are none. A wildcard covers exactly one leftmost label, needs at
  least two labels after it (`*.com` matches nothing), and never matches an IP address.
  IP addresses match only iPAddress SANs, and no SNI is sent for them.
- Algorithms: RSA (PKCS#1 v1.5 and PSS) and ECDSA (P-256, P-384) certificate signatures
  with SHA-256, SHA-384 or SHA-512. RSA keys must be at least 2048 bits. SHA-1
  signatures are rejected, and so are unsupported curves, non-minimal DER, trailing data
  and mismatched signature algorithms.

## Security status

No external audit has been done. Two internal reviews in October 2026 (the second by
three independent reviewers) produced findings that were all fixed. Known limits: no certificate revocation checking (OCSP or CRL), no session resumption or 0-RTT,
and no client certificates in TLS 1.3.

Every parser that reads bytes from the peer (certificates, handshake messages, alerts,
record reassembly) is fuzzed on each pull request and nightly; see
[CONTRIBUTING.md](CONTRIBUTING.md). Every fix, by release, is in [CHANGELOG.md](CHANGELOG.md).

## Performance

On an Apple M1 Pro against a local `openssl s_server`, tls receives at 1.2 GB/s (level with
Python's OpenSSL client) and sends at 1.8 GB/s (Python: 1.3 GB/s). A TLS 1.3 handshake takes
1.1 ms with an ECDSA certificate and 1.7 ms with RSA-2048 (Python: 0.94 and 1.6 ms).
Handshakes with real sites are bound by network round trips. Tables and methods are in
[BENCHMARKS.md](BENCHMARKS.md).

## Development

```bash
pixi run test               # unit tests (run in CI on Linux and macOS)
pixi run test-interop       # handshakes against openssl s_server (also run in CI)
pixi run fuzz 20000 1 2     # fuzz every parser: <inputs per target> <seeds...>
```

The other tasks, the test certificates, the fuzzer and the source layout are described in
[CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT, see [LICENSE](LICENSE).
