# tls

A TLS 1.3 and 1.2 client in pure [Mojo](https://www.modular.com/mojo): no OpenSSL and no
C wrappers. The record layer, both handshakes, X.509 path validation and every
cryptographic primitive (AES-GCM, ChaCha20-Poly1305, SHA-2, X25519, P-256 and P-384,
RSA) live in this repository.

Do not use versions before 1.4.4. Before 1.4.3, tls did not check that a certificate's
issuer was a CA, so the holder of any publicly trusted certificate could impersonate any
host, and 1.4.4 closed truncation and several protocol gaps. See
[Security status](#security-status).

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
the newest Mojo release. For Mojo 1.0 or 1.1, use tls 1.9.1.

### Using tls with other code

A Mojo program may declare each C function with only one signature. Since 1.7.0, tls
declares none of the C functions that Mojo's standard library declares (file I/O, errno,
`getenv`, clocks), so it works next to `open()`, `std.os` and `std.time`. Before 1.7.0, a
program that used tls and called `open()` failed to compile with "existing function with
conflicting signature". The socket calls (`recv`, `send`, `setsockopt`, `close`) use the
same signatures as the [tcp](https://github.com/Mosaad-M/tcp) package. If your own code
calls these C functions, declare them the same way: see `tests/test_ffi_compat.mojo`.
With tls 1.7.0 or later, use websocket >= 1.2.0, requests >= 1.3.0 and pg >= 1.6.0;
older releases declare errno access themselves and clash.

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
three independent reviewers) produced findings that were all fixed by 1.6.0. Known
limits: no certificate revocation checking (OCSP or CRL), no session resumption or 0-RTT,
and no client certificates in TLS 1.3.

Since 1.6.1, every parser that reads bytes from the peer (certificates, handshake
messages, alerts, record reassembly) is fuzzed on each pull request and nightly; see
[Development](#development). Run against 1.5.0, the fuzzer finds the empty-EC-point crash
within seconds. Every fix, by release, is in [CHANGELOG.md](CHANGELOG.md).

## Performance

Measured on an Apple M1 Pro against a local `openssl s_server` (`pixi run bench-io`,
`pixi run bench-handshake`), with Python's OpenSSL client alongside.

| Throughput (TLS 1.3, AES-256-GCM unless noted) | tls | Python (OpenSSL) |
|---|---|---|
| `recv(64 KiB)` loop | 1,230 MB/s | 1,160-1,260 MB/s |
| `recv_all` | 1,140 MB/s | |
| `send(16 KiB)` loop | 1,790 MB/s | 1,340 MB/s |
| `recv_exact(5)` + `recv_exact(59)` | 0.16 us | |
| AES-256-GCM, 16 KiB, seal / open | 4.8 / 4.5 GB/s | |
| ChaCha20-Poly1305, 16 KiB, seal / open | 930 / 935 MB/s | |
| `recv` loop over ChaCha20-Poly1305 | 735-746 MB/s | 695-732 MB/s |

| Handshake | tls | Python (OpenSSL) |
|---|---|---|
| ECDSA P-256 cert (TLS 1.3) | 1.1 ms | 0.94 ms |
| RSA-2048 cert (TLS 1.3) | 1.7 ms | 1.6 ms |
| RSA-2048 / RSA-4096 verify | 0.08 / 0.32 ms | |
| P-256 ECDSA verify | 0.24 ms | |
| P-256 key generation / ECDH / signing | 0.27-0.29 ms | |

Handshakes with real servers, best of 5 over the network from the same machine:

| | tls | Python (OpenSSL) |
|---|---|---|
| www.google.com | 40 ms | 40 ms |
| github.com | 36 ms | 40 ms |
| www.wikipedia.org | 40 ms | 42 ms |
| www.debian.org | 35 ms | 32 ms |
| www.apple.com | 25 ms | 24 ms |

Connecting is bound by network round trips, as it is for OpenSSL. In these benchmarks
receiving runs at the same speed as Python's client, with about the same CPU time per
megabyte.

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

## License

MIT, see [LICENSE](LICENSE).
