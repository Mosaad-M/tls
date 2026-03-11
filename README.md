# tls — Pure Mojo TLS 1.3 + 1.2

A pure-[Mojo](https://www.modular.com/mojo) implementation of TLS 1.3 and TLS 1.2.
No OpenSSL, no C wrappers — every cryptographic primitive is implemented in Mojo.

## Features

- **TLS 1.3** (RFC 8446) and **TLS 1.2** (RFC 5246) client
- Auto-negotiates version from server's ServerHello
- **Cipher suites**: AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305
- **Key exchange**: X25519, P-256 (ECDHE), P-384 (ECDHE)
- **Signatures**: RSA-PSS, RSA-PKCS#1, ECDSA (P-256, P-384)
- **Certificate verification**: full chain validation, hostname verification, validity dates
- **Hash**: SHA-256, SHA-384, SHA-1 (legacy certs only)
- Loads system CA bundle (`/etc/ssl/certs/ca-certificates.crt`)
- 245 unit tests across 31 modules

## Module Structure

```
crypto/          Cryptographic primitives
  hash.mojo      SHA-256, SHA-384, SHA-1
  hmac.mojo      HMAC
  hkdf.mojo      HKDF key derivation
  aes.mojo       AES block cipher
  gcm.mojo       AES-GCM with 4-bit GHASH table
  chacha20.mojo  ChaCha20 stream cipher
  poly1305.mojo  Poly1305 MAC
  curve25519.mojo X25519 key exchange
  bigint.mojo    Constant-time big integer arithmetic
  p256.mojo      NIST P-256 (ECDHE, ECDSA)
  p384.mojo      NIST P-384 (ECDHE, ECDSA)
  rsa.mojo       RSA-PKCS#1 and RSA-PSS verification
  asn1.mojo      ASN.1 DER parser
  cert.mojo      X.509 certificate parsing and verification
  pem.mojo       PEM decoder
  base64.mojo    Base64 encoder/decoder
  random.mojo    Cryptographically secure random bytes (via getrandom)
  record.mojo    TLS record-layer seal/open
  handshake.mojo TLS 1.3 key schedule and handshake helpers
  prf.mojo       TLS 1.2 PRF (HMAC-SHA256/SHA384)

tls/             TLS protocol layer
  socket.mojo    TlsSocket — main public API
  connection.mojo    TLS 1.3 handshake state machine
  connection12.mojo  TLS 1.2 handshake state machine
  message.mojo       TLS 1.3 message builders/parsers
  message12.mojo     TLS 1.2 message builders/parsers
```

## Requirements

- [Mojo](https://www.modular.com/mojo) >= 0.26.1
- [pixi](https://pixi.sh) (dependency manager)
- Linux x86-64

## Installation

```bash
git clone https://github.com/Mosaad-M/tls
cd tls
pixi install
```

## Usage

```mojo
from tcp import TcpSocket          # your TCP socket (or any fd)
from tls.socket import TlsSocket, load_system_ca_bundle

fn main() raises:
    # Load system CA bundle once (parses /etc/ssl/certs/ca-certificates.crt)
    var trust_anchors = load_system_ca_bundle()

    # Connect TCP
    var tcp = TcpSocket()
    tcp.connect("example.com", 443)

    # Perform TLS handshake (auto-negotiates TLS 1.3 or 1.2)
    var tls = TlsSocket(tcp.fd)
    tls.connect("example.com", trust_anchors)

    # Send data
    var req = List[UInt8]()
    # ... populate req with HTTP request bytes ...
    _ = tls.send(req)

    # Receive data
    var response = tls.recv_all()

    tls.close()
```

### TlsSocket API

```mojo
struct TlsSocket(Movable):
    fn __init__(out self, tcp_fd: Int32 = 0)
    fn connect(mut self, hostname: String, trust_anchors: List[X509Cert]) raises
    fn send(mut self, data: List[UInt8]) raises -> Int
    fn recv(mut self, max_bytes: Int) raises -> List[UInt8]
    fn recv_exact(mut self, n: Int) raises -> List[UInt8]
    fn recv_all(mut self, max_size: Int = 16*1024*1024) raises -> List[UInt8]
    fn close(mut self) raises

fn load_system_ca_bundle() raises -> List[X509Cert]
```

`connect()` auto-negotiates TLS 1.3 or TLS 1.2 based on the server's ServerHello.
Certificate chain validation and hostname verification are always performed.

## Running Tests

```bash
pixi run test-hash       # SHA-256, SHA-384, SHA-1  (13 tests)
pixi run test-hmac       # HMAC                     (17 tests)
pixi run test-hkdf       # HKDF                     (8 tests)
pixi run test-aes        # AES                      (7 tests)
pixi run test-gcm        # AES-GCM                  (11 tests)
pixi run test-chacha20   # ChaCha20                 (3 tests)
pixi run test-poly1305   # Poly1305                 (6 tests)
pixi run test-curve25519 # X25519                   (5 tests)
pixi run test-bigint     # Big integer arithmetic   (24 tests)
pixi run test-p256       # P-256                    (6 tests)
pixi run test-p384       # P-384                    (6 tests)
pixi run test-rsa        # RSA                      (6 tests)
pixi run test-asn1       # ASN.1 parser             (9 tests)
pixi run test-cert       # X.509 certificates       (6 tests)
pixi run test-base64     # Base64                   (10 tests)
pixi run test-pem        # PEM decoder              (4 tests)
pixi run test-record     # TLS record layer         (7 tests)
pixi run test-handshake  # TLS 1.3 key schedule     (15 tests)
pixi run test-connection # TLS 1.3 handshake        (2 tests)
pixi run test-socket     # TlsSocket integration    (4 tests)
pixi run test-alert      # Alert handling           (5 tests)
pixi run test-message    # TLS 1.3 messages         (12 tests)
pixi run test-message12  # TLS 1.2 messages         (8 tests)
pixi run test-record12   # TLS 1.2 record layer     (6 tests)
pixi run test-connection12 # TLS 1.2 handshake      (5 tests)
pixi run test-prf        # TLS 1.2 PRF              (8 tests)
pixi run test-random     # CSPRNG                   (5 tests)
pixi run test-sha1       # SHA-1                    (5 tests)
pixi run test-hkdf-sha384     # HKDF-SHA384         (3 tests)
pixi run test-cert-sha384     # SHA-384 certs        (7 tests)
pixi run test-cert-hostname   # Hostname verification (7 tests)
pixi run test-cert-chain      # Certificate chains   (5 tests)
```

245 tests total.

## Security Notes

- Constant-time big integer arithmetic (Montgomery ladder for EC scalar multiply, binary extended GCD for field inversion)
- Sequence number overflow guards (threshold 2^62)
- Maximum record size enforced (16384 bytes send, 16640 bytes receive)
- Alert handling per RFC 8446 §6

## License

MIT — see [LICENSE](LICENSE)
