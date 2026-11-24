# Benchmarks

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
