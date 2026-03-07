#!/usr/bin/env python3
"""TLS 1.3 test server for connection integration tests.

Usage: python3 tls_test_server.py PORT CERTFILE KEYFILE [MAX_CONNS]

Accepts MAX_CONNS connections, responds to HTTP requests with HTTP/1.1 200 OK,
handles SSL errors gracefully (e.g., when client disconnects after cert verify failure).
"""

import ssl
import socket
import sys


def run_server(port: int, certfile: str, keyfile: str, max_conns: int = 1) -> None:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(certfile, keyfile)
    # Restrict to SHA-256 ciphersuites so client's SHA-256-only key schedule works.
    try:
        ctx.set_ciphers("TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256")
    except ssl.SSLError:
        pass

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("127.0.0.1", port))
        sock.listen(max_conns)
        sock.settimeout(30)

        for _ in range(max_conns):
            try:
                conn, _ = sock.accept()
            except (socket.timeout, OSError):
                break

            try:
                with ctx.wrap_socket(conn, server_side=True) as tls:
                    tls.settimeout(10)
                    try:
                        data = tls.recv(4096)
                        if data:
                            tls.sendall(
                                b"HTTP/1.1 200 OK\r\n"
                                b"Content-Length: 2\r\n"
                                b"Connection: close\r\n"
                                b"\r\n"
                                b"OK"
                            )
                    except Exception:
                        pass
            except Exception:
                # TLS error: client likely disconnected (cert verify failure etc.)
                try:
                    conn.close()
                except Exception:
                    pass


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 14443
    certfile = sys.argv[2] if len(sys.argv) > 2 else "tests/server.pem"
    keyfile = sys.argv[3] if len(sys.argv) > 3 else "tests/server.key"
    max_conns = int(sys.argv[4]) if len(sys.argv) > 4 else 1
    run_server(port, certfile, keyfile, max_conns)
