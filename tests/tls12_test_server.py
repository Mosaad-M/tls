#!/usr/bin/env python3
"""TLS 1.2 test server for connection integration tests.

Usage: python3 tls12_test_server.py PORT CERTFILE KEYFILE [MAX_CONNS] [CIPHER]

Accepts MAX_CONNS connections, responds to any data with an HTTP 200 OK echo,
then closes the connection cleanly. Restricted to TLS 1.2 maximum.

CIPHER: optional OpenSSL cipher string (default: ECDHE-ECDSA-AES128-GCM-SHA256)
"""

import ssl
import socket
import sys


def run_server(
    port: int,
    certfile: str,
    keyfile: str,
    max_conns: int = 1,
    cipher: str = "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256",
) -> None:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(certfile, keyfile)
    try:
        ctx.set_ciphers(cipher)
    except ssl.SSLError as e:
        print(f"Warning: cipher selection failed ({e}), using defaults", flush=True)

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
                try:
                    conn.close()
                except Exception:
                    pass


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 14445
    certfile = sys.argv[2] if len(sys.argv) > 2 else "tests/server.pem"
    keyfile = sys.argv[3] if len(sys.argv) > 3 else "tests/server.key"
    max_conns = int(sys.argv[4]) if len(sys.argv) > 4 else 1
    cipher_arg = sys.argv[5] if len(sys.argv) > 5 else "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256"
    run_server(port, certfile, keyfile, max_conns, cipher_arg)
