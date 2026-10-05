#!/usr/bin/env python3
"""Hostile TLS peers for tests/interop.sh (the "hostile" scenarios).

Each mode misbehaves in one way the October 2026 security review found the
client mishandling. The client must fail cleanly (an error, never a crash or
unbounded memory) - except "coalesce", which is legitimate and must succeed.

Usage: hostile_server.py MODE PORT [ARG]

  flood     ServerHello, then endless handshake messages (no limit in 1.5.0:
            ~6 GB of client memory in 3 s). Prints "sent N bytes" when the
            client hangs up; the test requires N to stay far below the
            64 MB cap (N includes what the kernel's socket buffers absorb,
            a few MB on Linux).
  bigmsg    ServerHello, then a Certificate claiming 16 MB, streamed slowly.
  badsh     ServerHello with an unoffered cipher, compression 1 and an
            unsolicited extension.
  crashcert ServerHello + a certificate whose EC point is empty (ARG: DER hex
            file), in a complete server flight. tls 1.5.0 aborted the process
            on it; it must now be a clean parse error.
  inject    proxy to ARG (an s_server port), injecting an unknown handshake
            message after ServerHello.
  dropccs   proxy to ARG, dropping the server's ChangeCipherSpec and sending
            a junk application_data record instead.
  coalesce  proxy to ARG, merging ServerHello and the next handshake record
            into one record (legal; 1.5.0 failed on it).
"""
import os
import socket
import struct
import sys
import threading
import time


def recv_exact(s, n):
    b = b""
    while len(b) < n:
        c = s.recv(n - len(b))
        if not c:
            raise EOFError
        b += c
    return b


def read_rec(s):
    h = recv_exact(s, 5)
    return h, recv_exact(s, struct.unpack(">H", h[3:5])[0])


def rec(t, body):
    return bytes([t, 3, 3]) + struct.pack(">H", len(body)) + body


def hs(t, body):
    return bytes([t]) + len(body).to_bytes(3, "big") + body


def server_hello(cipher=0xC02F, comp=0, exts=b""):
    body = b"\x03\x03" + os.urandom(32) + b"\x00" + struct.pack(">H", cipher) + bytes([comp])
    body += struct.pack(">H", len(exts)) + exts
    return hs(2, body)


def send_until_closed(c, chunk, limit=64 << 20):
    """Send chunk repeatedly until the client hangs up (or 64 MB, so a
    regressed client fails the test without exhausting the machine)."""
    sent = 0
    try:
        while sent < limit:
            c.sendall(chunk)
            sent += len(chunk)
    except OSError:
        pass
    print("sent %d bytes" % sent, flush=True)


def proxy(c, upstream_port, mode):
    up = socket.create_connection(("127.0.0.1", upstream_port))

    def client_to_server():
        try:
            while True:
                d = c.recv(65536)
                if not d:
                    break
                up.sendall(d)
        except OSError:
            pass

    threading.Thread(target=client_to_server, daemon=True).start()
    first = True
    try:
        while True:
            h, b = read_rec(up)
            if mode == "dropccs" and h[0] == 20:
                c.sendall(rec(23, os.urandom(40)))
                continue
            if mode == "coalesce" and h[0] == 22 and first:
                first = False
                h2, b2 = read_rec(up)
                if h2[0] == 22:
                    c.sendall(rec(22, b + b2))
                else:
                    c.sendall(h + b + h2 + b2)
                continue
            c.sendall(h + b)
            if mode == "inject" and h[0] == 22 and first:
                first = False
                c.sendall(rec(22, hs(0x63, b"")))
    except (EOFError, OSError):
        pass


def main():
    mode, port = sys.argv[1], int(sys.argv[2])
    ls = socket.socket()
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind(("127.0.0.1", port))
    ls.listen(1)
    ls.settimeout(60)
    c, _ = ls.accept()
    if mode in ("inject", "dropccs", "coalesce"):
        proxy(c, int(sys.argv[3]), mode)
        return
    read_rec(c)  # ClientHello
    if mode == "flood":
        c.sendall(rec(22, server_hello()))
        send_until_closed(c, rec(22, hs(0x63, b"") * 4096))
    elif mode == "bigmsg":
        c.sendall(rec(22, server_hello()))
        header = hs(11, b"")[:1] + (16 * 1024 * 1024 - 1).to_bytes(3, "big")
        c.sendall(rec(22, header))
        send_until_closed(c, rec(22, b"\x00" * 16000))
    elif mode == "badsh":
        c.sendall(rec(22, server_hello(cipher=0x0000, comp=1, exts=struct.pack(">HH", 0x0010, 0))))
        time.sleep(2)
    elif mode == "crashcert":
        cert = bytes.fromhex(open(sys.argv[3]).read().strip())
        certmsg = hs(11, (len(cert) + 3).to_bytes(3, "big") + len(cert).to_bytes(3, "big") + cert)
        # Certificate, a placeholder ServerKeyExchange, ServerHelloDone: the
        # whole flight, so the client gets as far as parsing the certificate
        ske = hs(0x0C, b"\x03\x00\x17\x00\x04\x03\x00\x00")
        c.sendall(rec(22, server_hello()) + rec(22, certmsg + ske + hs(0x0E, b"")))
        time.sleep(2)
    else:
        sys.exit("unknown mode " + mode)


if __name__ == "__main__":
    main()
