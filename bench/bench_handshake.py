# Python (OpenSSL) side of bench/bench_handshake.sh
import socket, ssl, sys, time
port, ca, n = int(sys.argv[1]), sys.argv[2], int(sys.argv[3])
ctx = ssl.create_default_context(cafile=ca)
best = 1e9; t0 = time.perf_counter()
for _ in range(n):
    t1 = time.perf_counter()
    s = ctx.wrap_socket(socket.create_connection(("127.0.0.1", port)), server_hostname="localhost")
    best = min(best, time.perf_counter() - t1)
    s.close()
print(f"  python: avg {(time.perf_counter()-t0)/n*1000:.2f} ms/handshake, best {best*1000:.2f} ms ")
