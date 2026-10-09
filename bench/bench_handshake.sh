#!/usr/bin/env bash
# TLS handshake latency against openssl s_server: ECDSA P-256 and RSA-2048
# certificates, TLS 1.3 and 1.2; Python's ssl module (OpenSSL) for reference.
# Usage (from the repo root): pixi run bench-handshake [count]
set -u
N=${1:-200}
W="$(mktemp -d)"
trap 'rm -rf "$W"' EXIT
mojo build -I . bench/bench_handshake.mojo -o "$W/hs" > /dev/null 2>&1 || { echo "build failed"; exit 1; }
cp bench/bench_handshake.py "$W/hs.py"
cd "$W"
openssl ecparam -name prime256v1 -genkey -noout -out ec.key 2>/dev/null
openssl req -x509 -new -key ec.key -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost" -days 1 -out ec.pem 2>/dev/null
openssl req -x509 -newkey rsa:2048 -nodes -keyout rsa.key -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost" -days 1 -out rsa.pem 2>/dev/null
for kind in ec rsa; do
  for ver in -tls1_3 -tls1_2; do
    PORT=19700
    openssl s_server -accept $PORT -cert $kind.pem -key $kind.key $ver -quiet -naccept $((2*N+10)) </dev/null >/dev/null 2>&1 &
    SRV=$!; sleep 0.5
    echo "== $kind cert, $ver"
    ./hs $PORT "$(openssl x509 -in $kind.pem -outform DER | xxd -p | tr -d '\n')" $N
    python3 hs.py $PORT $kind.pem $N
    kill $SRV 2>/dev/null; wait $SRV 2>/dev/null
    true
  done
done
