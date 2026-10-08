#!/usr/bin/env bash
# TLS receive benchmarks against openssl s_server -WWW serving a 256 MiB
# file, and a send benchmark against a second s_server that discards its
# input, for the hardware and the software AES-GCM path.
# Usage (from the repo root): pixi run bench-io
set -uo pipefail
WORK="$(mktemp -d)"
PORT=19611
SINK_PORT=19612
cleanup() {
    [ -n "${SRV:-}" ] && kill "$SRV" 2>/dev/null
    [ -n "${SINK:-}" ] && kill "$SINK" 2>/dev/null
    rm -rf "$WORK"
}
trap cleanup EXIT
openssl ecparam -name prime256v1 -genkey -noout -out "$WORK/key.pem" 2>/dev/null
openssl req -x509 -new -key "$WORK/key.pem" -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost" -days 1 -out "$WORK/cert.pem" 2>/dev/null
CA_HEX="$(openssl x509 -in "$WORK/cert.pem" -outform DER | xxd -p | tr -d '\n')"
mkdir -p "$WORK/www"
head -c $((256 * 1024 * 1024)) /dev/zero > "$WORK/www/big.bin"
(cd "$WORK/www" && exec openssl s_server -accept "$PORT" -cert "$WORK/cert.pem" \
    -key "$WORK/key.pem" -WWW -quiet) > /dev/null 2>&1 &
SRV=$!
# The send benchmark's server discards what it receives. Its stdin is a
# FIFO held open by this shell, so it never sees EOF. A fresh one serves
# each run: s_server does not always go back to accept() after a client.
mkfifo "$WORK/in"
exec 3<> "$WORK/in"
start_sink() {
    openssl s_server -accept "$SINK_PORT" -cert "$WORK/cert.pem" \
        -key "$WORK/key.pem" -quiet < "$WORK/in" > /dev/null 2>&1 &
    SINK=$!
}
sleep 1
echo "TLS 1.3 benchmarks (openssl s_server, loopback):"
for flags in "" "-D TLS_SOFT_AES=true"; do
    mojo build $flags -I . bench/bench_tls_io.mojo -o "$WORK/bench" > /dev/null 2>&1 || { echo "build failed"; exit 1; }
    start_sink
    sleep 1
    "$WORK/bench" "$PORT" "$CA_HEX" "$SINK_PORT"
    kill "$SINK" 2>/dev/null
    wait "$SINK" 2>/dev/null
done
