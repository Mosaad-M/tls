#!/usr/bin/env bash
# KeyUpdate interop against OpenSSL (local, manual; needs OpenSSL >= 1.1.1).
#
# openssl s_server sends a KeyUpdate when a line containing just "k" arrives
# on its stdin, and a KeyUpdate with update_requested for "K". The client
# (tests/keyupdate_client.mojo) must read data sent before and after both
# updates, and its own reply must decrypt on the server ("ping-after-update"
# appears in the server's output).
#
# Usage (from the repo root): pixi run bash tests/keyupdate_interop.sh
# KU_LOG=<file> keeps a copy of the server's -msg log.
set -euo pipefail
PORT="${PORT:-14460}"
WORK="$(mktemp -d)"
trap 'kill "$SERVER" 2>/dev/null || true; cp "$WORK/server.log" "${KU_LOG:-/dev/null}" 2>/dev/null || true; rm -rf "$WORK"' EXIT

source tests/interop_certs.sh

# Build first: the server's stdin lines must arrive one at a time after the
# client has connected, or s_server reads "hello\nk\n" as one chunk of data.
mojo build -I . tests/keyupdate_client.mojo -o "$WORK/keyupdate_client"

{
    sleep 2; echo "hello"
    sleep 1; echo "k"
    sleep 1; echo "after-k"
    sleep 1; echo "K"
    sleep 1; echo "after-K"
    sleep 4
} | openssl s_server -accept "$PORT" -tls1_3 -cert "$WORK/server.pem" -key "$WORK/server.key" \
        -ign_eof -msg > "$WORK/server.log" 2>&1 &
SERVER=$!

sleep 1
kill -0 "$SERVER" 2>/dev/null || { echo "FAIL: s_server did not start (port $PORT busy?)"; exit 1; }
"$WORK/keyupdate_client" "$PORT" "$CA_HEX"
sleep 2
# -msg logs each handshake message: ">>>" sent by the server, "<<<" received.
SENT=$(grep -c ">>> .*KeyUpdate" "$WORK/server.log" || true)
RECEIVED=$(grep -c "<<< .*KeyUpdate" "$WORK/server.log" || true)
if grep -q "ping-after-update" "$WORK/server.log" && [ "$SENT" -ge 2 ] && [ "$RECEIVED" -ge 1 ]; then
    echo "PASS: KeyUpdate interop with $(openssl version): server sent $SENT, client answered $RECEIVED"
else
    echo "FAIL: server log:"; cat "$WORK/server.log"; exit 1
fi
