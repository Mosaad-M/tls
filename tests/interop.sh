#!/usr/bin/env bash
# Interop scenarios against `openssl s_server` (needs OpenSSL 3.x, e.g. the
# one in the pixi environment; runs in CI). Certificates are generated per
# run by tests/interop_certs.sh.
#
# Each scenario starts s_server with specific settings and checks, from the
# -www status page, that the handshake succeeded with the expected protocol,
# cipher and parameters.
#
# Usage (from the repo root): pixi run bash tests/interop.sh
set -uo pipefail
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
PORT=14470
FAILURES=0

mojo build -I . tests/interop_client.mojo -o "$WORK/client" >/dev/null
source tests/interop_certs.sh

# scenario <name> <page checks> <client args...> -- <s_server args...>
# <page checks>: strings that must all appear in the -www status page,
# separated by ";;" (e.g. "New, TLSv1.2, Cipher is X;;Shared groups: secp256r1").
scenario() {
    local name="$1" checks="$2"
    shift 2
    local client_args=()
    while [ "$1" != "--" ]; do client_args+=("$1"); shift; done
    shift
    PORT=$((PORT + 1))
    openssl s_server -accept "$PORT" -cert "${CERT:-$WORK/server.pem}" -key "${KEY:-$WORK/server.key}" \
        -www "$@" > "$WORK/server.log" 2>&1 &
    local server=$!
    sleep 1
    if ! kill -0 "$server" 2>/dev/null; then
        echo "FAIL: $name (s_server did not start; port $PORT busy?)"
        sed 's/^/    server: /' "$WORK/server.log" | head -3
        FAILURES=$((FAILURES + 1))
        return
    fi
    "$WORK/client" "$PORT" "$CA_HEX" ${client_args[@]+"${client_args[@]}"} > "$WORK/page.txt" 2>&1
    local rc=$?
    kill "$server" 2>/dev/null; wait "$server" 2>/dev/null
    local ok=1
    [ $rc -eq 0 ] || ok=0
    local rest="$checks"
    while [ -n "$rest" ]; do
        local check="${rest%%;;*}"
        if [ "$check" = "$rest" ]; then rest=""; else rest="${rest#*;;}"; fi
        grep -qF -- "$check" "$WORK/page.txt" || { ok=0; echo "    missing: $check"; }
    done
    if [ $ok -eq 1 ]; then
        echo "PASS: $name"
    else
        echo "FAIL: $name (client exit $rc)"
        grep -E "^New,|Shared groups|Extended master|Unhandled|Error" "$WORK/page.txt" | sed 's/^/    client: /' | head -5
        FAILURES=$((FAILURES + 1))
    fi
}

scenario "TLS 1.2, P-256 ECDHE (constant-time ECDH)" \
    "New, TLSv1.2, Cipher is ECDHE-ECDSA-AES128-GCM-SHA256;;Shared groups: secp256r1" \
    -- -tls1_2 -groups P-256
scenario "TLS 1.2 mTLS, P-256 client certificate (constant-time ECDSA signing)" \
    "New, TLSv1.2, Cipher is;;CN=interop-client" "$CLIENT_CERT_HEX" "$CLIENT_KEY_HEX" \
    -- -tls1_2 -Verify 1 -CAfile "$WORK/ca.pem"
scenario "TLS 1.3, X25519, AES-128-GCM" "New, TLSv1.3, Cipher is TLS_AES_128_GCM_SHA256" \
    -- -tls1_3 -ciphersuites TLS_AES_128_GCM_SHA256
scenario "TLS 1.3, X25519, AES-256-GCM" "New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384" \
    -- -tls1_3 -ciphersuites TLS_AES_256_GCM_SHA384
scenario "TLS 1.3, X25519, ChaCha20-Poly1305" "New, TLSv1.3, Cipher is TLS_CHACHA20_POLY1305_SHA256" \
    -- -tls1_3 -ciphersuites TLS_CHACHA20_POLY1305_SHA256
scenario "TLS 1.2, ECDHE-ECDSA-AES128-GCM-SHA256" "New, TLSv1.2, Cipher is ECDHE-ECDSA-AES128-GCM-SHA256" \
    -- -tls1_2 -cipher ECDHE-ECDSA-AES128-GCM-SHA256

# ── Protocol completeness (1.5.0) ───────────────────────────────────────────
scenario "TLS 1.3 HelloRetryRequest to P-256 (server has no X25519)" \
    "New, TLSv1.3, Cipher is;;Shared groups: secp256r1" \
    -- -tls1_3 -groups P-256
scenario "TLS 1.3 HelloRetryRequest to P-384" \
    "New, TLSv1.3, Cipher is;;Shared groups: secp384r1" \
    -- -tls1_3 -groups P-384
scenario "TLS 1.2, P-384 ECDHE (constant-time ECDH)" \
    "New, TLSv1.2, Cipher is ECDHE-ECDSA;;Shared groups: secp384r1" \
    -- -tls1_2 -groups P-384
scenario "TLS 1.2 ECDHE-ECDSA-AES256-GCM-SHA384 (SHA-384 PRF)" \
    "New, TLSv1.2, Cipher is ECDHE-ECDSA-AES256-GCM-SHA384" \
    -- -tls1_2 -cipher ECDHE-ECDSA-AES256-GCM-SHA384
CERT="$WORK/p384.pem" KEY="$WORK/p384.key" scenario "TLS 1.3, P-384 ECDSA server certificate" \
    "New, TLSv1.3, Cipher is" \
    -- -tls1_3
CERT="$WORK/p384.pem" KEY="$WORK/p384.key" scenario "TLS 1.2, P-384 ECDSA server certificate" \
    "New, TLSv1.2, Cipher is ECDHE-ECDSA" \
    -- -tls1_2
scenario "TLS 1.2 extended master secret negotiated" \
    "New, TLSv1.2, Cipher is;;Extended master secret: yes" \
    -- -tls1_2
scenario "TLS 1.2 without extended master secret (server -no_ems)" \
    "New, TLSv1.2, Cipher is;;Extended master secret: no" \
    -- -tls1_2 -no_ems

# ── Security review fixes (1.6.0) ───────────────────────────────────────────
scenario "TLS 1.3 handshake messages fragmented across records" \
    "New, TLSv1.3, Cipher is" \
    -- -tls1_3 -max_send_frag 512 -cert_chain "$WORK/ca.pem"
scenario "TLS 1.3 CertificateRequest answered with an empty Certificate" \
    "New, TLSv1.3, Cipher is;;no client certificate available" \
    -- -tls1_3 -verify 1
scenario "TLS 1.2 mTLS over ECDHE-ECDSA-AES256-GCM-SHA384" \
    "New, TLSv1.2, Cipher is ECDHE-ECDSA-AES256-GCM-SHA384;;CN=interop-client" "$CLIENT_CERT_HEX" "$CLIENT_KEY_HEX" \
    -- -tls1_2 -cipher ECDHE-ECDSA-AES256-GCM-SHA384 -Verify 1 -CAfile "$WORK/ca.pem"

# ── SHA-512 signatures (1.6.1): RSA-2048 leaf signed ecdsa-with-SHA512, and
# s_server restricted to one SHA-512 handshake signature scheme ─────────────
CERT="$WORK/rsa.pem" KEY="$WORK/rsa.key" scenario "TLS 1.3 rsa_pss_rsae_sha512 CertificateVerify" \
    "New, TLSv1.3, Cipher is" \
    -- -tls1_3 -sigalgs rsa_pss_rsae_sha512
CERT="$WORK/rsa.pem" KEY="$WORK/rsa.key" scenario "TLS 1.2 rsa_pkcs1_sha512 ServerKeyExchange" \
    "New, TLSv1.2, Cipher is ECDHE-RSA" \
    -- -tls1_2 -sigalgs RSA+SHA512
CERT="$WORK/rsa.pem" KEY="$WORK/rsa.key" scenario "TLS 1.2 rsa_pss_rsae_sha512 ServerKeyExchange" \
    "New, TLSv1.2, Cipher is ECDHE-RSA" \
    -- -tls1_2 -sigalgs rsa_pss_rsae_sha512

# ── Receive path (1.8.0): 32 MiB from s_server -WWW, three receive styles ─────
# Every byte is checked; the time limits catch quadratic copying (1.7.0's
# recv_all ran at ~1 MB/s, small reads at ~22 us per message).
BULK_SIZE=$((32 * 1024 * 1024))
mkdir -p "$WORK/www"
python3 -c "
import sys
block = bytes(i % 251 for i in range(251))
n = $BULK_SIZE
sys.stdout.buffer.write((block * (n // 251 + 1))[:n])" > "$WORK/www/bulk.bin"
bulk() {  # bulk <mode> <max seconds>
    PORT=$((PORT + 1))
    (cd "$WORK/www" && exec openssl s_server -accept "$PORT" -cert "$WORK/server.pem" -key "$WORK/server.key" \
        -WWW -quiet) > "$WORK/bulk_server.log" 2>&1 &
    local server=$!
    sleep 1
    if "$WORK/client" "$PORT" "$CA_HEX" --bulk /bulk.bin "$BULK_SIZE" "$1" "$2" > "$WORK/bulk.txt" 2>&1; then
        echo "PASS: 32 MiB download, $1 ($(grep -o '[0-9]* MB/s' "$WORK/bulk.txt"))"
    else
        echo "FAIL: 32 MiB download, $1"
        tail -3 "$WORK/bulk.txt" | sed 's/^/    client: /'
        FAILURES=$((FAILURES + 1))
    fi
    kill "$server" 2>/dev/null; wait "$server" 2>/dev/null
}
bulk recv_all 2
bulk recv 2
bulk small 4

# hostile <name> <mode> <expect> [upstream s_server args...]
# expect: "ok:<page check>" (handshake must succeed) or "fail:<error text>"
# (the client must exit with a clean error: status 1, not an abort).
# flood/bigmsg must also make the client hang up after < 16 MB (the count
# includes kernel socket buffers, ~0.6 MB on macOS and ~2.7 MB on Linux;
# an unbounded client would take all 64 MB the server sends).
hostile() {
    local name="$1" mode="$2" expect="$3"
    shift 3
    PORT=$((PORT + 1))
    local hport=$PORT arg="" upstream=""
    if [ $# -gt 0 ]; then
        PORT=$((PORT + 1))
        openssl s_server -accept "$PORT" -cert "$WORK/server.pem" -key "$WORK/server.key" \
            -www "$@" > "$WORK/server.log" 2>&1 &
        upstream=$!
        arg=$PORT
        sleep 1
    fi
    [ "$mode" = "crashcert" ] && arg="tests/crash_cert.hex"
    python3 tests/hostile_server.py "$mode" "$hport" $arg > "$WORK/hostile.log" 2>&1 &
    local hs=$!
    sleep 1
    "$WORK/client" "$hport" "$CA_HEX" > "$WORK/page.txt" 2>&1
    local rc=$?
    sleep 0.5
    kill "$hs" 2>/dev/null; wait "$hs" 2>/dev/null
    [ -n "$upstream" ] && { kill "$upstream" 2>/dev/null; wait "$upstream" 2>/dev/null; }
    local ok=1 detail=""
    case "$expect" in
        ok:*) [ $rc -eq 0 ] && grep -qF -- "${expect#ok:}" "$WORK/page.txt" || { ok=0; detail="expected success"; } ;;
        fail:*) [ $rc -eq 1 ] && grep -qF -- "${expect#fail:}" "$WORK/page.txt" || { ok=0; detail="expected a clean error containing '${expect#fail:}' (exit $rc)"; } ;;
    esac
    if grep -q "^sent " "$WORK/hostile.log"; then
        local sent; sent=$(sed -n 's/^sent \([0-9]*\) bytes/\1/p' "$WORK/hostile.log")
        [ "$sent" -lt 16000000 ] || { ok=0; detail="client accepted $sent bytes before giving up"; }
        detail="$detail (server sent $sent bytes)"
    fi
    if [ $ok -eq 1 ]; then
        echo "PASS: hostile: $name $detail"
    else
        echo "FAIL: hostile: $name: $detail"
        tail -3 "$WORK/page.txt" | sed 's/^/    client: /'
        FAILURES=$((FAILURES + 1))
    fi
}

hostile "endless handshake messages after ServerHello" flood "fail:unexpected_message"
hostile "16 MB Certificate message" bigmsg "fail:handshake message too large"
hostile "bad ServerHello (cipher, compression, extension)" badsh "fail:illegal_parameter"
hostile "malformed certificate (empty EC point; aborted 1.5.0)" crashcert "fail:asn1:"
hostile "unknown handshake message injected" inject "fail:unexpected_message" -tls1_2
hostile "server CCS dropped, junk application data" dropccs "fail:ChangeCipherSpec" -tls1_2
hostile "ServerHello coalesced with the next message (legal)" coalesce "ok:New, TLSv1.2, Cipher is" -tls1_2

echo
if [ "$FAILURES" -gt 0 ]; then
    echo "$FAILURES scenario(s) failed"
    exit 1
fi
echo "all scenarios passed"
