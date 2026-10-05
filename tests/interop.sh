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

echo
if [ "$FAILURES" -gt 0 ]; then
    echo "$FAILURES scenario(s) failed"
    exit 1
fi
echo "all scenarios passed"
