#!/usr/bin/env bash
# Interop scenarios against `openssl s_server` (local; needs OpenSSL 3.x,
# e.g. the one in the pixi environment).
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
CA_HEX="$(openssl x509 -in tests/ca.pem -outform DER | xxd -p | tr -d '\n')"

# P-256 client certificate signed by the test CA (generated per run)
openssl ecparam -name prime256v1 -genkey -noout -out "$WORK/client.key" 2>/dev/null
openssl req -new -key "$WORK/client.key" -subj "/CN=interop-client" -out "$WORK/client.csr" 2>/dev/null
printf 'extendedKeyUsage=clientAuth\n' > "$WORK/client.ext"
openssl x509 -req -in "$WORK/client.csr" -CA tests/ca.pem -CAkey tests/ca.key \
    -CAserial "$WORK/ca.srl" -CAcreateserial \
    -days 1 -extfile "$WORK/client.ext" -out "$WORK/client.pem" 2>/dev/null
CLIENT_CERT_HEX="$(openssl x509 -in "$WORK/client.pem" -outform DER | xxd -p | tr -d '\n')"
CLIENT_KEY_HEX="$(openssl ec -in "$WORK/client.key" -noout -text 2>/dev/null \
    | sed -n '/priv:/,/pub:/p' | grep -v 'priv:\|pub:' | tr -d ' :\n' | tail -c 64)"

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
    openssl s_server -accept "$PORT" -cert "${CERT:-tests/server.pem}" -key "${KEY:-tests/server.key}" \
        -www "$@" > "$WORK/server.log" 2>&1 &
    local server=$!
    sleep 1
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
    -- -tls1_2 -Verify 1 -CAfile tests/ca.pem
scenario "TLS 1.3, X25519, AES-128-GCM" "New, TLSv1.3, Cipher is TLS_AES_128_GCM_SHA256" \
    -- -tls1_3 -ciphersuites TLS_AES_128_GCM_SHA256
scenario "TLS 1.3, X25519, AES-256-GCM" "New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384" \
    -- -tls1_3 -ciphersuites TLS_AES_256_GCM_SHA384
scenario "TLS 1.3, X25519, ChaCha20-Poly1305" "New, TLSv1.3, Cipher is TLS_CHACHA20_POLY1305_SHA256" \
    -- -tls1_3 -ciphersuites TLS_CHACHA20_POLY1305_SHA256
scenario "TLS 1.2, ECDHE-ECDSA-AES128-GCM-SHA256" "New, TLSv1.2, Cipher is ECDHE-ECDSA-AES128-GCM-SHA256" \
    -- -tls1_2 -cipher ECDHE-ECDSA-AES128-GCM-SHA256

echo
if [ "$FAILURES" -gt 0 ]; then
    echo "$FAILURES scenario(s) failed"
    exit 1
fi
echo "all scenarios passed"
