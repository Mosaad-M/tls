#!/bin/bash
# Generate test certificates for TLS unit tests.
#
# Produces:
#   tests/ca.key         CA private key (keep local, never commit)
#   tests/ca.pem         CA certificate (self-signed)
#   tests/server.pem     Server cert for CN=localhost, signed by CA
#   tests/server.key     Server private key (keep local, never commit)
#   tests/wronghost.pem  Server cert for CN=wronghost.com, signed by CA
#   tests/wronghost.key  Server private key for wronghost (never commit)
#
# After running this script, update CA_DER_HEX in:
#   tests/test_connection.mojo
#   tests/test_connection12.mojo
#   tests/test_socket.mojo
# with the hex printed at the end of this script.
#
# Usage: bash tests/gen_test_certs.sh
#   (run from the repo root)

set -e
cd "$(dirname "$0")"

# ── CA ─────────────────────────────────────────────────────────────────────
openssl ecparam -name prime256v1 -genkey -noout -out ca.key

openssl req -new -x509 -key ca.key -out ca.pem -days 1826 \
    -subj "/CN=TLS Test CA" \
    -addext "basicConstraints=critical,CA:TRUE"

# ── server cert (CN=localhost) ─────────────────────────────────────────────
openssl ecparam -name prime256v1 -genkey -noout -out server.key

openssl req -new -key server.key -out server.csr -subj "/CN=localhost"

openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key \
    -CAcreateserial -out server.pem -days 1826 \
    -extfile <(printf "subjectAltName=DNS:localhost\n")

# ── wronghost cert (CN=wronghost.com) ──────────────────────────────────────
openssl ecparam -name prime256v1 -genkey -noout -out wronghost.key

openssl req -new -key wronghost.key -out wronghost.csr -subj "/CN=wronghost.com"

openssl x509 -req -in wronghost.csr -CA ca.pem -CAkey ca.key \
    -CAcreateserial -out wronghost.pem -days 1826 \
    -extfile <(printf "subjectAltName=DNS:wronghost.com\n")

# ── cleanup ────────────────────────────────────────────────────────────────
rm -f server.csr wronghost.csr ca.srl

echo ""
echo "=== New CA_DER_HEX (update in test_connection.mojo, test_connection12.mojo, test_socket.mojo) ==="
openssl x509 -in ca.pem -outform DER | xxd -p | tr -d '\n'
echo ""
echo ""
echo "Done. DO NOT commit ca.key, server.key, or wronghost.key."
