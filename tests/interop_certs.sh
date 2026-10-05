# Sourced by tests/interop.sh and tests/keyupdate_interop.sh.
# Generates a throwaway PKI in "$WORK" (no keys ever live in the repo):
#   $WORK/ca.pem, ca.key            P-256 test CA
#   $WORK/server.pem, server.key    P-256 leaf for localhost (serverAuth)
#   $WORK/p384.pem, p384.key        P-384 leaf for localhost (serverAuth)
#   $WORK/client.pem, client.key    P-256 client certificate (clientAuth)
# and exports CA_HEX (CA as DER hex), CLIENT_CERT_HEX and CLIENT_KEY_HEX.

_leaf() {  # _leaf <name> <curve> <CN> <extensions>
    openssl ecparam -name "$2" -genkey -noout -out "$WORK/$1.key" 2>/dev/null
    openssl req -new -key "$WORK/$1.key" -subj "/CN=$3" -out "$WORK/$1.csr" 2>/dev/null
    printf '%b' "$4" > "$WORK/$1.ext"
    openssl x509 -req -in "$WORK/$1.csr" -CA "$WORK/ca.pem" -CAkey "$WORK/ca.key" \
        -CAserial "$WORK/ca.srl" -CAcreateserial -days 1 \
        -extfile "$WORK/$1.ext" -out "$WORK/$1.pem" 2>/dev/null
}

openssl ecparam -name prime256v1 -genkey -noout -out "$WORK/ca.key" 2>/dev/null
openssl req -new -x509 -key "$WORK/ca.key" -out "$WORK/ca.pem" -days 1 \
    -subj "/CN=Interop Test CA" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign" 2>/dev/null
_leaf server prime256v1 localhost 'subjectAltName=DNS:localhost\nextendedKeyUsage=serverAuth\n'
_leaf p384 secp384r1 localhost 'subjectAltName=DNS:localhost\nextendedKeyUsage=serverAuth\n'
_leaf client prime256v1 interop-client 'extendedKeyUsage=clientAuth\n'

CA_HEX="$(openssl x509 -in "$WORK/ca.pem" -outform DER | xxd -p | tr -d '\n')"
CLIENT_CERT_HEX="$(openssl x509 -in "$WORK/client.pem" -outform DER | xxd -p | tr -d '\n')"
CLIENT_KEY_HEX="$(openssl ec -in "$WORK/client.key" -noout -text 2>/dev/null \
    | sed -n '/priv:/,/pub:/p' | grep -v 'priv:\|pub:' | tr -d ' :\n' | tail -c 64)"
[ -n "$CA_HEX" ] && [ -n "$CLIENT_KEY_HEX" ] || { echo "interop_certs.sh: certificate generation failed"; exit 1; }
