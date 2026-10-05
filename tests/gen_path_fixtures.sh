#!/usr/bin/env bash
# Generate the certificate fixtures for tests/test_cert_path.mojo.
#
# Builds a small PKI with OpenSSL (>= 3.4 for -not_before/-not_after) in a
# temporary directory and writes tests/path_fixtures.mojo: one comptime DER
# hex constant per certificate. Only certificates are written out; private
# keys stay in the temporary directory and are deleted.
#
# Usage (from the repo root): bash tests/gen_path_fixtures.sh
set -euo pipefail

OUT="$(cd "$(dirname "$0")" && pwd)/path_fixtures.mojo"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"

LONG_START="20250101000000Z"
LONG_END="21250101000000Z"   # fixtures stay valid for a century

# P-256 keys, except names starting with rsa<bits>_ (e.g. rsa1024_leaf)
key() {
    case "$1" in
        rsa[0-9]*_*) openssl genrsa -out "$1.key" "$(echo "$1" | sed 's/^rsa\([0-9]*\)_.*/\1/')" 2>/dev/null ;;
        *) openssl ecparam -name prime256v1 -genkey -noout -out "$1.key" 2>/dev/null ;;
    esac
}

# self_signed <name> <CN> <extensions>
self_signed() {
    key "$1"
    printf '%b' "$3" > "$1.ext"
    openssl req -new -key "$1.key" -subj "/CN=$2" -out "$1.csr" 2>/dev/null
    openssl x509 -req -in "$1.csr" -key "$1.key" -out "$1.pem" \
        -not_before "$LONG_START" -not_after "$LONG_END" -extfile "$1.ext" 2>/dev/null
}

# issue <name> <CN> <issuer> <extensions> [not_before] [not_after] [existing key]
issue() {
    if [ -n "${7:-}" ]; then cp "$7.key" "$1.key"; else key "$1"; fi
    printf '%b' "$4" > "$1.ext"
    openssl req -new -key "$1.key" -subj "/CN=$2" -out "$1.csr" 2>/dev/null
    openssl x509 -req -in "$1.csr" -CA "$3.pem" -CAkey "$3.key" -CAcreateserial \
        -out "$1.pem" -not_before "${5:-$LONG_START}" -not_after "${6:-$LONG_END}" \
        -extfile "$1.ext" 2>/dev/null
}

CA='basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n'
leaf_ext() { printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:%s\n' "$1"; }

# ── Trust anchor and a normal intermediate ──────────────────────────────────
self_signed root "Path Test Root" "$CA"
issue inter "Path Test Intermediate" root "$CA"
issue leaf_ok "ok.example" inter "$(leaf_ext ok.example)"
issue leaf_direct "direct-root.example" root "$(leaf_ext direct-root.example)"

# ── The exploit: a CA:FALSE leaf used to sign another host's cert ──────────
issue evil "evil.example" inter "$(leaf_ext evil.example)"
issue bank "bank.example" evil "subjectAltName=DNS:bank.example\n"

# ── Issuers that are not allowed to issue ───────────────────────────────────
issue inter_nobc "No BasicConstraints" root "keyUsage=critical,keyCertSign\n"
issue leaf_nobc "nobc.example" inter_nobc "$(leaf_ext nobc.example)"
issue inter_ku "KeyUsage Without CertSign" root \
    'basicConstraints=critical,CA:TRUE\nkeyUsage=critical,digitalSignature\n'
issue leaf_ku "ku.example" inter_ku "$(leaf_ext ku.example)"

# ── pathLenConstraint ───────────────────────────────────────────────────────
issue inter_pl0 "PathLen Zero" root 'basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign\n'
issue sub_pl0 "Below PathLen Zero" inter_pl0 "$CA"
issue leaf_pl0_deep "deep.example" sub_pl0 "$(leaf_ext deep.example)"
issue leaf_pl0 "direct.example" inter_pl0 "$(leaf_ext direct.example)"

# ── Leaf key usage / extended key usage ─────────────────────────────────────
issue leaf_client "client.example" inter \
    'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\nsubjectAltName=DNS:client.example\n'
issue leaf_noeku "noeku.example" inter 'subjectAltName=DNS:noeku.example\n'
issue leaf_kenc "kenc.example" inter \
    'keyUsage=critical,keyEncipherment\nsubjectAltName=DNS:kenc.example\n'

# ── Critical extensions we do not process ───────────────────────────────────
issue inter_crit "Unknown Critical" root "${CA}1.2.3.4=critical,ASN1:NULL\n"
issue leaf_crit "crit.example" inter_crit "$(leaf_ext crit.example)"
issue inter_noncrit "Unknown NonCritical" root "${CA}1.2.3.4=ASN1:NULL\n"
issue leaf_noncrit "noncrit.example" inter_noncrit "$(leaf_ext noncrit.example)"
issue inter_nc "Name Constrained" root "${CA}nameConstraints=critical,permitted;DNS:nc.example\n"
issue leaf_nc "nc.example" inter_nc "$(leaf_ext nc.example)"

# ── Issuer/subject name mismatch with a valid signature ─────────────────────
# inter_alt reuses inter's key under another name; a leaf it issues verifies
# against inter's key, but its issuer name is not inter's subject.
issue inter_alt "Different Name Same Key" root "$CA" "" "" inter
issue leaf_dn "dn.example" inter_alt "$(leaf_ext dn.example)"

# ── Validity periods ────────────────────────────────────────────────────────
issue leaf_expired "expired.example" inter "$(leaf_ext expired.example)" \
    "20200101000000Z" "20210101000000Z"
issue inter_future "Not Yet Valid" root "$CA" "21000101000000Z" "$LONG_END"
issue leaf_future "future.example" inter_future "$(leaf_ext future.example)"

# Expired cross-sign above the anchor: new_root is trusted; the chain also
# carries an expired copy of new_root's key signed by old_root.
self_signed new_root "Path New Root" "$CA"
self_signed old_root "Path Old Root" "$CA"
issue cross_expired "Path New Root" old_root "$CA" "20200101000000Z" "20210101000000Z" new_root
issue inter_x "Path Cross Intermediate" new_root "$CA"
issue leaf_x "cross.example" inter_x "$(leaf_ext cross.example)"

# ── Unanchored chain (root not in the trust store) ──────────────────────────
self_signed stray_root "Stray Root" "$CA"
issue stray_inter "Stray Intermediate" stray_root "$CA"
issue stray_leaf "stray.example" stray_inter "$(leaf_ext stray.example)"

# ── Name constraints (enforced whether or not critical) ─────────────────────
issue inter_ncd "NC DNS NonCritical" root "${CA}nameConstraints=permitted;DNS:allowed.example\n"
issue leaf_ncd_ok "www.allowed.example" inter_ncd "$(leaf_ext www.allowed.example)"
issue leaf_ncd_bad "victim.example" inter_ncd "$(leaf_ext victim.example)"
issue inter_ncx "NC DNS Excluded" root "${CA}nameConstraints=critical,excluded;DNS:bad.example\n"
issue leaf_ncx_ok "good.example" inter_ncx "$(leaf_ext good.example)"
issue leaf_ncx_bad "x.bad.example" inter_ncx "$(leaf_ext x.bad.example)"
issue leaf_ncx_wild "wild.example" inter_ncx "$(leaf_ext '*.bad.example')"
issue inter_ncip "NC IP" root "${CA}nameConstraints=critical,permitted;IP:10.0.0.0/255.0.0.0\n"
issue leaf_ncip_ok "ip-ok" inter_ncip 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=IP:10.1.2.3\n'
issue leaf_ncip_bad "ip-bad" inter_ncip 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=IP:192.168.1.1\n'
issue inter_ncemail "NC Email" root "${CA}nameConstraints=permitted;email:.example.com\n"
issue leaf_ncemail "mail.example" inter_ncemail "$(leaf_ext mail.example)"

# ── extendedKeyUsage on intermediates ───────────────────────────────────────
issue inter_eku_email "EKU Email CA" root "${CA}extendedKeyUsage=emailProtection\n"
issue leaf_eku_email "ekuemail.example" inter_eku_email "$(leaf_ext ekuemail.example)"
issue inter_eku_server "EKU Server CA" root "${CA}extendedKeyUsage=serverAuth\n"
issue leaf_eku_server "ekuserver.example" inter_eku_server "$(leaf_ext ekuserver.example)"

# ── RSA key sizes (minimum 2048 bits) ───────────────────────────────────────
issue rsa1024_leaf "rsa1024.example" inter "$(leaf_ext rsa1024.example)"
issue rsa2048_leaf "rsa2048.example" inter "$(leaf_ext rsa2048.example)"

# ── IP address SANs ─────────────────────────────────────────────────────────
issue leaf_ipsan "ipsan" inter 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=IP:192.0.2.7,IP:2001:db8::7,DNS:ipsan.example\n'
issue leaf_dns_ip "dnsip" inter 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:192.0.2.8\n'

# ── Write the Mojo fixture module ───────────────────────────────────────────
{
    echo "# Generated by tests/gen_path_fixtures.sh: do not edit."
    echo "# DER certificates (hex) for tests/test_cert_path.mojo, valid until 2125."
    echo
    for name in root inter leaf_ok leaf_direct evil bank inter_nobc leaf_nobc inter_ku leaf_ku \
                inter_pl0 sub_pl0 leaf_pl0_deep leaf_pl0 leaf_client leaf_noeku leaf_kenc \
                inter_crit leaf_crit inter_noncrit leaf_noncrit inter_nc leaf_nc \
                inter_alt leaf_dn leaf_expired inter_future leaf_future \
                new_root old_root cross_expired inter_x leaf_x \
                stray_root stray_inter stray_leaf \
                inter_ncd leaf_ncd_ok leaf_ncd_bad inter_ncx leaf_ncx_ok leaf_ncx_bad leaf_ncx_wild \
                inter_ncip leaf_ncip_ok leaf_ncip_bad inter_ncemail leaf_ncemail \
                inter_eku_email leaf_eku_email inter_eku_server leaf_eku_server \
                rsa1024_leaf rsa2048_leaf leaf_ipsan leaf_dns_ip; do
        upper="$(echo "$name" | tr '[:lower:]' '[:upper:]')"
        echo "comptime ${upper} = \"$(openssl x509 -in "$name.pem" -outform DER | xxd -p | tr -d '\n')\""
    done
} > "$OUT"
echo "wrote $OUT"
# KEEP_PEMS=<dir> keeps the certificates (not keys) for checking with openssl verify
if [ -n "${KEEP_PEMS:-}" ]; then cp "$WORK"/*.pem "$KEEP_PEMS"/; fi
