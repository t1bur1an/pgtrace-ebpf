#!/usr/bin/env bash
# Test PKI for scripts/e2e_tls.sh, perf_tls.sh and the TLS soak: root CA ->
# intermediate -> server certs (pgbouncer, postgres) and client certs (user
# "postgres": pgbench -> pgbouncer and pgbouncer -> postgres). Written to
# ./certs (git-ignored). Test use only.
set -euo pipefail
cd "$(dirname "$0")"
rm -rf certs && mkdir certs && cd certs
subj() { echo "/O=pgtrace-spike/CN=$1"; }
key() { openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1.key" 2>/dev/null; }

key root
openssl req -x509 -new -key root.key -subj "$(subj 'Spike Root CA')" -days 30 -out root.crt \
	-addext basicConstraints=critical,CA:true -addext keyUsage=critical,keyCertSign,cRLSign
key inter
openssl req -new -key inter.key -subj "$(subj 'Spike Intermediate CA')" -out inter.csr
openssl x509 -req -in inter.csr -CA root.crt -CAkey root.key -CAcreateserial -days 30 -out inter.crt \
	-extfile <(printf 'basicConstraints=critical,CA:true,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\n') 2>/dev/null

leaf() { # leaf <name> <CN> <serverAuth|clientAuth> [SAN]
	key "$1"
	openssl req -new -key "$1.key" -subj "$(subj "$2")" -out "$1.csr"
	local ext="basicConstraints=CA:false\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=$3\n"
	[ -n "${4:-}" ] && ext+="subjectAltName=$4\n"
	openssl x509 -req -in "$1.csr" -CA inter.crt -CAkey inter.key -CAcreateserial -days 30 -out "$1.leaf.crt" \
		-extfile <(printf "$ext") 2>/dev/null
	cat "$1.leaf.crt" inter.crt > "$1.crt" # leaf + intermediate; peers trust only root.crt
}
leaf pgbouncer pgbouncer serverAuth DNS:pgbouncer
leaf postgres postgres serverAuth DNS:postgres
leaf client postgres clientAuth # pgbench -> pgbouncer
leaf pgb-client postgres clientAuth # pgbouncer -> postgres
rm -f ./*.csr ./*.srl
chmod 644 ./*          # pgbouncer (uid 70) and the postgres wrapper read these
chmod 600 client.key   # libpq refuses a client key readable by others
openssl verify -CAfile root.crt -untrusted inter.crt pgbouncer.leaf.crt postgres.leaf.crt client.leaf.crt pgb-client.leaf.crt
