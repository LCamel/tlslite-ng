#!/bin/bash
set -e

# === Target host and port ===
HOST="localhost"
PORT=4433

# === Minimal TLS 1.3 requirements based on RFC 8446 ===
CIPHER="TLS_AES_128_GCM_SHA256"
TLS_GROUPS="secp256r1"
SIGALGS="rsa_pss_rsae_sha256:rsa_pkcs1_sha256:ecdsa_secp256r1_sha256"

# === HTTP/1.1 HEAD request ===
REQUEST="HEAD / HTTP/1.1\r\nHost: ${HOST}\r\nConnection: close\r\n\r\n"

# === Run openssl s_client with specified TLS 1.3 parameters ===
echo "Testing TLS 1.3 with:"
echo " - Cipher Suite       : $CIPHER"
echo " - Signature Algorithms: $SIGALGS"
echo " - Named Group         : $TLS_GROUPS"
echo ""

printf "$REQUEST" | \
openssl s_client \
  -connect "${HOST}:${PORT}" \
  -tls1_3 \
  -ciphersuites "$CIPHER" \
  -groups "$TLS_GROUPS" \
  -sigalgs "$SIGALGS" \
  -ign_eof \
  -ignore_unexpected_eof

#  -servername "$HOST" \
#  -alpn http/1.1 \
#  -quiet \
#  -debug \
#  -trace \
# openssl s_client --help
