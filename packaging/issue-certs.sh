#!/bin/sh
# Issue a Let's Encrypt cert for *.gnthr.dev via Porkbun DNS-01 (lego).
#
# 1. Porkbun → Account → API Access: create a key pair.
# 2. Same page: enable "Opt In All Domains", OR Domain Management →
#    gnthr.dev → Details → API Access. Keys alone are not enough.
# 3. Then:
#      ACME_EMAIL=toi@gnthr.dev \
#      PORKBUN_API_KEY=pk1_… \
#      PORKBUN_SECRET_API_KEY=sk1_… \
#        ./packaging/issue-certs.sh
set -eu

ACME_EMAIL="${ACME_EMAIL:?set ACME_EMAIL}"
DNS_PROVIDER="${DNS_PROVIDER:-porkbun}"
DOMAIN="${DOMAIN:-gnthr.dev}"
OUT_DIR="${OUT_DIR:-./certs}"

if [ "$DNS_PROVIDER" = "porkbun" ]; then
  : "${PORKBUN_API_KEY:?set PORKBUN_API_KEY}"
  : "${PORKBUN_SECRET_API_KEY:?set PORKBUN_SECRET_API_KEY}"
fi

if ! command -v lego >/dev/null 2>&1; then
  echo "install lego first, e.g.: brew install lego" >&2
  exit 1
fi

mkdir -p "$OUT_DIR"
cd "$OUT_DIR"

# lego v5 moved flags onto `run` (global `--accept-tos` is rejected).
lego run --accept-tos --email "$ACME_EMAIL" --dns "$DNS_PROVIDER" \
  --domains "$DOMAIN" --domains "*.${DOMAIN}" \
  --path "$PWD"

# lego writes <path>/certificates/<domain>.crt and .key
CRT="$(find certificates -name "${DOMAIN}.crt" | head -n 1)"
KEY="$(find certificates -name "${DOMAIN}.key" | head -n 1)"
if [ -z "$CRT" ] || [ -z "$KEY" ]; then
  echo "lego did not produce expected files in $OUT_DIR/certificates" >&2
  exit 1
fi

cp "$CRT" tls.crt
cp "$KEY" tls.key
chmod 644 tls.crt
chmod 600 tls.key

echo
echo "wrote:"
echo "  $OUT_DIR/tls.crt"
echo "  $OUT_DIR/tls.key"
echo
echo "deploy:"
echo "  DEPLOY_TLS_CERT=$OUT_DIR/tls.crt DEPLOY_TLS_KEY=$OUT_DIR/tls.key ./packaging/deploy-gateway.sh"
