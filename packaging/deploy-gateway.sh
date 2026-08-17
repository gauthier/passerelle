#!/bin/sh
# Deploy passerelle-gateway over SSH.
# Usage:
#   ./packaging/deploy-gateway.sh
#   ./packaging/deploy-gateway.sh root@passserelle.gnthr.dev
#   DEPLOY_HOST=root@passerelle.gnthr.dev ./packaging/deploy-gateway.sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

HOST="${1:-${DEPLOY_HOST:-root@passerelle.gnthr.dev}}"
PREFIX="${PREFIX:-/usr/local}"
BIN_REMOTE="${PREFIX}/bin/passerelle-gateway"
CONF_DIR="/etc/passerelle"
DATA_DIR="/var/lib/passerelle"
GO="${GO:-go}"
VERSION="${VERSION:-0.1.1}"
LDFLAGS="-s -w -X github.com/gauthier/passerelle/internal/version.Version=${VERSION}"

SSH_OPTS="${SSH_OPTS:--o StrictHostKeyChecking=accept-new}"

echo "==> probing ${HOST}"
REMOTE_ARCH="$(ssh $SSH_OPTS "$HOST" uname -m)"
case "$REMOTE_ARCH" in
  x86_64 | amd64) GOARCH=amd64 ;;
  aarch64 | arm64) GOARCH=arm64 ;;
  *)
    echo "unsupported remote arch: ${REMOTE_ARCH}" >&2
    exit 1
    ;;
esac

STAGING="$(mktemp -d "${TMPDIR:-/tmp}/passerelle-deploy.XXXXXX")"
trap 'rm -rf "$STAGING"' EXIT

echo "==> building linux/${GOARCH} passerelle-gateway"
mkdir -p "${ROOT}/bin"
CGO_ENABLED=0 GOOS=linux GOARCH="$GOARCH" "$GO" build -ldflags "$LDFLAGS" \
  -o "${STAGING}/passerelle-gateway" ./cmd/passerelle-gateway

cp packaging/systemd/passerelle-gateway.service "${STAGING}/passerelle-gateway.service"
cp packaging/gateway.toml.example "${STAGING}/gateway.toml.example"

echo "==> copying files"
scp $SSH_OPTS \
  "${STAGING}/passerelle-gateway" \
  "${STAGING}/passerelle-gateway.service" \
  "${STAGING}/gateway.toml.example" \
  "${HOST}:/tmp/"

if [ -n "${DEPLOY_TLS_CERT:-}" ] && [ -n "${DEPLOY_TLS_KEY:-}" ]; then
  scp $SSH_OPTS "$DEPLOY_TLS_CERT" "${HOST}:/tmp/passerelle-tls.crt"
  scp $SSH_OPTS "$DEPLOY_TLS_KEY" "${HOST}:/tmp/passerelle-tls.key"
fi

echo "==> installing on ${HOST}"
# shellcheck disable=SC2086
ssh $SSH_OPTS "$HOST" PREFIX="$PREFIX" BIN_REMOTE="$BIN_REMOTE" \
  CONF_DIR="$CONF_DIR" DATA_DIR="$DATA_DIR" \
  HAS_TLS="${DEPLOY_TLS_CERT:+1}" \
  sh -s <<'REMOTE'
set -eu
if [ "$(id -u)" -ne 0 ]; then
  echo "remote user must be root" >&2
  exit 1
fi

if ! id passerelle >/dev/null 2>&1; then
  useradd --system --home "$DATA_DIR" --shell /usr/sbin/nologin passerelle
fi

install -d -m 0755 "$CONF_DIR"
install -d -m 0700 -o passerelle -g passerelle "$DATA_DIR"
install -m 0755 /tmp/passerelle-gateway "$BIN_REMOTE"
rm -f /tmp/passerelle-gateway

if [ ! -f "$CONF_DIR/gateway.toml" ]; then
  install -m 0640 -o root -g passerelle /tmp/gateway.toml.example "$CONF_DIR/gateway.toml"
fi
rm -f /tmp/gateway.toml.example

install -m 0644 /tmp/passerelle-gateway.service /etc/systemd/system/passerelle-gateway.service
rm -f /tmp/passerelle-gateway.service

if [ "${HAS_TLS:-}" = "1" ]; then
  install -m 0640 -o root -g passerelle /tmp/passerelle-tls.crt "$CONF_DIR/tls.crt"
  install -m 0640 -o root -g passerelle /tmp/passerelle-tls.key "$CONF_DIR/tls.key"
  rm -f /tmp/passerelle-tls.crt /tmp/passerelle-tls.key
fi

if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
  ufw allow 80/tcp >/dev/null
  ufw allow 443/tcp >/dev/null
  ufw allow 443/udp >/dev/null
fi

systemctl daemon-reload
systemctl enable passerelle-gateway.service

if [ -f "$CONF_DIR/tls.crt" ] && [ -f "$CONF_DIR/tls.key" ]; then
  systemctl restart passerelle-gateway.service
  systemctl --no-pager --full status passerelle-gateway.service | head -n 20
  echo
  echo "gateway running"
  echo "  enroll: https://passerelle.gnthr.dev"
else
  echo
  echo "binary and unit installed; TLS certs missing:"
  echo "  $CONF_DIR/tls.crt"
  echo "  $CONF_DIR/tls.key"
  echo "Install a cert with SAN *.gnthr.dev then:"
  echo "  systemctl start passerelle-gateway"
fi
REMOTE

echo "==> done (${HOST}, linux/${GOARCH})"
