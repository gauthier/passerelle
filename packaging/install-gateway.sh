#!/bin/sh
# Install passerelle-gateway on this machine.
# Usage:
#   ./packaging/install-gateway.sh example.com
#   BASE_DOMAIN=example.com ./packaging/install-gateway.sh
set -eu

PREFIX="${PREFIX:-/usr/local}"
BIN="${PREFIX}/bin/passerelle-gateway"
UNIT_SRC="$(dirname "$0")/systemd/passerelle-gateway.service"
EXAMPLE="$(dirname "$0")/gateway.toml.example"
CONF_DIR="/etc/passerelle"
DATA_DIR="/var/lib/passerelle"
BASE_DOMAIN="${1:-${BASE_DOMAIN:-}}"

valid_domain() {
  case "$1" in
    "" | *[!a-zA-Z0-9.-]* | .* | *. | *- | -* | *..*) return 1 ;;
    *.*) return 0 ;;
    *) return 1 ;;
  esac
}

if [ "$(id -u)" -ne 0 ]; then
  echo "run as root" >&2
  exit 1
fi

if ! valid_domain "$BASE_DOMAIN"; then
  echo "usage: $0 <base_domain>" >&2
  echo "  e.g. $0 example.com" >&2
  exit 1
fi

if [ ! -x ./bin/passerelle-gateway ]; then
  echo "build first: make" >&2
  exit 1
fi

id passerelle >/dev/null 2>&1 || useradd --system --home "$DATA_DIR" --shell /usr/sbin/nologin passerelle

install -d -m 0755 "$CONF_DIR"
install -d -m 0700 -o passerelle -g passerelle "$DATA_DIR"
install -m 0755 ./bin/passerelle-gateway "$BIN"

tmp="$(mktemp)"
if [ -f "$CONF_DIR/gateway.toml" ]; then
  sed "s/^base_domain = \".*\"/base_domain = \"${BASE_DOMAIN}\"/" "$CONF_DIR/gateway.toml" >"$tmp"
else
  sed "s/^base_domain = \".*\"/base_domain = \"${BASE_DOMAIN}\"/" "$EXAMPLE" >"$tmp"
fi
install -m 0640 -o root -g passerelle "$tmp" "$CONF_DIR/gateway.toml"
rm -f "$tmp"

install -m 0644 "$UNIT_SRC" /etc/systemd/system/passerelle-gateway.service
install -m 0644 "$(dirname "$0")/sysctl/99-passerelle-udp.conf" /etc/sysctl.d/99-passerelle-udp.conf
sysctl --system >/dev/null
systemctl daemon-reload
systemctl enable passerelle-gateway.service
echo "Config: $CONF_DIR/gateway.toml (base_domain=${BASE_DOMAIN})"
echo "DNS: *.${BASE_DOMAIN} → this host; enroll: passerelle auth https://passerelle.${BASE_DOMAIN}"
echo "TLS: install a cert with SAN *.${BASE_DOMAIN} then:"
echo "  systemctl start passerelle-gateway"
