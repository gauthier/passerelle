#!/bin/sh
set -eu

PREFIX="${PREFIX:-/usr/local}"
BIN="${PREFIX}/bin/passerelle-gateway"
UNIT_SRC="$(dirname "$0")/systemd/passerelle-gateway.service"
CONF_DIR="/etc/passerelle"
DATA_DIR="/var/lib/passerelle"

if [ "$(id -u)" -ne 0 ]; then
  echo "run as root" >&2
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

if [ ! -f "$CONF_DIR/gateway.toml" ]; then
  install -m 0640 -o root -g passerelle "$(dirname "$0")/gateway.toml.example" "$CONF_DIR/gateway.toml"
fi

install -m 0644 "$UNIT_SRC" /etc/systemd/system/passerelle-gateway.service
systemctl daemon-reload
systemctl enable passerelle-gateway.service
echo "Config: $CONF_DIR/gateway.toml (base_domain=gnthr.dev)"
echo "DNS: *.gnthr.dev already points here; enroll at https://passerelle.gnthr.dev"
echo "TLS: install cert with SAN *.gnthr.dev then:"
echo "  systemctl start passerelle-gateway"
