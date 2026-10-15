#!/bin/sh
# Installs Lanternfish Gate as a systemd service. Run as root inside the Gate
# container:   ./install-gate.sh /root/lanternfish-gate
set -eu

BIN=${1:?usage: install-gate.sh /path/to/lanternfish-gate}
HERE=$(cd "$(dirname "$0")" && pwd)
[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 1; }

id lanternfish >/dev/null 2>&1 ||
  useradd --system --home-dir /var/lib/lanternfish --no-create-home --shell /usr/sbin/nologin lanternfish

# Via a temporary file, so upgrading a running Gate works.
install -m 0755 "$BIN" /usr/local/bin/.lanternfish-gate.new
mv -f /usr/local/bin/.lanternfish-gate.new /usr/local/bin/lanternfish-gate
install -m 0755 "$HERE/lanternfish-gatectl" /usr/local/sbin/lanternfish-gatectl
install -d -m 0755 /usr/local/lib/lanternfish
install -m 0755 "$HERE/certbot-deploy-hook.sh" /usr/local/lib/lanternfish/certbot-deploy-hook.sh

install -d -m 0755 /etc/lanternfish
install -d -m 0750 -o root -g lanternfish /etc/lanternfish/tls
# keys/ is normally a bind mount from the Proxmox host; make sure it exists either way.
mkdir -p /etc/lanternfish/keys
chown root:lanternfish /etc/lanternfish/keys
chmod 0750 /etc/lanternfish/keys
install -d -m 0700 -o lanternfish -g lanternfish /var/lib/lanternfish

if [ ! -s /etc/lanternfish/keys/master_key ]; then
  (umask 077 && /usr/local/bin/lanternfish-gate gen-master-key > /etc/lanternfish/keys/master_key)
  echo ">>> Generated /etc/lanternfish/keys/master_key."
  echo ">>> Copy it into your password manager now. Without it, a restored Gate cannot open its data."
fi
chown root:lanternfish /etc/lanternfish/keys/master_key
chmod 0440 /etc/lanternfish/keys/master_key

if [ ! -f /etc/lanternfish/gate.env ]; then
  install -m 0640 -o root -g lanternfish "$HERE/gate.env.example" /etc/lanternfish/gate.env
  echo ">>> Wrote /etc/lanternfish/gate.env. Review it before starting."
fi

install -m 0644 "$HERE/lanternfish-gate.service" /etc/systemd/system/lanternfish-gate.service
if [ -d /run/systemd/system ]; then
  systemctl daemon-reload
  systemctl enable lanternfish-gate >/dev/null
fi

cat <<'MSG'

Installed. Next:
  1. Get a TLS certificate into /etc/lanternfish/tls (see deploy/proxmox/README.md, step 5).
  2. lanternfish-gatectl admin-key create -name builder
  3. lanternfish-gatectl upstream-key      # paste into the Jellyfin plugin
  4. systemctl start lanternfish-gate && journalctl -u lanternfish-gate -f
MSG
