#!/bin/sh
# install-termd.sh — install the Xyfr terminal server as an isolated system service.
#
# This is what actually delivers the J-8 isolation: it creates a dedicated,
# login-less `xyfr` user and installs a systemd unit that runs the daemon AS
# that user. After this, terminal sessions can never run as you, because the
# service simply does not.
#
# Idempotent: safe to re-run to pick up a new binary or unit.
# Run as root:  sudo ./install-termd.sh

set -eu

BIN_SRC="${1:-./xyfr-termd}"
UNIT_SRC="$(dirname "$0")/xyfr-termd.service"
CONF_EXAMPLE="$(dirname "$0")/../termd.conf.example"

USER=xyfr
HOME_DIR=/var/lib/xyfr
SHARED_DIR=$HOME_DIR/shared
CONF_DIR=/etc/xyfr
CONF=$CONF_DIR/termd.conf
BIN_DST=/usr/local/bin/xyfr-termd
UNIT_DST=/etc/systemd/system/xyfr-termd.service

if [ "$(id -u)" -ne 0 ]; then
	echo "install-termd: must be run as root (try: sudo $0)" >&2
	exit 1
fi
if [ ! -x "$BIN_SRC" ]; then
	echo "install-termd: no xyfr-termd binary at '$BIN_SRC' (run 'make xyfr-termd' first)" >&2
	exit 1
fi

# 1. The dedicated user. System account, no login shell, no password -- the
#    whole point is that nobody logs in AS it; the service just runs as it.
if ! id "$USER" >/dev/null 2>&1; then
	useradd --system --home-dir "$HOME_DIR" --shell /usr/sbin/nologin \
	        --comment "Xyfr terminal server" "$USER"
	echo "created system user: $USER"
else
	echo "user $USER already exists"
fi

# 2. State + shared workspace, owned by the service user, not group/other
#    readable. A terminal session is confined here (WorkingDirectory + the
#    systemd ReadWritePaths).
install -d -o "$USER" -g "$USER" -m 0700 "$HOME_DIR"
install -d -o "$USER" -g "$USER" -m 0700 "$SHARED_DIR"

# 3. Config directory. The config holds the server's PRIVATE KEY, so it is
#    readable ONLY by the service user (0600) -- not even group.
install -d -o root -g root -m 0755 "$CONF_DIR"
if [ ! -f "$CONF" ]; then
	install -o "$USER" -g "$USER" -m 0600 "$CONF_EXAMPLE" "$CONF"
	echo "installed a TEMPLATE config at $CONF -- EDIT IT before starting:"
	echo "    * generate a FRESH key with ./keygen (do NOT reuse your phone key)"
	echo "    * set server_key / server_ip"
	echo "    * add allow_terminal=<partkey> for each handheld you permit"
else
	echo "config $CONF already present, left untouched"
fi

# 4. Binary + unit.
install -o root -g root -m 0755 "$BIN_SRC"  "$BIN_DST"
install -o root -g root -m 0644 "$UNIT_SRC" "$UNIT_DST"
echo "installed $BIN_DST and $UNIT_DST"

# 5. Register with systemd. Deliberately NOT started -- the template config has
#    no real key yet; the operator edits it and then `systemctl start`.
systemctl daemon-reload
systemctl enable xyfr-termd.service >/dev/null 2>&1 || true

cat <<EOF

Installed. The service runs as the '$USER' user, so a forked shell can never
reach your files or your messaging key.

Next:
  1. sudoedit $CONF          # add a real key + allow_terminal entries
  2. sudo systemctl start xyfr-termd
  3. journalctl -u xyfr-termd -f    # watch it log in and admit/reject peers
EOF
