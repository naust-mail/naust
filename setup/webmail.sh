#!/bin/bash
# Webmail with oxi.email
# ----------------------

source setup/functions.sh # load our functions
source /etc/mailinabox.conf # load global vars

echo "Installing oxi.email (webmail)..."

# Install Rust to stable system paths so PATH is consistent across MIAB re-runs.
export RUSTUP_HOME=/opt/rustup
export CARGO_HOME=/opt/cargo
if [ ! -x /opt/cargo/bin/cargo ]; then
	curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
		| hide_output sh -s -- -y --profile minimal --no-modify-path
fi
export PATH="/opt/cargo/bin:$PATH"
cat > /etc/profile.d/cargo.sh << 'PROFILE'
export RUSTUP_HOME=/opt/rustup
export CARGO_HOME=/opt/cargo
export PATH="$CARGO_HOME/bin:$PATH"
PROFILE

# Install Bun so the binary lands at /usr/local/bin/bun.
# BUN_INSTALL must be exported (not inline) so the piped bash subshell inherits it.
if [ ! -x /usr/local/bin/bun ]; then
	export BUN_INSTALL=/usr/local
	curl -fsSL https://bun.sh/install | hide_output bash
fi
# Ensure bun is on PATH for the rest of this script regardless of install path.
export PATH="/usr/local/bin:${BUN_INSTALL:-/usr/local}/bin:$HOME/.bun/bin:$PATH"

apt_install_cached "webmail" libssl-dev libsqlite3-dev ca-certificates

# Pin to a known-good commit (update this hash when upgrading).
OXI_COMMIT=f210ec5863dad8d8f9ab432272a749fe79a65f74
OXI_DIR=/usr/local/src/oxi

if [ ! -d "$OXI_DIR/.git" ]; then
	hide_output git clone https://github.com/c0h1b4/oxi.git "$OXI_DIR"
fi
# Fetch only if the pinned commit is not already present locally (e.g. first
# clone, or after a force-push on the upstream remote).
if ! git -C "$OXI_DIR" cat-file -e "${OXI_COMMIT}^{commit}" 2>/dev/null; then
	git -C "$OXI_DIR" fetch --all -q
fi
git -C "$OXI_DIR" checkout -q "$OXI_COMMIT"

# Apply MIAB-specific patches. Patches are applied in order; reversed in
# reverse order first so the operation is idempotent across re-runs.
OXI_PATCH1="$PWD/management/oxi/1_miab_oxi_auth_patch.patch"
OXI_PATCH2="$PWD/management/oxi/2_miab_oxi_ui_patch.patch"
for _p in "$OXI_PATCH2" "$OXI_PATCH1"; do
	[ -f "$_p" ] || continue
	git -C "$OXI_DIR" apply --reverse --check "$_p" 2>/dev/null && \
		git -C "$OXI_DIR" apply --reverse "$_p"
done
for _p in "$OXI_PATCH1" "$OXI_PATCH2"; do
	[ -f "$_p" ] && git -C "$OXI_DIR" apply "$_p"
done

# Frontend and backend use separate stamps so a patch-only change does not
# force a frontend rebuild, and a failed mid-build can resume from where it
# left off on the next run. Each stamp is written only after its deploy step
# succeeds, so a partial failure leaves the stamp invalid for retry.

# Frontend stamp: commit + lockfile hash + UI patch hash.
_fe_want="$OXI_COMMIT:$(hash_files "$OXI_DIR/frontend/bun.lock" "$OXI_PATCH2")"

# Backend stamp: commit + backend patch hash.
_be_want="$OXI_COMMIT:$(hash_files "$OXI_PATCH1")"

OXI_STATIC_DIR=/usr/local/share/oxi-email/static
mkdir -p "$OXI_STATIC_DIR"

if needs_build "oxi-frontend" "$_fe_want"; then
	echo "Building oxi.email frontend..."
	(
		cd "$OXI_DIR/frontend"
		hide_output bun install --frozen-lockfile

		# Cap Node heap at 60% of RAM. Floor: 256 MB. Ceiling: 4096 MB.
		# Disable Next.js telemetry - server build, not a dev environment.
		_total_kb=$(awk '/MemTotal/{print $2}' /proc/meminfo)
		_node_mem=$(( _total_kb * 60 / 100 / 1024 ))
		[ "$_node_mem" -lt 256 ]  && _node_mem=256
		[ "$_node_mem" -gt 4096 ] && _node_mem=4096

		NEXT_TELEMETRY_DISABLED=1 NODE_OPTIONS="--max-old-space-size=${_node_mem}" \
			hide_output bun x next build
	)
	hide_output rsync -a --delete "$OXI_DIR/frontend/out/" "$OXI_STATIC_DIR/"
	chown -R root:root "$OXI_STATIC_DIR"
	chmod -R 755 "$OXI_STATIC_DIR"
	mark_built "oxi-frontend" "$_fe_want"
fi

if needs_build "oxi-backend" "$_be_want"; then
	echo "Building oxi.email backend (this will take a few minutes on first run)..."
	(
		cd "$OXI_DIR/backend"
		hide_output cargo build --release
	)
	cp --remove-destination "$OXI_DIR/backend/target/release/oxi-email-server" /usr/local/bin/oxi-email-server
	chmod 755 /usr/local/bin/oxi-email-server
	chown root:root /usr/local/bin/oxi-email-server
	mark_built "oxi-backend" "$_be_want"
fi

# Data directory for per-user SQLite + search indexes - www-data needs write.
mkdir -p "$STORAGE_ROOT/oxi"
chown www-data:www-data "$STORAGE_ROOT/oxi"
chmod 750 "$STORAGE_ROOT/oxi"

# Runtime config.
# Use IMAP port 143 (plain, loopback-only) - oxi has no TLS cert skip option
# so port 993 with a self-signed cert would fail. Dovecot already listens on
# 127.0.0.1:143 for local plain IMAP.
mkdir -p /etc/oxi
cat > /etc/oxi/config.env << EOF
HOST=127.0.0.1
PORT=3001
IMAP_HOST=127.0.0.1
IMAP_PORT=143
TLS_ENABLED=false
SMTP_HOST=127.0.0.1
SMTP_PORT=587
ALLOW_CUSTOM_MAIL_SERVERS=false
DATA_DIR=$STORAGE_ROOT/oxi
STATIC_DIR=/usr/local/share/oxi-email/static
RUST_LOG=info,tantivy=warn,async_imap=warn
SESSION_TIMEOUT_HOURS=24
EOF
chmod 640 /etc/oxi/config.env
chown root:www-data /etc/oxi/config.env

cat > /lib/systemd/system/oxi-email.service << EOF
[Unit]
Description=oxi.email webmail
After=network.target dovecot.service postfix.service

[Service]
EnvironmentFile=/etc/oxi/config.env
ExecStart=/usr/local/bin/oxi-email-server
User=www-data
Group=www-data
Restart=on-failure
RestartSec=5
WorkingDirectory=/usr/local/share/oxi-email

# Sandboxing
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ReadWritePaths=$STORAGE_ROOT/oxi
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=true
LockPersonality=true
MemoryDenyWriteExecute=true
SystemCallFilter=@system-service
CapabilityBoundingSet=

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable oxi-email
restart_service oxi-email
