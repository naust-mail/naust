#!/bin/bash
# FileBrowser - web file manager
# ------------------------------

source setup/functions.sh # load our functions
source /etc/mailinabox.conf # load global vars

echo "Installing FileBrowser..."

# Pinned version (update FB_HASH when changing FB_VERSION).
# To get the hash: run this script once with a wrong hash; the correct sha1
# is printed in the error. Or: sha1sum linux-amd64-filebrowser.tar.gz
FB_VERSION=v2.63.11
FB_HASH=4bc72dad029d531d153b58bd63a3dabf74c0b395

# Skip download if the installed version already matches.
needs_update=0
if [ ! -x /usr/local/bin/filebrowser ]; then
	needs_update=1
elif [[ "$FB_VERSION" != "v$(/usr/local/bin/filebrowser version 2>/dev/null | awk '/Version/{print $2}')" ]]; then
	needs_update=1
fi

if [ "$needs_update" = "1" ]; then
	wget_verify \
		"https://github.com/filebrowser/filebrowser/releases/download/${FB_VERSION}/linux-amd64-filebrowser.tar.gz" \
		"$FB_HASH" \
		/tmp/filebrowser.tar.gz
	tar -xzf /tmp/filebrowser.tar.gz -C /usr/local/bin filebrowser
	chmod +x /usr/local/bin/filebrowser
	rm /tmp/filebrowser.tar.gz
fi

# Files root and database directories.
mkdir -p "$STORAGE_ROOT/files"
chown www-data:www-data "$STORAGE_ROOT/files"

mkdir -p "$STORAGE_ROOT/filebrowser"
chown www-data:www-data "$STORAGE_ROOT/filebrowser"

FB_DB="$STORAGE_ROOT/filebrowser/filebrowser.db"

# Install IMAP hook auth script. Connects on port 993 with cert verification
# disabled (Python ssl allows this; oxi does not). Lets users log in with
# their mail credentials.
# Exit codes: 0=auth or block (FileBrowser reads hook.action), 1=server error.
# Bad credentials must exit 0 with hook.action=block - a non-zero exit makes
# FileBrowser return 500 instead of 403, which breaks fail2ban targeting.
cat > /usr/local/lib/filebrowser-auth.py << EOF
#!/usr/bin/env python3
import sys, os, imaplib, ssl, socket, re

FILES_ROOT = "$STORAGE_ROOT/files"

socket.setdefaulttimeout(5)

username = os.environ.get('USERNAME', '')
password = os.environ.get('PASSWORD', '')

if not username or not password:
    print("hook.action=block")
    sys.exit(0)

# Reject usernames outside normal email address syntax to prevent
# IMAP command injection (imaplib passes username raw into LOGIN).
if not re.fullmatch(r'[A-Za-z0-9._%+\-@]+', username):
    print("hook.action=block")
    sys.exit(0)

try:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    conn = imaplib.IMAP4_SSL('127.0.0.1', 993, ssl_context=ctx)
    conn.login(username, password)
    conn.logout()

    # Ensure the user's personal directory exists under the files root.
    user_dir = os.path.join(FILES_ROOT, username)
    os.makedirs(user_dir, mode=0o750, exist_ok=True)

    # Scope the user to their own directory so they cannot see other users' files.
    print("hook.action=auth")
    print(f"user.scope={username}")
    sys.exit(0)
except imaplib.IMAP4.error:
    print("hook.action=block")
    sys.exit(0)
except Exception:
    # Dovecot unreachable or other connection error - let FileBrowser return 500.
    sys.exit(1)
EOF
chmod 755 /usr/local/lib/filebrowser-auth.py
chown root:root /usr/local/lib/filebrowser-auth.py

# Stop the service before touching the database - it holds a BoltDB lock
# while running and config init/set will timeout if it's up.
systemctl stop filebrowser 2>/dev/null || true

# Initialize on first install only.
if [ ! -f "$FB_DB" ]; then
	hide_output sudo -u www-data filebrowser config init \
		--database "$FB_DB"
fi

# Apply config on every run so settings are updated when setup re-runs.
hide_output sudo -u www-data filebrowser config set \
	--database "$FB_DB" \
	--address 127.0.0.1 \
	--port 8080 \
	--root "$STORAGE_ROOT/files" \
	--baseURL /files \
	--auth.method hook \
	--auth.command "python3 /usr/local/lib/filebrowser-auth.py" \
	--minimumPasswordLength 1 \
	--createUserDir \
	--branding.name "$PRIMARY_HOSTNAME"
# minimumPasswordLength 1: 0 is treated as unset (Go zero value) and reverts to default 12
# createUserDir: each user gets their own subdirectory under the files root

# Ensure the log file exists before fail2ban starts watching it.
touch /var/log/filebrowser.log
chown www-data:www-data /var/log/filebrowser.log

# Logrotate config: rotate weekly, keep 4 weeks, copytruncate so we don't
# need to signal FileBrowser to reopen the file (it doesn't support SIGUSR1).
cat > /etc/logrotate.d/filebrowser << 'LOGROTATEOF'
/var/log/filebrowser.log {
    weekly
    rotate 4
    compress
    delaycompress
    missingok
    notifempty
    create 0640 www-data www-data
    copytruncate
}
LOGROTATEOF

cat > /lib/systemd/system/filebrowser.service << EOF
[Unit]
Description=FileBrowser web file manager
After=network.target

[Service]
ExecStart=/usr/local/bin/filebrowser \
    --database $STORAGE_ROOT/filebrowser/filebrowser.db
User=www-data
Group=www-data
Restart=on-failure
RestartSec=5
StandardOutput=append:/var/log/filebrowser.log
StandardError=append:/var/log/filebrowser.log

# Sandboxing
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ReadWritePaths=$STORAGE_ROOT/files $STORAGE_ROOT/filebrowser /var/log/filebrowser.log
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=true
LockPersonality=true
CapabilityBoundingSet=

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable filebrowser
restart_service filebrowser
