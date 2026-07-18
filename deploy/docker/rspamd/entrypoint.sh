#!/bin/bash
# Rspamd container entrypoint.
# Generates the DKIM key and writes rspamd config directly - we don't source
# rspamd.sh because it also wires up Postfix (which lives in the mail container).

set -euo pipefail

NAUST=/opt/naust
source "$NAUST/deploy/docker/common-entrypoint.sh"

install_systemctl_stub
write_naust_conf

export RUNTIME=docker

cd "$NAUST"

export LANGUAGE=en_US.UTF-8
export LC_ALL=en_US.UTF-8
export LANG=en_US.UTF-8
export LC_TYPE=en_US.UTF-8

source /etc/naust.conf
mkdir -p "$STORAGE_ROOT"

echo "Configuring Rspamd..."

# DKIM key
mkdir -p "$STORAGE_ROOT/mail/dkim"
if [ ! -f "$STORAGE_ROOT/mail/dkim/mail.private" ]; then
    rspamadm dkim_keygen -s mail -b 2048 -k "$STORAGE_ROOT/mail/dkim/mail.private" \
        > "$STORAGE_ROOT/mail/dkim/mail.txt"
    chmod 644 "$STORAGE_ROOT/mail/dkim/mail.txt"
fi
chown root:_rspamd "$STORAGE_ROOT/mail/dkim"
chmod 750 "$STORAGE_ROOT/mail/dkim"
chown root:_rspamd "$STORAGE_ROOT/mail/dkim/mail.private"
chmod 640 "$STORAGE_ROOT/mail/dkim/mail.private"

mkdir -p /etc/rspamd/local.d

REDIS_HOST="${REDIS_HOST:-redis}"
cat > /etc/rspamd/local.d/redis.conf << EOF
servers = "${REDIS_HOST}";
EOF

# Bind on all interfaces so Postfix (in the mail container) can reach us.
cat > /etc/rspamd/local.d/worker-proxy.inc << 'EOF'
bind_socket = "0.0.0.0:11332";
timeout = 120s;
upstream "local" {
  default = yes;
  self_scan = yes;
}
EOF

cat > /etc/rspamd/local.d/dkim_signing.conf << EOF
allow_username_mismatch = true;
use_domain = "envelope";
path = "$STORAGE_ROOT/mail/dkim/\${selector}.private";
selector = "mail";
sign_authenticated = true;
sign_local = true;
EOF

cat > /etc/rspamd/local.d/greylisting.conf << 'EOF'
enabled = true;
timeout = 180;
expire = 86400;
EOF

cat > /etc/rspamd/local.d/dmarc.conf << 'EOF'
reporting {
  enabled = false;
}
EOF

cat > /etc/rspamd/local.d/milter_headers.conf << 'EOF'
use = ["x-spam-status", "x-spam-score", "authentication-results"];
extended_spam_headers = true;
EOF

cat > /etc/rspamd/local.d/actions.conf << 'EOF'
reject = 15;
add_header = 6;
greylist = 4;
EOF

echo "Rspamd setup complete. Starting supervisord..."
exec /usr/bin/supervisord -c /etc/supervisor/supervisord.conf
