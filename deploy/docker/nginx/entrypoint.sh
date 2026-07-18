#!/bin/bash
# Nginx container entrypoint.
#
# Runs nginx in the foreground (single process - no supervisord needed).
# The nginx configuration is written by the management daemon's web_update
# tool, so nginx may be reloaded via 'nginx -s reload' at runtime.

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

link_conf_to_storage /etc/nginx/conf.d nginx/conf.d

# managerd's web.sync_sites intent (run from the management container) writes
# managed server blocks here; nginx's own naust-sites.conf (below) includes
# them. mta-sts.txt is served straight off the management container's writes
# too, via the same shared-storage pattern.
link_conf_to_storage /etc/nginx/naust.d nginx/naust.d
link_conf_to_storage /var/lib/naust var-lib-naust

echo "Configuring nginx..."
cd "$NAUST/setup"
python3 -m components.runner web
cd "$NAUST"

# Stamp the box hostname into the panel's boot loader so first paint never
# waits on the API - same as panel.py's install-files step on bare metal,
# just done here since PRIMARY_HOSTNAME is only known at container start.
BOOT_JS=/usr/local/share/naust/frontend/dist/admin/boot.js
if [ -f "$BOOT_JS" ]; then
    cat > "$BOOT_JS" <<EOF
window.__BOX__ = { hostname: "${PRIMARY_HOSTNAME}" }
document.title = window.__BOX__.hostname
EOF
fi

echo "Nginx setup complete. Starting nginx and control socket server via supervisord..."
exec /usr/bin/supervisord -c /opt/naust/deploy/docker/nginx/supervisord.conf
