#!/bin/bash
# DNS container entrypoint.
#
# Runs: nsd (authoritative, port 5353 inside container mapped to host :53)
#       unbound (recursive resolver, port 53 inside container for other containers)

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

link_conf_to_storage /etc/nsd nsd

echo "Configuring DNS services..."
cd "$NAUST/setup"
python3 -m components.runner dns
cd "$NAUST"

# Write a Docker-specific unbound config. On bare metal unbound listens only on
# 127.0.0.1; here it must answer on all interfaces so other containers can reach
# it as their recursive resolver over the Docker bridge.
mkdir -p /etc/unbound/unbound.conf.d
cat > /etc/unbound/unbound.conf.d/naust.conf << 'EOF'
server:
    interface: 0.0.0.0
    port: 53
    do-ip6: no
    access-control: 0.0.0.0/0 allow
    hide-identity: yes
    hide-version: yes
    harden-glue: yes
    harden-dnssec-stripped: yes
    use-caps-for-id: yes
    cache-min-ttl: 300
    cache-max-ttl: 86400

remote-control:
    control-enable: yes
    control-use-cert: no
    control-interface: /var/run/unbound.ctl
EOF

echo "DNS setup complete. Patching NSD config for Docker..."

# On bare metal, NSD binds to PRIVATE_IP and bind9 binds to 127.0.0.1 - they
# coexist on port 53 because they use different IPs.  In Docker the container
# only has a bridge IP, not the external IP, so NSD can't bind to PRIVATE_IP.
# Also, bind9 is patched above to listen on any (port 53) so that other
# containers can use it as their recursive resolver via 172.20.0.2.  To avoid
# a port conflict we move NSD to port 5353 inside the container; the compose
# file maps host port 53 (or PORT_DNS) to container port 5353.
sed -i '/^\s*ip-address:/d' /etc/nsd/nsd.conf
sed -i '/^server:/a\  port: 5353' /etc/nsd/nsd.conf

# nsd.conf contains: include: /etc/nsd/nsd.conf.d/*.conf
# On first boot the management daemon has not yet written zones.conf to that
# directory.  NSD treats a non-matching glob as a parse error and exits 1.
# Create an empty placeholder so the include is always satisfied.  The
# management daemon will overwrite this file with real zone definitions.
touch /etc/nsd/nsd.conf.d/zones.conf

# NSD 4.8+ requires remote control TLS certificates to start.  On bare metal
# the package postinstall generates them in /etc/nsd/.  In Docker, /etc/nsd/
# is symlinked to the storage volume (which starts empty), so they are never
# present on first boot.  nsd-control-setup writes them into /etc/nsd/ which
# persists into the volume for subsequent restarts.
if [ ! -f /etc/nsd/nsd_server.pem ]; then
    echo "Generating NSD remote control certificates..."
    nsd-control-setup
fi

# Unbound requires the root trust anchor to validate DNSSEC signatures.  The
# unbound-anchor utility generates this file, but it needs to write it to a location
# that persists across container restarts.  Use /var/lib/unbound/ which is the default
# location for the root.key file on Debian/Ubuntu and is writable by the unbound user
if [ ! -f /var/lib/unbound/root.key ]; then
    echo "Initializing Unbound DNSSEC trust anchor..."
    mkdir -p /var/lib/unbound
    # unbound-anchor exits 1 when it updates the anchor (success), 0 if unchanged.
    # Both are fine - suppress the exit code so set -e doesn't kill the script.
    unbound-anchor -a /var/lib/unbound/root.key || true

    chown unbound:unbound /var/lib/unbound/root.key
    chmod 644 /var/lib/unbound/root.key
fi

echo "Starting supervisord..."
exec /usr/bin/supervisord -c /etc/supervisor/supervisord.conf
