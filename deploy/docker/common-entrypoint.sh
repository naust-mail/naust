#!/bin/bash
# Shared helpers sourced by every container entrypoint.
#
# Provides:
#   install_systemctl_stub  - replaces /usr/local/bin/systemctl with the stub
#   write_naust_conf   - writes /etc/naust.conf from env vars
#
# The container entrypoint must source this file early, before sourcing any
# NAUST setup script.

set -euo pipefail

install_systemctl_stub() {
    # Copy the stub into PATH so every subsequent 'systemctl ...' call in the
    # setup scripts is intercepted without any code changes to those scripts.
    cp /opt/naust/deploy/docker/systemctl-stub.sh /usr/local/bin/systemctl
    chmod +x /usr/local/bin/systemctl

    # Setup scripts also write systemd unit files via envsubst before calling
    # systemctl. The directory won't exist in Docker containers without systemd,
    # so create it to prevent those writes from aborting with set -euo pipefail.
    mkdir -p /lib/systemd/system
}

link_conf_to_storage() {
    # Symlink a container-local /etc/<service> path to $STORAGE_ROOT/conf/<subpath>
    # so that the management container can write configs and service containers
    # can read them via the shared storage volume - no service-specific volumes needed.
    # Usage: link_conf_to_storage /etc/nsd nsd
    local etc_path="$1"
    local sub_path="$2"
    local target="${STORAGE_ROOT:-/home/user-data}/conf/$sub_path"

    mkdir -p "$target"
    mkdir -p "$(dirname "$etc_path")"

    # Remove the directory created by apt package install if not already a symlink.
    if [ -d "$etc_path" ] && [ ! -L "$etc_path" ]; then
        rm -rf "$etc_path"
    fi

    ln -sfn "$target" "$etc_path"
}

write_naust_conf() {
    # Write /etc/naust.conf from environment variables.  All setup scripts
    # source this file on startup; in Docker the values come from the compose
    # environment instead of the interactive questions.sh wizard.
    #
    # Required env vars:
    #   PRIMARY_HOSTNAME  - the box's fully-qualified domain name
    #   PUBLIC_IP         - the server's public IPv4 address
    #   STORAGE_ROOT      - path to persistent data volume (default /home/user-data)
    #
    # Optional env vars:
    #   PUBLIC_IPV6       - public IPv6 address (empty string if not available)
    #   STORAGE_USER      - system user that owns STORAGE_ROOT (default user-data)
    #   PRIVATE_IP        - private/internal IPv4 (defaults to PUBLIC_IP)
    #   PRIVATE_IPV6      - private/internal IPv6 (defaults to PUBLIC_IPV6)
    #   ENABLE_FILEBROWSER, ENABLE_RADICALE, WEBMAIL_CLIENT, DNS_MODE, BACKUP_TOOL, SPAM_FILTER

    : "${PRIMARY_HOSTNAME:?PRIMARY_HOSTNAME env var is required}"
    : "${PUBLIC_IP:?PUBLIC_IP env var is required}"

    local storage_root="${STORAGE_ROOT:-/home/user-data}"
    local storage_user="${STORAGE_USER:-user-data}"
    local public_ipv6="${PUBLIC_IPV6:-}"
    local private_ip="${PRIVATE_IP:-$PUBLIC_IP}"
    local private_ipv6="${PRIVATE_IPV6:-$public_ipv6}"

    # Service host addresses - default to 127.0.0.1 (bare metal single-host).
    # In Docker these are overridden via compose environment to container service names.
    local mail_host="${MAIL_HOST:-127.0.0.1}"
    local dns_host="${DNS_HOST:-127.0.0.1}"
    local management_host="${MANAGEMENT_HOST:-127.0.0.1}"
    local webmail_host="${WEBMAIL_HOST:-127.0.0.1}"
    local filebrowser_host="${FILEBROWSER_HOST:-127.0.0.1}"
    local radicale_host="${RADICALE_HOST:-127.0.0.1}"
    local rspamd_host="${RSPAMD_HOST:-127.0.0.1}"
    local redis_host="${REDIS_HOST:-127.0.0.1}"
    local nginx_host="${NGINX_HOST:-127.0.0.1}"

    mkdir -p /etc
    cat > /etc/naust.conf <<EOF
STORAGE_USER=${storage_user}
STORAGE_ROOT=${storage_root}
PRIMARY_HOSTNAME=${PRIMARY_HOSTNAME}
PUBLIC_IP=${PUBLIC_IP}
PUBLIC_IPV6=${public_ipv6}
PRIVATE_IP=${private_ip}
PRIVATE_IPV6=${private_ipv6}
MTA_STS_MODE=${MTA_STS_MODE:-enforce}
ENABLE_FILEBROWSER=${ENABLE_FILEBROWSER:-false}
ENABLE_RADICALE=${ENABLE_RADICALE:-false}
WEBMAIL_CLIENT=${WEBMAIL_CLIENT:-rav}
DNS_MODE=${DNS_MODE:-self}
BACKUP_TOOL=${BACKUP_TOOL:-restic}
SPAM_FILTER=${SPAM_FILTER:-rspamd}
MAIL_HOST=${mail_host}
DNS_HOST=${dns_host}
MANAGEMENT_HOST=${management_host}
WEBMAIL_HOST=${webmail_host}
FILEBROWSER_HOST=${filebrowser_host}
RADICALE_HOST=${radicale_host}
RSPAMD_HOST=${rspamd_host}
REDIS_HOST=${redis_host}
NGINX_HOST=${nginx_host}
EOF

    # On bare metal, start.sh creates the STORAGE_USER OS account before sourcing
    # any setup script. Docker entrypoints skip start.sh, so create the user here.
    if ! id -u "${storage_user}" >/dev/null 2>&1; then
        useradd -r -m -d "${storage_root}" "${storage_user}"
    fi
}
