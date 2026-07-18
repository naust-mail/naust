#!/bin/bash
# Mail container entrypoint.
#
# Runs: postfix, dovecot
# Spam filtering (rspamd) and Redis run in separate containers.
#
# The NAUST setup scripts are sourced with RUNTIME=docker so that apt_install,
# ufw_allow etc. no-op, and 'systemctl start/restart' calls are forwarded to
# supervisorctl via the stub.

set -euo pipefail

NAUST=/opt/naust
source "$NAUST/deploy/docker/common-entrypoint.sh"

install_systemctl_stub
write_naust_conf

export RUNTIME=docker

cd "$NAUST"

# Ensure locale is set - some setup scripts depend on it.
export LANGUAGE=en_US.UTF-8
export LC_ALL=en_US.UTF-8
export LANG=en_US.UTF-8
export LC_TYPE=en_US.UTF-8

# Ensure the storage directories the mail scripts expect exist.
source /etc/naust.conf
mkdir -p "$STORAGE_ROOT"

if [ "${SPAM_FILTER:-rspamd}" = "spamassassin" ]; then
    link_conf_to_storage /etc/opendkim opendkim
fi

# Generate TLS certificates and configure mail services via the component runner.
# ssl must run before postfix/dovecot (they refuse to start without a cert).
echo "Configuring mail services..."
cd "$NAUST/setup"
python3 -m components.runner ssl postfix dovecot users
cd "$NAUST"

# Rspamd runs in its own container. Wire Postfix to use it as a milter and
# set the transport/restrictions that rspamd.sh would normally set on bare metal.
RSPAMD_HOST="${RSPAMD_HOST:-rspamd}"
echo "Wiring Postfix milter to rspamd at ${RSPAMD_HOST}:11332..."
python3 setup/tools/editconf.py /etc/postfix/main.cf \
    "virtual_transport=lmtp:unix:private/dovecot-lmtp"
python3 setup/tools/editconf.py /etc/postfix/main.cf -e \
    lmtp_destination_recipient_limit=
python3 setup/tools/editconf.py /etc/postfix/main.cf \
    "smtpd_milters=inet:${RSPAMD_HOST}:11332" \
    "non_smtpd_milters=inet:${RSPAMD_HOST}:11332" \
    milter_default_action=accept
python3 setup/tools/editconf.py /etc/postfix/main.cf \
    smtpd_recipient_restrictions="permit_sasl_authenticated,permit_mynetworks,reject_rbl_client zen.spamhaus.org=127.0.0.[2..11],reject_unlisted_recipient,check_policy_service inet:127.0.0.1:12340"

if [ "${ENABLE_CLAMAV:-false}" = "true" ]; then
    CLAMAV_HOST="${CLAMAV_HOST:-clamav}"
    echo "Wiring Postfix milter to clamav-milter at ${CLAMAV_HOST}:7357..."
    CURRENT_MILTERS=$(postconf -h smtpd_milters 2>/dev/null | sed 's/[[:space:]]*$//')
    if [[ "$CURRENT_MILTERS" != *"${CLAMAV_HOST}:7357"* ]]; then
        python3 setup/tools/editconf.py /etc/postfix/main.cf \
            "smtpd_milters=${CURRENT_MILTERS:+$CURRENT_MILTERS }inet:${CLAMAV_HOST}:7357"
        python3 setup/tools/editconf.py /etc/postfix/main.cf \
            "non_smtpd_milters=\$smtpd_milters"
    fi
fi

echo "Mail setup complete. Starting supervisord..."
exec /usr/bin/supervisord -c /etc/supervisor/supervisord.conf
