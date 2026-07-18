#!/bin/bash
# Stub replacement for systemctl inside Docker containers.
#
# Install this file to /usr/local/bin/systemctl before sourcing any NAUST
# setup script.  Routes service-lifecycle verbs through the per-service
# handler scripts in /etc/naust/handlers/ (same dispatch path as the
# control-socket-server).  Falls back to supervisorctl for services that
# have no handler.
#
# Service names passed to systemctl may have a ".service" suffix, and callers
# may pass flags (e.g. "is-active --quiet naust-managerd") before the unit
# name; the stub takes the last non-flag argument as the service name.

verb="$1"
shift
svc=""
for arg in "$@"; do
    case "$arg" in
        -*) ;;
        *) svc="$arg" ;;
    esac
done
svc="${svc%.service}"

case "$verb" in
    daemon-reload|enable|disable|is-enabled|unmask|link)
        exit 0
        ;;
    is-active)
        # naust's own systemd units are named naust-<process> (see
        # daemon/systemd/); the process actually running under supervisord
        # here has no naust- prefix. Third-party services (fail2ban, nginx,
        # postfix, ...) have no prefix to strip either way.
        proc="${svc#naust-}"
        pgrep -x "${proc}" >/dev/null 2>&1
        exit $?
        ;;
    start|restart|reload|stop)
        # Dispatch through the per-service handler when supervisord is running,
        # so setup-script restarts use the same path as socket-server requests.
        # When supervisord is not yet running (first-time container setup),
        # silently skip: the service will start fresh under supervisord at the
        # end of the entrypoint anyway.
        if [ -x "/etc/naust/handlers/${svc}" ] && [ -S /run/supervisor.sock ]; then
            exec /etc/naust/handlers/"${svc}" "${verb}"
        else
            supervisorctl "${verb}" "${svc}" 2>/dev/null || true
        fi
        ;;
    *)
        exit 0
        ;;
esac
