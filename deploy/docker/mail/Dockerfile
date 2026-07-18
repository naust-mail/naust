FROM ubuntu:26.04

ENV DEBIAN_FRONTEND=noninteractive

# Infrastructure packages not owned by any component def.
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update && apt-get install -y --no-install-recommends \
    # Supervisor manages multiple processes inside the container
    supervisor \
    # Python used by management tools called from mail setup.
    # python3-idna: mailconfig.py imports idna at module level - on bare metal this
    # rides in as a transitive dep of certbot, but this container never installs certbot.
    python3 python3-pip python3-idna \
    # locales required for en_US.UTF-8 (Postfix, Dovecot, and Python all need it)
    locales \
    # Misc utilities
    ca-certificates curl wget git \
    && locale-gen en_US.UTF-8 \
    && pip3 install --break-system-packages --quiet doit exclusiveprocess \
    && rm -rf /var/lib/apt/lists/*

# Copy component defs before the full source COPY so this layer is only
# invalidated when component definitions change, not on every code change.
COPY setup/components /opt/naust/setup/components
WORKDIR /opt/naust

# Install component packages (postfix, dovecot, openssl, etc.) derived from
# component defs - no manual list to keep in sync.
# RUNTIME is unset here so ensure_installed() runs apt normally.
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update && \
    PYTHONPATH=/opt/naust/setup python3 -m components.runner --build-mode ssl postfix dovecot

# Pin dovecot's system group to a fixed gid. managerd (in the separate
# management container) writes mail/materialized/dovecot-users - the
# passwd-file dovecot's auth process reads for login - and needs to chown
# it to a group dovecot can actually read with (its own supplementary
# groups are dropped for its worker processes; only its primary gid
# applies). apt assigns dovecot's gid sequentially at install time, so it
# is not stable across image rebuilds - pinning it here and creating a
# matching group of the same gid in management's entrypoint is what lets
# the two independently-built images agree on one number.
RUN groupmod -g 8991 dovecot

COPY . /opt/naust
WORKDIR /opt/naust

# supervisord configuration
COPY deploy/docker/mail/supervisord.conf /etc/supervisor/conf.d/mail.conf

COPY deploy/docker/mail/handlers/ /etc/naust/handlers/
COPY deploy/docker/control-socket-server.py /usr/local/sbin/control-socket-server
COPY deploy/docker/mail/entrypoint.sh /entrypoint.sh
RUN chmod +x /usr/local/sbin/control-socket-server /etc/naust/handlers/* /entrypoint.sh

EXPOSE 25 465 587 993 4190

ENTRYPOINT ["/entrypoint.sh"]
