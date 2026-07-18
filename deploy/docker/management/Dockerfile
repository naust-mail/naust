# go-builder: compiles managerd, helperd, and boxctl from daemon/. Pure Go
# (modernc.org/sqlite - no CGO), so no gcc needed. Runs in parallel with the
# main stage's apt bootstrap (the slowest step).

FROM golang:1.25 AS go-builder

COPY daemon/ /daemon/
WORKDIR /daemon

RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    CGO_ENABLED=0 go build -o /out/managerd ./cmd/managerd && \
    CGO_ENABLED=0 go build -o /out/helperd ./cmd/helperd && \
    CGO_ENABLED=0 go build -o /out/boxctl ./cmd/boxctl

# ---------------------------------------------------------------------------

FROM ubuntu:26.04

ENV DEBIAN_FRONTEND=noninteractive

ARG BACKUP_TOOL=restic

# Bootstrap: minimal set of packages this container needs. python3 runs the
# setup component runner (for $BACKUP_TOOL) and the Docker shims'
# _socket_send.py; supervisor manages helperd + managerd; the Go daemons
# themselves need nothing beyond libc.
# git is not needed - Docker images have no .git dir and the version file is written at runtime.
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    echo "postfix postfix/main_mailer_type select No configuration" | debconf-set-selections && \
    apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip \
    # supervisor manages helperd + managerd
    supervisor \
    # ldnsutils: provides ldns-signzone, which managerd's dnsapply execs
    # directly (DNSSEC signing happens in-process, not via helperd)
    ldnsutils \
    # postfix: only its CLI tools (postmap, postconf, postqueue) are used
    # here. managerd's materializer execs postmap to build the lookup maps
    # Postfix reads from shared storage in the separate mail container, and
    # the mail-tls/mail-queue checks exec postconf/postqueue. The postfix
    # daemon itself never runs in this container (not in supervisord.conf).
    postfix \
    # locales: managerd requires en_US.UTF-8 for email header handling
    locales \
    # curl: used by backup and cert renewal scripts; ca-certificates: TLS trust store
    curl ca-certificates \
    # gnupg: duplicity uses GPG for backup encryption; not needed for restic
    $([ "$BACKUP_TOOL" = "duplicity" ] && echo gnupg) \
    && locale-gen en_US.UTF-8 \
    # "No configuration" (above) skips writing main.cf entirely, but
    # postmap/postconf/postqueue all read config_directory and friends
    # from it even for a standalone map build - seed the package's own
    # default template so those reads succeed. This file is never used to
    # run a postfix daemon in this container.
    && cp /etc/postfix/main.cf.proto /etc/postfix/main.cf \
    && rm -rf /var/lib/apt/lists/*

RUN --mount=type=cache,target=/root/.cache/pip \
    pip3 install --break-system-packages --quiet doit exclusiveprocess

ENV LANG=en_US.UTF-8
ENV LC_ALL=en_US.UTF-8

# Copy component defs before the full source COPY so this apt+pip layer is only
# invalidated when component definitions change, not on every code change.
COPY setup/components /opt/naust/setup/components
WORKDIR /opt/naust

# Install $BACKUP_TOOL's packages (restic binary or duplicity + gnupg deps).
# RUNTIME is unset here so ensure_installed() runs apt normally.
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update && \
    PYTHONPATH=/opt/naust/setup python3 -m components.runner --build-mode $BACKUP_TOOL

COPY . /opt/naust

# Go daemon binaries, matching bare metal's install locations exactly (the
# systemd units and boxctl's own conventions both assume these paths).
COPY --from=go-builder /out/managerd /out/helperd /usr/local/lib/naust/
COPY --from=go-builder /out/boxctl /usr/local/bin/boxctl
RUN chmod +x /usr/local/lib/naust/managerd /usr/local/lib/naust/helperd /usr/local/bin/boxctl \
    && ln -s /usr/local/bin/boxctl /usr/local/bin/naust

# Docker shims: intercept helperd's systemctl/nginx/nsd-control/unbound-control
# calls and route them through the cross-container control-socket-server
# bridge instead - see deploy/docker/management/bin/. helperd execs these by
# fixed absolute path (daemon/internal/helper), not via $PATH lookup, so the
# shims are installed at those exact paths rather than relying on PATH order.
COPY deploy/docker/management/bin/_socket_send.py /usr/local/lib/naust/_socket_send.py
COPY deploy/docker/management/bin/systemctl /usr/bin/systemctl
COPY deploy/docker/management/bin/nginx /usr/sbin/nginx
COPY deploy/docker/management/bin/nsd-control /usr/sbin/nsd-control
COPY deploy/docker/management/bin/unbound-control /usr/sbin/unbound-control
RUN chmod +x /usr/local/lib/naust/_socket_send.py /usr/bin/systemctl /usr/sbin/nginx \
    /usr/sbin/nsd-control /usr/sbin/unbound-control

COPY deploy/docker/management/supervisord.conf /etc/supervisor/conf.d/management.conf

COPY deploy/docker/management/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ARG GIT_SHA=unknown
RUN mkdir -p /usr/local/share/naust && echo "$GIT_SHA" > /usr/local/share/naust/version

# managerd's API port - must be reachable from nginx (on the Docker bridge).
EXPOSE 10223

ENTRYPOINT ["/entrypoint.sh"]
