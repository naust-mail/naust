# muninweb builder: the static HTTP face for munin (serves the cron-rendered
# site and wraps munin-cgi-graph). Stdlib-only, so this stage downloads no
# modules. Bare metal installs this via the daemon component; Docker images
# ship their binaries at image build time.
FROM golang:1.25 AS daemon-builder

COPY daemon /daemon
RUN cd /daemon && CGO_ENABLED=0 go build -o /muninweb ./cmd/muninweb

# ---------------------------------------------------------------------------

FROM ubuntu:26.04

ENV DEBIAN_FRONTEND=noninteractive

# Infrastructure packages not owned by any component def.
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update && apt-get install -y --no-install-recommends \
    supervisor \
    # python3 is required by tools/editconf.py (#!/usr/bin/python3 shebang)
    python3 python3-pip \
    # locales required by munin-node (Perl daemon - fails without a valid locale)
    locales \
    ca-certificates curl \
    && locale-gen en_US.UTF-8 \
    && pip3 install --break-system-packages --quiet doit exclusiveprocess \
    && rm -rf /var/lib/apt/lists/*

# Copy component defs before the full source COPY so this layer is only
# invalidated when component definitions change, not on every code change.
COPY setup/components /opt/naust/setup/components
WORKDIR /opt/naust

# Install component packages (munin, munin-node, libcgi-fast-perl, procps, sudo).
# RUNTIME is unset here so ensure_installed() runs apt normally.
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update && \
    PYTHONPATH=/opt/naust/setup python3 -m components.runner --build-mode munin

COPY . /opt/naust

COPY --from=daemon-builder /muninweb /usr/local/lib/naust/muninweb

COPY deploy/docker/monitoring/supervisord.conf /etc/supervisor/conf.d/monitoring.conf

COPY deploy/docker/monitoring/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# muninweb serves the rendered site + graph CGI on 4948; munin-node's
# collection protocol is on 4949. Both stay on the internal network.
EXPOSE 4948 4949

ENTRYPOINT ["/entrypoint.sh"]
