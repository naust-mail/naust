FROM ubuntu:26.04

ENV DEBIAN_FRONTEND=noninteractive

# Infrastructure packages not owned by any component def.
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update && apt-get install -y --no-install-recommends \
    supervisor \
    # python3-pip needed to install doit; python3 pulled in as a dep
    python3 python3-pip \
    # locales required for en_US.UTF-8
    locales \
    # dnsutils (dig/nslookup) for healthchecks and debugging - Docker-specific
    dnsutils \
    ca-certificates curl \
    && locale-gen en_US.UTF-8 \
    && pip3 install --break-system-packages --quiet doit exclusiveprocess \
    && rm -rf /var/lib/apt/lists/*

# Copy component defs before the full source COPY so this layer is only
# invalidated when component definitions change, not on every code change.
COPY setup/components /opt/naust/setup/components
WORKDIR /opt/naust

# Install component packages (nsd, ldnsutils, openssh-client, unbound, unbound-anchor).
# RUNTIME is unset here so ensure_installed() runs apt normally.
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update && \
    PYTHONPATH=/opt/naust/setup python3 -m components.runner --build-mode dns

COPY . /opt/naust
WORKDIR /opt/naust

COPY deploy/docker/dns/supervisord.conf /etc/supervisor/conf.d/dns.conf

COPY deploy/docker/dns/handlers/ /etc/naust/handlers/
COPY deploy/docker/control-socket-server.py /usr/local/sbin/control-socket-server
COPY deploy/docker/dns/entrypoint.sh /entrypoint.sh
RUN chmod +x /usr/local/sbin/control-socket-server /etc/naust/handlers/* /entrypoint.sh

# 53/tcp and 53/udp are exposed to the host network for public DNS.
EXPOSE 53/tcp 53/udp

ENTRYPOINT ["/entrypoint.sh"]
