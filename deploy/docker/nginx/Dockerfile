FROM oven/bun:latest AS frontend-builder

# Copy only the frontend source so this layer is only invalidated when
# frontend files change, not when setup scripts or other repo files change.
COPY frontend/ /frontend/

RUN --mount=type=cache,target=/root/.bun/install/cache \
    cd /frontend && bun install --frozen-lockfile && bunx vite build

# ---------------------------------------------------------------------------

FROM ubuntu:26.04

ENV DEBIAN_FRONTEND=noninteractive

# Infrastructure packages not owned by any component def.
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update && apt-get install -y --no-install-recommends \
    # python3 is required by tools/editconf.py and control-socket-server
    python3 python3-pip \
    # supervisor manages nginx + control socket server
    supervisor \
    ca-certificates curl \
    # locales required for en_US.UTF-8
    locales \
    && locale-gen en_US.UTF-8 \
    && pip3 install --break-system-packages --quiet doit exclusiveprocess \
    && rm -rf /var/lib/apt/lists/*

# Copy component defs before the full source COPY so this layer is only
# invalidated when component definitions change, not on every code change.
COPY setup/components /opt/naust/setup/components
WORKDIR /opt/naust

# Install component packages (nginx, idn2).
# RUNTIME is unset here so ensure_installed() runs apt normally.
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update && \
    PYTHONPATH=/opt/naust/setup python3 -m components.runner --build-mode web

COPY . /opt/naust
WORKDIR /opt/naust

# Admin panel static bundle. apps.go's rendered nginx config serves /admin/
# straight off this FHS path (root /usr/local/share/naust/frontend/dist) -
# the same path bare metal's panel.py install-files step rsyncs to, so
# managerd's config never needs to know which runtime it's on.
COPY --from=frontend-builder /frontend/dist/admin /usr/local/share/naust/frontend/dist/admin

COPY deploy/docker/nginx/supervisord.conf /etc/supervisor/conf.d/nginx.conf
COPY deploy/docker/nginx/handlers/ /etc/naust/handlers/
COPY deploy/docker/control-socket-server.py /usr/local/sbin/control-socket-server
COPY deploy/docker/nginx/entrypoint.sh /entrypoint.sh
RUN chmod +x /usr/local/sbin/control-socket-server /etc/naust/handlers/* /entrypoint.sh

EXPOSE 80 443

ENTRYPOINT ["/entrypoint.sh"]
