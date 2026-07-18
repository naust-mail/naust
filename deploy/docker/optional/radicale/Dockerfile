FROM ubuntu:26.04

ENV DEBIAN_FRONTEND=noninteractive

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-venv python3-pip \
    ca-certificates \
    locales \
    && locale-gen en_US.UTF-8 \
    && rm -rf /var/lib/apt/lists/*

# Install the component runner deps into the system Python so the entrypoint
# can invoke `python3 -m components.runner radicale` at startup.
RUN pip3 install --break-system-packages --quiet doit exclusiveprocess

# Copy the component definition first so the pip layer below is only
# invalidated when the Radicale package list in the component changes.
COPY setup/components/defs/optional/radicale.py /tmp/radicale_component.py

# Pre-install the Radicale venv at image build time so container startup
# skips the slow pip step (doit's uptodate check sees the venv directory
# already exists and marks radicale:venv uptodate on first run).
RUN --mount=type=cache,target=/root/.cache/pip \
    python3 -m venv /usr/local/lib/radicale && \
    /usr/local/lib/radicale/bin/python3 -m ensurepip --upgrade && \
    /usr/local/lib/radicale/bin/pip install --upgrade pip && \
    /usr/local/lib/radicale/bin/pip install "radicale>=3.1,<4" "passlib[bcrypt]"

COPY . /opt/naust
WORKDIR /opt/naust

COPY deploy/docker/optional/radicale/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Radicale listens on port 5232 (internal only - nginx proxies /.well-known/caldav etc.).
EXPOSE 5232

ENTRYPOINT ["/entrypoint.sh"]
