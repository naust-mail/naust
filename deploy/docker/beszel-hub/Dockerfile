FROM debian:bookworm-slim

ARG BESZEL_VERSION=0.18.7
ARG BESZEL_SHA256=b75c52a82af5c9721f08a7a9cb0c16df27e81967a3855cef7c77dbad9fb43524

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates \
    # python3/pip run the beszel component: creates the beszel system user
    # and generates the hub<->agent keypair + hub.env/agent.env/config.yml
    # onto the shared storage volume (self-contained, matching munin's
    # Docker pattern - management runs no Python setup component itself).
    python3 python3-pip \
    # ssh-keygen (hub<->agent Ed25519 keypair)
    openssh-client \
    && pip3 install --break-system-packages --quiet doit exclusiveprocess \
    && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL "https://github.com/henrygd/beszel/releases/download/v${BESZEL_VERSION}/beszel_linux_amd64.tar.gz" \
        -o /tmp/beszel.tar.gz \
    && echo "${BESZEL_SHA256}  /tmp/beszel.tar.gz" | sha256sum -c - \
    && tar -xzf /tmp/beszel.tar.gz -C /usr/local/bin beszel \
    && chmod +x /usr/local/bin/beszel \
    && rm /tmp/beszel.tar.gz

COPY . /opt/naust
WORKDIR /opt/naust

COPY deploy/docker/beszel-hub/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 8090

ENTRYPOINT ["/entrypoint.sh"]
