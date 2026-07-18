# rav
#
# Backend binary + built frontend are fetched as a single prebuilt release
# tarball from naust-mail/rav's release CI - nothing is compiled here.

FROM ubuntu:26.04

SHELL ["/bin/bash", "-c"]

ENV DEBIAN_FRONTEND=noninteractive

# Runtime shared libraries only - no build tools, no Rust, no Bun.
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates wget \
    libssl3 libsqlite3-0 \
    # sudo to drop to www-data when starting the server
    sudo \
    # locales required for en_US.UTF-8
    locales \
    && locale-gen en_US.UTF-8 \
    && rm -rf /var/lib/apt/lists/*

# Pinned prebuilt release - keep these three in sync with
# setup/components/defs/webmail/rav.py's RAV_VERSION/RAV_ASSET/RAV_SHA256. The hash is
# copied here from that release's checksums.txt, not fetched at build time -
# fetching it from the same place as the binary would give a compromised
# release nothing independent to be caught by.
ARG RAV_VERSION="v0.2.1+7e88db7"
ARG RAV_ASSET="rav-email-server-linux-x86_64.tar.gz"
ARG RAV_SHA256="3b85e6ee90c4b170192437f99ea091c16f5661432e289600b0a11d5ef7358e61"

RUN set -euo pipefail && \
    RAV_URL="https://github.com/naust-mail/rav/releases/download/${RAV_VERSION//+/%2B}/${RAV_ASSET}" && \
    wget -O /tmp/rav.tar.gz "$RAV_URL" && \
    echo "${RAV_SHA256}  /tmp/rav.tar.gz" | sha256sum --check --strict && \
    mkdir -p /tmp/rav-extract && \
    tar -xzf /tmp/rav.tar.gz -C /tmp/rav-extract && \
    mv /tmp/rav-extract/rav-email-server /usr/local/bin/rav-server && \
    chmod 755 /usr/local/bin/rav-server && \
    mkdir -p /usr/local/share/rav/static && \
    cp -a /tmp/rav-extract/static/. /usr/local/share/rav/static/ && \
    rm -rf /tmp/rav.tar.gz /tmp/rav-extract

# Copy the NAUST repo so the entrypoint has access to shared helpers
# (common-entrypoint.sh) and the storage volume config path.
COPY . /opt/naust
WORKDIR /opt/naust

COPY deploy/docker/webmail/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# rav listens on port 3001 by default.
EXPOSE 3001

ENTRYPOINT ["/entrypoint.sh"]
