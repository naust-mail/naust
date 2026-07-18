FROM ubuntu:26.04

ENV DEBIAN_FRONTEND=noninteractive

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update && apt-get install -y --no-install-recommends \
    # FileBrowser binary is a static Go binary; only needs wget/tar to fetch it.
    wget ca-certificates \
    # Python3 is used by the IMAP auth hook script and control-socket-server.
    python3 \
    # envsubst used by filebrowser.sh to stamp the systemd unit file.
    gettext-base \
    # sudo lets supervisord drop to www-data for the FileBrowser process.
    sudo \
    # supervisor manages filebrowser + control socket server.
    supervisor \
    # locales required for en_US.UTF-8
    locales \
    && locale-gen en_US.UTF-8 \
    && rm -rf /var/lib/apt/lists/*

# Download and verify the FileBrowser binary at build time so the container
# does not need network access at runtime. filebrowser.sh skips the download
# when /usr/local/bin/filebrowser already exists and matches the pinned version.
RUN wget -O /tmp/filebrowser.tar.gz \
      https://github.com/filebrowser/filebrowser/releases/download/v2.63.11/linux-amd64-filebrowser.tar.gz && \
    echo "4bc72dad029d531d153b58bd63a3dabf74c0b395  /tmp/filebrowser.tar.gz" | sha1sum -c && \
    tar -xzf /tmp/filebrowser.tar.gz -C /usr/local/bin filebrowser && \
    chmod +x /usr/local/bin/filebrowser && \
    rm /tmp/filebrowser.tar.gz && \
    mkdir -p /usr/local/share && echo "v2.63.11" > /usr/local/share/filebrowser.version

RUN apt-get update && apt-get install -y --no-install-recommends python3-pip \
    && rm -rf /var/lib/apt/lists/*
RUN pip3 install --break-system-packages --quiet doit exclusiveprocess

COPY . /opt/naust
WORKDIR /opt/naust

COPY deploy/docker/optional/filebrowser/supervisord.conf /etc/supervisor/conf.d/filebrowser.conf
COPY deploy/docker/optional/filebrowser/handlers/ /etc/naust/handlers/
COPY deploy/docker/control-socket-server.py /usr/local/sbin/control-socket-server
COPY deploy/docker/optional/filebrowser/entrypoint.sh /entrypoint.sh
RUN chmod +x /usr/local/sbin/control-socket-server /etc/naust/handlers/* /entrypoint.sh

# FileBrowser listens on port 8080 (internal only - nginx proxies /files).
EXPOSE 8080

ENTRYPOINT ["/entrypoint.sh"]
