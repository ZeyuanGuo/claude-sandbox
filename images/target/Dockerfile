ARG BASE_IMAGE=docker.io/library/ubuntu@sha256:4fbb8e6a8395de5a7550b33509421a2bafbc0aab6c06ba2cef9ebffbc7092d90
FROM ${BASE_IMAGE}

ARG TARGET_NAME=developer
ARG TARGET_UID=1000
ARG TARGET_GID=1000
ARG TARGET_HOME=/home/developer
ARG TARGET_TIMEZONE=UTC
ARG TARGET_BUILD_DIGEST
ARG NODE_VERSION=22.23.1
ARG NODE_SHA256=9749e988f437343b7fa832c69ded82a312e41a03116d766797ac14f6f9eee578
ARG CODEX_VERSION=0.147.0

ENV DEBIAN_FRONTEND=noninteractive \
    TZ=${TARGET_TIMEZONE} \
    LANG=en_US.UTF-8 \
    LC_ALL=en_US.UTF-8

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bash-completion \
        build-essential \
        ca-certificates \
        curl \
        dnsutils \
        fd-find \
        file \
        fontconfig \
        fonts-dejavu-core \
        fonts-liberation \
        git \
        gnupg \
        iproute2 \
        iputils-ping \
        jq \
        less \
        locales \
        lsof \
        nano \
        netcat-openbsd \
        openssh-client \
        procps \
        python3 \
        python3-pip \
        python3-venv \
        ripgrep \
        screen \
        strace \
        sudo \
        tmux \
        tzdata \
        unzip \
        vim-tiny \
        wget \
        xz-utils \
        zip \
    && locale-gen en_US.UTF-8 \
    && test -f "/usr/share/zoneinfo/${TZ}" \
    && ln -snf "/usr/share/zoneinfo/${TZ}" /etc/localtime \
    && printf '%s\n' "${TZ}" > /etc/timezone \
    && groupadd --gid "${TARGET_GID}" "${TARGET_NAME}" \
    && useradd --uid "${TARGET_UID}" --gid "${TARGET_GID}" \
        --home-dir "${TARGET_HOME}" --create-home --shell /bin/bash "${TARGET_NAME}" \
    && curl --fail --silent --show-error --location \
        "https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-x64.tar.xz" \
        --output /tmp/node.tar.xz \
    && printf '%s  %s\n' "${NODE_SHA256}" /tmp/node.tar.xz | sha256sum --check --strict \
    && tar --extract --file /tmp/node.tar.xz --directory /usr/local --strip-components=1 \
    && rm -f /tmp/node.tar.xz \
    && ln -s /usr/bin/fdfind /usr/local/bin/fd \
    && npm install --global @anthropic-ai/claude-code@2.1.220 \
    && npm install --global "@openai/codex@${CODEX_VERSION}" \
    && npm cache clean --force \
    && usermod --append --groups sudo "${TARGET_NAME}" \
    && rm -rf /var/lib/apt/lists/*

LABEL org.controlled-dev-machine.target-build-digest=${TARGET_BUILD_DIGEST}

USER ${TARGET_UID}:${TARGET_GID}
WORKDIR ${TARGET_HOME}

CMD ["sleep", "infinity"]
