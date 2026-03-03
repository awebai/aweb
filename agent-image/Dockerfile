FROM node:22

ARG TARGETARCH

ENV DEBIAN_FRONTEND=noninteractive

# Core tools: git, gh, sudo, essentials
RUN apt-get update && apt-get install -y --no-install-recommends \
    sudo \
    curl \
    ca-certificates \
    gnupg \
    jq \
    openssh-client \
    redis-tools \
    gh \
    android-tools-adb \
    && rm -rf /var/lib/apt/lists/*

# kubectl
RUN curl -fsSL "https://dl.k8s.io/release/$(curl -fsSL https://dl.k8s.io/release/stable.txt)/bin/linux/${TARGETARCH}/kubectl" \
    -o /usr/local/bin/kubectl \
    && chmod +x /usr/local/bin/kubectl

# Dolt (required by beads CLI for issue database)
RUN curl -fsSL "https://github.com/dolthub/dolt/releases/latest/download/dolt-linux-${TARGETARCH}.tar.gz" \
    | tar -xz -C /usr/local --strip-components=1 dolt-linux-${TARGETARCH}/bin/dolt

# Wrangler
RUN npm install -g wrangler

# beads (bd) + bdh CLI
RUN curl -fsSL https://raw.githubusercontent.com/steveyegge/beads/main/scripts/install.sh | bash \
    && curl -fsSL https://raw.githubusercontent.com/beadhub/bdh/main/install.sh | bash

# node user (UID 1000) already exists in node:22 base — give it sudo
RUN echo "node ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/node

# Claude Code config: skip ALL interactive prompts + dangerously skip permissions
RUN mkdir -p /home/node/.claude \
    && echo '{"hasCompletedOnboarding": true, "hasTrustDialogAccepted": true, "hasTrustDialogHooksAccepted": true}' > /home/node/.claude.json \
    && echo '{"skipDangerousModePermissionPrompt": true}' > /home/node/.claude/settings.json \
    && chown -R node:node /home/node/.claude /home/node/.claude.json

USER node
WORKDIR /home/node

# Claude Code — native install as node user (required for `claude remote-control`)
# npm-installed Claude Code fails with `node: bad option: --sdk-url`
RUN curl -fsSL https://claude.ai/install.sh | bash
ENV PATH="/home/node/.local/bin:${PATH}"

# No ENTRYPOINT — K8s manifest controls command/args
CMD ["bash"]
