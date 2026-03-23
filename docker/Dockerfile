# Linux development and test environment for go-acl.
#
# Uses the official Go image (Debian Bookworm base) so the Go toolchain is
# pre-installed and matches the version used in CI.
#
# The repo is mounted at /workspace at runtime (see docker-compose.yml) so
# source changes on the host are immediately visible inside the container
# without a rebuild.
#
# Usage (via justfile):
#   just docker test     # run go test ./... inside the container
#   just docker shell    # open an interactive shell for exploration

# Copy golangci-lint binary from the official release image (pinned version).
FROM golangci/golangci-lint:v2.11.3 AS golangci-lint-bin

FROM golang:1.24-bookworm

# Bring in golangci-lint from the official release image.
COPY --from=golangci-lint-bin /usr/bin/golangci-lint /usr/local/bin/golangci-lint

# Install libacl1-dev (required by '#cgo linux LDFLAGS: -lacl') and the
# acl(1) CLI tools for manual inspection / round-trip testing.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        libacl1-dev \
        acl \
 && rm -rf /var/lib/apt/lists/*

# Install just (task runner) from a pinned GitHub release tarball.
# Extracts only the `just` binary — no pipe-to-bash involved.
ARG JUST_VERSION=1.47.1
RUN set -eux; \
    ARCH="$(uname -m)"; \
    curl -sSfL "https://github.com/casey/just/releases/download/${JUST_VERSION}/just-${JUST_VERSION}-${ARCH}-unknown-linux-musl.tar.gz" \
      | tar xz -C /usr/local/bin just

WORKDIR /workspace

# Default command drops into a shell so the container is useful interactively.
CMD ["bash"]
