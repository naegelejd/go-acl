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

FROM golang:1.24-bookworm

# Install libacl1-dev (required by '#cgo linux LDFLAGS: -lacl'), the
# acl(1) CLI tools for manual inspection / round-trip testing, and
# just (task runner) so container recipes match the host exactly.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        libacl1-dev \
        acl \
 && rm -rf /var/lib/apt/lists/* \
 && curl -sSfL https://just.systems/install.sh | bash -s -- --to /usr/local/bin \
 && curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh \
    | sh -s -- -b /usr/local/bin latest

WORKDIR /workspace

# Default command drops into a shell so the container is useful interactively.
CMD ["bash"]
