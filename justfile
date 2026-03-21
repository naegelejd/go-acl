# Default: list available recipes
default: list

# List all available recipes
list:
    @just --list

# ── Full cross-platform pipeline ────────────────────────────────────────────

# Run the complete build/vet/test/cover/roundtrip pipeline on macOS AND Linux.
# Use this as the single command before committing or tagging a release.
all:
    @echo ''
    @echo '════════════════════════════════════════'
    @echo '  macOS (native)'
    @echo '════════════════════════════════════════'
    just build
    just vet
    just lint
    just cover
    just roundtrip
    @echo ''
    @echo '════════════════════════════════════════'
    @echo '  Linux (Docker)'
    @echo '════════════════════════════════════════'
    just build-docker
    just docker build
    just docker vet
    just docker lint
    just docker cover
    just docker roundtrip-linux
    just docker test

# ── macOS recipes ────────────────────────────────────────────────────────────

# Build all packages
build:
    go build ./...

# Run all tests
test:
    go test ./...

# Run go vet
vet:
    go vet ./...

# Run golangci-lint
lint:
    golangci-lint run ./...

# Run vet + tests
check: vet test

# Run getfacl on a file (default: go.mod)
getfacl file="go.mod":
    go run ./getfacl/ {{file}}

# Run setfacl on a file (macOS format: type:name:action:perms)
setfacl args file="go.mod":
    go run ./setfacl/ {{args}} {{file}}

# Round-trip: grant access, display, delete, display (macOS)
roundtrip:
    touch /tmp/acl-roundtrip-test
    @echo '--- set ACL ---'
    go run ./setfacl/ -m "user:$(whoami):allow:read,write,execute" /tmp/acl-roundtrip-test
    @echo '--- getfacl after set ---'
    go run ./getfacl/ /tmp/acl-roundtrip-test
    @echo '--- delete all ACL entries (-b) ---'
    go run ./setfacl/ -b /tmp/acl-roundtrip-test
    @echo '--- getfacl after delete (should be empty) ---'
    go run ./getfacl/ /tmp/acl-roundtrip-test
    rm /tmp/acl-roundtrip-test

# Round-trip: grant access, display, delete, display (Linux POSIX format)
roundtrip-linux:
    touch /tmp/acl-roundtrip-test
    @echo '--- set ACL ---'
    go run ./setfacl/ -m "user:$(whoami):rwx" /tmp/acl-roundtrip-test
    @echo '--- getfacl after set ---'
    go run ./getfacl/ /tmp/acl-roundtrip-test
    @echo '--- delete all extended ACL entries (-b) ---'
    go run ./setfacl/ -b /tmp/acl-roundtrip-test
    @echo '--- getfacl after delete (base entries only) ---'
    go run ./getfacl/ /tmp/acl-roundtrip-test
    rm /tmp/acl-roundtrip-test

# ── Docker (Linux) recipes ───────────────────────────────────────────────────

# Build the Linux Docker image
build-docker:
    docker compose -f docker/docker-compose.yml build --quiet

# Run any just recipe inside the Linux Docker container: just docker build, just docker test, etc.
docker recipe:
    RECIPE={{recipe}} docker compose -f docker/docker-compose.yml run --rm runner

# Open an interactive shell inside the Linux Docker container
docker-shell:
    docker compose -f docker/docker-compose.yml run --rm dev

# Show per-function test coverage summary
cover:
    go test -coverprofile=coverage.out ./...
    go tool cover -func=coverage.out
    rm coverage.out

# Open interactive HTML coverage report in the browser
cover-html:
    go test -coverprofile=coverage.out ./...
    go tool cover -html=coverage.out
    rm coverage.out

# Serve godoc locally
docs:
    CGO_ENABLED=1 pkgsite -open .
