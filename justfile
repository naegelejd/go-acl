# Default: list available recipes
default: check

# Build all packages
build:
    go build -v ./...

# Run all tests
test:
    go test -v ./...

# Run go vet
vet:
    go vet ./...

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

# Build and run the darwin probe (macOS only)
probe-darwin:
    cc -o probe/darwin_probe probe/darwin_probe.c
    probe/darwin_probe

# Build the Linux Docker image
docker-build:
    docker compose -f docker/docker-compose.yml build

# Run go test ./... inside the Linux Docker container
docker-test:
    docker compose -f docker/docker-compose.yml run --rm test

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
