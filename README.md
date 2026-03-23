# go-acl

[![CI](https://github.com/naegelejd/go-acl/actions/workflows/ci.yml/badge.svg)](https://github.com/naegelejd/go-acl/actions/workflows/ci.yml)

Go bindings for POSIX.1e ACLs (Linux) and NFSv4 ACLs (macOS).

## Platform Support

| Platform | ACL Model | Library |
|---|---|---|
| Linux | POSIX.1e (`ACL_TYPE_ACCESS`, `ACL_TYPE_DEFAULT`) | `libacl` (`-lacl`) |
| macOS | NFSv4 subset (`ACL_TYPE_EXTENDED`) | system `libc` |
| FreeBSD | POSIX.1e (partial, untested) | system `libc` |

## Requirements

**Linux:** install `libacl1-dev` (Debian/Ubuntu) or `libacl-devel` (Fedora/RHEL):

```sh
sudo apt-get install libacl1-dev   # Debian / Ubuntu
sudo dnf install libacl-devel      # Fedora / RHEL
```

**macOS:** no extra dependencies. The ACL library ships with the OS.

## Installation

```sh
go get github.com/naegelejd/go-acl
```

## Usage

See also the [package documentation](https://pkg.go.dev/github.com/naegelejd/go-acl) for
runnable examples.

### Linux (POSIX.1e)

```go
import (
    "fmt"

    acl "github.com/naegelejd/go-acl"
)

// Create an ACL from Unix mode bits.
a, _ := acl.FromMode(0o644)
defer a.Free()

// Iterate entries.
for e := a.FirstEntry(); e != nil; e = a.NextEntry() {
    tag, _ := e.GetTag()
    pset, _ := e.GetPermset()
    fmt.Printf("tag=%v perms=%s\n", tag, pset)
}

// Check whether an ACL is equivalent to a plain Unix mode (no named entries).
mode, isEquiv, _ := a.EquivMode()
_ = mode
_ = isEquiv
```

See the [package examples](https://pkg.go.dev/github.com/naegelejd/go-acl#pkg-examples) for
a full read/modify/write workflow.

### macOS (NFSv4)

```go
import (
    "fmt"
    "os"

    acl "github.com/naegelejd/go-acl"
)

// Grant the current user read and execute access.
a, _ := acl.GetFileAccess("/path/to/file")
defer a.Free()

entry, _ := a.CreateEntry()
entry.SetTag(acl.TagExtendedAllow)
entry.SetQualifierUID(os.Getuid())
pset, _ := entry.GetPermset()
pset.AddPerm(acl.PermReadData)
pset.AddPerm(acl.PermExecute)
a.SetFileAccess("/path/to/file")
```

See the [package examples](https://pkg.go.dev/github.com/naegelejd/go-acl#pkg-examples) for
a flagset/inheritance example.

## Development

This project uses [`just`](https://just.systems/) as a task runner.

```sh
just          # list available recipes
just check    # vet + test (macOS/Linux native)
just all      # full pipeline on macOS and Linux (via Docker)

just docker test             # run tests in Linux Docker container
just docker cover            # coverage report in Linux Docker container
just docker roundtrip-linux  # Linux ACL round-trip demo
just docker-shell            # interactive Linux shell
```

## License

Copyright (c) 2026 Joseph Naegele. See [LICENSE](LICENSE).

