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
    "os"

    acl "github.com/naegelejd/go-acl"
)

// Read the access ACL from a file.
a, err := acl.GetFileAccess("/path/to/file")
if err != nil { ... }
defer a.Free()

// Iterate entries.
for e := a.FirstEntry(); e != nil; e = a.NextEntry() {
    tag, _ := e.GetTag()
    pset, _ := e.GetPermset()
    fmt.Printf("tag=%v perms=%s\n", tag, pset)
}

// Add a named user entry.
uid := os.Getuid() // or resolve a specific username
entry, _ := a.CreateEntry()
entry.SetTag(acl.TagUser)
entry.SetQualifier(uid)
pset, _ := entry.GetPermset()
pset.AddPerm(acl.PermRead)
a.CalcMask()
a.SetFileAccess("/path/to/file")

// Create an ACL from Unix mode bits.
a, _ = acl.FromMode(0o644)
defer a.Free()

// Check whether an ACL is equivalent to a plain Unix mode (no named entries).
mode, isEquiv, _ := a.EquivMode()
```

### macOS (NFSv4)

```go
import (
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

// Set an inheritance flag on a directory entry.
fs, _ := entry.GetFlagset()
fs.AddFlag(acl.FlagFileInherit)
```

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

