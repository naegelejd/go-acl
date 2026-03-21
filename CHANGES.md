# Upgrade Summary

Everything done to modernize this repository relative to the original master
(`b107678`). Items are organized by theme. This is a reference document —
see [PLAN.md](PLAN.md) for outstanding tasks.

---

## Go module and build infrastructure

- Added `go.mod` declaring module `github.com/naegelejd/go-acl` at `go 1.22`.
- Converted all `// +build` constraints to `//go:build` (Go 1.17+ style).
- Replaced deprecated `ioutil.ReadFile` / `ioutil.WriteFile` / `ioutil.TempDir`
  calls with `os.ReadFile` / `os.WriteFile` / `t.TempDir()` throughout.

---

## File layout and platform split

| File | Change |
|---|---|
| `acl.go` | Stripped to platform-agnostic types and helpers only |
| `acl_posix.go` | New — `//go:build linux \|\| freebsd`; shared path/fd ACL ops |
| `entry_posix.go` | New — `//go:build linux \|\| freebsd`; uid/gid qualifier handling |
| `acl_darwin.go` | Major additions (see Darwin section below) |
| `acl_linux.go` | Significant additions (see Linux section below) |
| `acl_freebsd.go` | Stubs preserved; `acl_size` workaround retained |
| `entry.go` | Common entry wrappers shared by all platforms |
| `perms.go` | `PermExecute` moved here to be shared |

---

## Darwin (macOS) — NFSv4 complete implementation

Darwin uses the NFSv4 ACL model (`ACL_TYPE_EXTENDED`). The original code had
essentially no working macOS implementation. Everything below was added.

### Tag types
- `TagExtendedAllow` (`ACL_EXTENDED_ALLOW`) and `TagExtendedDeny`
  (`ACL_EXTENDED_DENY`) — the only two tag types on macOS.

### Permission constants (all 16 NFSv4 perms)
`PermReadData`, `PermListDirectory`, `PermWriteData`, `PermAddFile`,
`PermExecute` / `PermSearch`, `PermDelete`, `PermAppendData`,
`PermAddSubdirectory`, `PermDeleteChild`, `PermReadAttributes`,
`PermWriteAttributes`, `PermReadExtattributes`, `PermWriteExtattributes`,
`PermReadSecurity`, `PermWriteSecurity`, `PermChangeOwner`, `PermSynchronize`.

### UUID qualifiers
macOS ACL qualifiers are 16-byte UUIDs (`guid_t`), not uid/gid integers.
Added `SetQualifierUID`, `SetQualifierGID`, and `GetQualifierID` using
`mbr_uid_to_uuid` / `mbr_gid_to_uuid` from `<membership.h>`.

### Inheritance flags
Added `Flag` and `Flagset` types backed by `acl_get_flagset_np` /
`acl_add_flag_np`. Exported constants: `FlagFileInherit`,
`FlagDirectoryInherit`, `FlagLimitInherit`, `FlagOnlyInherit`.
Methods: `GetFlagset`, `AddFlag`, `DeleteFlag`, `ClearFlags`, `HasFlag`.

### `Permset.String()`
Implemented for Darwin via `acl_get_perm_np` — returns a human-readable
string listing the active permissions.

### Correct `GetFileAccess` / `SetFileAccess`
- Uses `ACL_TYPE_EXTENDED` (not `ACL_TYPE_ACCESS` which is always `EINVAL`).
- `acl_get_file` returning `NULL` with `ENOENT` means the file has no ACL —
  the Go wrapper now returns an empty ACL rather than an error.
- `SetFileDefault` / `DeleteDefaultACL` / `CalcMask` are documented no-ops
  (default ACLs and the mask concept do not exist on macOS).

### `setfacl` — Darwin platform module
`setfacl/platform_darwin.go` added: full NFSv4 entry parser that resolves
user/group names to UUIDs and builds `ACL_EXTENDED_ALLOW` / `ACL_EXTENDED_DENY`
entries with the correct permission bitmask.

### Darwin tests (`acl_darwin_test.go`)
- UUID qualifier round-trips (set/get via uid and gid)
- Flagset get/add/has/delete/clear
- `Permset.String()` output
- Full file ACL round-trip (set access ACL, read back, verify entries)

---

## Linux — POSIX.1e additions

### Tag and permission constants
Exported all six tag constants (`TagUserObj`, `TagUser`, `TagGroupObj`,
`TagGroup`, `TagMask`, `TagOther`) and `PermRead` / `PermWrite` in
`acl_linux.go`. `PermExecute` moved to `perms.go` (shared with Darwin).

### `Permset.String()`
Implemented for Linux via `acl_get_perm` from `<acl/libacl.h>` — returns
`"rwx"`-style strings.

### `GetFd` / `SetFd`
Added to `acl_posix.go`:
```go
func GetFd(f *os.File) (*ACL, error)
func (acl *ACL) SetFd(f *os.File) error
```
Wrappers for `acl_get_fd` / `acl_set_fd`. Accept `*os.File` (not a raw `int`)
and use `runtime.KeepAlive` to prevent GC during the CGo call.

### `FromMode`
Added to `acl_linux.go`:
```go
func FromMode(mode os.FileMode) (*ACL, error)
```
Wraps `acl_from_mode` from `<acl/libacl.h>`. Synthesises a minimal
three-entry ACL (user-obj, group-obj, other) from Unix permission bits.

### `EquivMode`
Added to `acl_linux.go`:
```go
func (acl *ACL) EquivMode() (os.FileMode, bool, error)
```
Wraps `acl_equiv_mode`. Returns `(mode, isEquiv, error)` where `isEquiv` is
`true` when the ACL contains no extended (named user/group) entries and is
therefore equivalent to a plain Unix mode.

### `setfacl` — POSIX platform module and `-b` bug fix
`setfacl/platform_posix.go` added: handles Linux `user:name:rwx` entry format.

Bug fix: the original `-b` (delete all) handler reconstructed the ACL from the
file's mode bits. On Linux this is wrong — after setting an extended ACL the
mode's group execute bit reflects the mask, not the actual group permissions.
Fixed via `clearExtendedEntries`: reads the existing ACL and strips only the
named user/group and mask entries, leaving the three base entries intact.

### Linux tests (`acl_linux_test.go`)
All tests added from scratch — the original repo had no Linux-specific tests:
- `TestGetEntries` — ACL entry iteration
- `TestAddEntry` — add/tag/perm round-trip
- `TestCalcMask` — mask entry created by `CalcMask`
- `TestDeleteDefaultACL` — default ACL on a directory
- `TestEntrySetGetTag` — tag set/get
- `TestEntrySetGetQualifier` — uid/gid qualifier round-trips
- `TestPermsetString` — `"---"` → `"rw-"` → `"rwx"` progression
- `TestMaskEntry` — mask entry present after named user added
- `TestNamedUserRoundTrip` — named `TagUser` entry survives set/get
- `TestDefaultACLRoundTrip` — 4-entry default ACL survives set/get
- `TestGetFd` — `GetFd` on a temp file
- `TestSetFd` — `SetFd` + read-back via path
- `TestFromMode` — `FromMode(0755)` produces correct 3-entry ACL
- `TestEquivMode` — base-only ACL → equiv; after named user → not equiv

---

## CI / Docker / development infrastructure

### GitHub Actions (`.github/workflows/ci.yml`)
- Runs `go vet ./...` + `go test -race -count=1 ./...` on:
  - `macos-latest` (CGo, no extra libraries)
  - `ubuntu-latest` (CGo, installs `libacl1-dev`)
- Go version matrix: 1.22, 1.23, 1.24.

### Docker (`docker/`)
- `docker/Dockerfile`: `golang:1.24-bookworm` + `libacl1-dev` + `acl` + `just`,
  bind-mount workspace at `/workspace`.
- `docker/docker-compose.yml`: two services —
  - `runner` — runs `just ${RECIPE}` non-interactively
  - `dev` — interactive bash shell

### `justfile`
Key recipes:

| Recipe | Purpose |
|---|---|
| `just build` | `go build ./...` |
| `just test` | `go test ./...` |
| `just vet` | `go vet ./...` |
| `just cover` | coverage report via `go tool cover` |
| `just roundtrip` | macOS NFSv4 setfacl/getfacl smoke test |
| `just roundtrip-linux` | Linux POSIX setfacl/getfacl smoke test |
| `just docker <recipe>` | Run any recipe inside the Linux Docker container |
| `just docker-shell` | Interactive shell in the container |
| `just build-docker` | Rebuild the Docker image |
| `just all` | Full macOS + Linux pipeline (build/vet/cover/roundtrip/test) |

### README
Fully rewritten: CI badge, platform support table (Linux/macOS/FreeBSD),
install requirements, quick-start examples for both platforms, and a
development section describing the `just` workflow.

---

## Platform reference documentation (`PLAN.md`)

Added comprehensive per-platform reference documentation derived from the C
headers and experimental probes:
- Darwin: complete NFSv4 model comparison table, confirmed `acl_get_file` /
  `acl_set_file` behavior, tag types, all 16 permission constants, qualifier
  format, `acl_valid` behavior, unsupported functions.
- Linux: POSIX.1e model comparison table, tag constants with hex values,
  `acl_get_file` / `acl_set_file` semantics, `acl_calc_mask` behavior,
  qualifier format, `acl_get_fd` / `acl_set_fd` notes.
