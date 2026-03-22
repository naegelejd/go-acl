# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.2.0] — 2026-03-20

### Added

#### Darwin (macOS) — NFSv4 ACL support
macOS was previously unsupported. This release adds a complete NFSv4
(`ACL_TYPE_EXTENDED`) implementation.

- **Tag types**: `TagExtendedAllow`, `TagExtendedDeny`
- **Permission constants** (all 16 NFSv4 permissions): `PermReadData`,
  `PermListDirectory`, `PermWriteData`, `PermAddFile`, `PermExecute`,
  `PermDelete`, `PermAppendData`, `PermAddSubdirectory`,
  `PermDeleteChild`, `PermReadAttributes`, `PermWriteAttributes`,
  `PermReadExtAttributes`, `PermWriteExtAttributes`, `PermReadSecurity`,
  `PermWriteSecurity`, `PermChangeOwner`, `PermSynchronize`
- **UUID qualifiers**: `SetQualifierUID`, `SetQualifierGID`, `GetQualifierID`
  (macOS ACL qualifiers are 16-byte UUIDs, not uid/gid integers)
- **Inheritance flags**: `Flag` and `Flagset` types with constants
  `FlagFileInherit`, `FlagDirectoryInherit`, `FlagLimitInherit`,
  `FlagOnlyInherit` and methods `GetFlagset`, `AddFlag`, `DeleteFlag`,
  `ClearFlags`, `HasFlag`
- **`Permset.String()`**: human-readable permission listing via
  `acl_get_perm_np`
- **`GetFileAccess` / `SetFileAccess`**: now functional on macOS using
  `ACL_TYPE_EXTENDED`; `GetFileAccess` returns an empty ACL (not an error)
  when a file has no ACL
- **`setfacl`**: Darwin platform module added — parses NFSv4 entry strings and
  resolves user/group names to UUIDs

#### Linux — POSIX.1e additions

- **Tag constants**: `TagUserObj`, `TagUser`, `TagGroupObj`, `TagGroup`,
  `TagMask`, `TagOther`
- **Permission constants**: `PermRead`, `PermWrite`, `PermExecute`
- **`Permset.String()`**: returns `"rwx"`-style strings via `acl_get_perm`
- **`GetFd(f *os.File) (*ACL, error)`**: wraps `acl_get_fd`
- **`(*ACL).SetFd(f *os.File) error`**: wraps `acl_set_fd`
- **`FromMode(mode os.FileMode) (*ACL, error)`**: synthesises a minimal
  three-entry ACL from Unix permission bits via `acl_from_mode`
- **`(*ACL).EquivMode() (os.FileMode, bool, error)`**: returns the equivalent
  Unix mode and whether the ACL has no extended entries

#### Module / build

- Go module (`go.mod`) declared at `go 1.22`
- `//go:build` constraints throughout (Go 1.17+ style)

### Fixed

- **`setfacl -b` (Linux)**: the delete-all handler previously reconstructed the
  ACL from mode bits, which is incorrect when an extended ACL is present (the
  group execute bit reflects the mask, not actual group permissions). It now
  strips only the named user/group and mask entries, preserving the three base
  entries.

### Notes

- **macOS**: `SetFileDefault`, `DeleteDefaultACL`, and `CalcMask` are no-ops —
  default ACLs and the mask concept do not exist on macOS.
- **FreeBSD**: stubs are present and the module compiles, but FreeBSD ACL
  behavior has not been verified on a live system. Use with caution.

---

## [0.1.0] — 2015-07-13

Initial release.
