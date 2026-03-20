# ACL Library Platform Plan

This document records **confirmed** ACL API behavior per platform, derived from
system man pages and the probe programs in `probe/`. Nothing here is assumed —
every fact was experimentally verified. Outdated or speculative documentation
was discarded.

---

## Platform: Darwin (macOS)

### Source of truth
- `$(xcrun --show-sdk-path)/usr/include/sys/acl.h`
- `man 3 acl` (and related pages)
- `probe/darwin_probe.c` — compile and run to re-verify at any time

### ACL model

macOS does **not** support POSIX.1e access ACLs. It implements a subset of the
NFSv4 ACL model. The key differences from POSIX:

| Topic | POSIX.1e (Linux) | macOS (NFSv4 subset) |
|---|---|---|
| ACL type | `ACL_TYPE_ACCESS`, `ACL_TYPE_DEFAULT` | `ACL_TYPE_EXTENDED` only |
| Tag types | `ACL_USER_OBJ`, `ACL_USER`, `ACL_GROUP_OBJ`, `ACL_GROUP`, `ACL_MASK`, `ACL_OTHER` | `ACL_EXTENDED_ALLOW` (1), `ACL_EXTENDED_DENY` (2) |
| Qualifier | uid/gid as `int` | 16-byte UUID (`guid_t`) via `<membership.h>` |
| Mandatory entries | Yes (owner, group, other must exist) | No (empty ACL is valid) |
| Default ACLs | Yes (directories) | Not supported |
| Mask | `acl_calc_mask` | **Not supported** (`ENOTSUP`) |
| Base entries | Required for validity | Not required |

### Confirmed API behavior (from probe)

#### `acl_get_file`
| Type | Result | errno |
|---|---|---|
| `ACL_TYPE_EXTENDED` | `NULL` when file has no ACL | `ENOENT` |
| `ACL_TYPE_EXTENDED` | non-NULL ACL when file has ACL | 0 |
| `ACL_TYPE_ACCESS` | always `NULL` | `EINVAL` |
| `ACL_TYPE_DEFAULT` | always `NULL` | `EINVAL` |

**Go implication:** `GetFileAccess` on Darwin must use `ACL_TYPE_EXTENDED`.
A `NULL` return with `ENOENT` means "no ACL" — return an empty ACL, not an error.

#### `acl_set_file`
| Type | Empty ACL | Non-empty ACL |
|---|---|---|
| `ACL_TYPE_EXTENDED` | success (clears ACL) | success |
| `ACL_TYPE_ACCESS` | success (appears to be a no-op or clear) | untested |
| `ACL_TYPE_DEFAULT` | success (appears to be a no-op or clear) | untested |

**Go implication:** `SetFileAccess` on Darwin should use `ACL_TYPE_EXTENDED`.
`SetFileDefault` is not meaningful on macOS; it should be a documented no-op.

#### Tag types
- `ACL_UNDEFINED_TAG` = 0
- `ACL_EXTENDED_ALLOW` = 1
- `ACL_EXTENDED_DENY` = 2
- There is no `ACL_USER_OBJ`, `ACL_GROUP_OBJ`, or `ACL_OTHER` on macOS.

#### Permissions (NFSv4 set)
| Constant | Value | Alias |
|---|---|---|
| `ACL_READ_DATA` | `0x02` | `ACL_LIST_DIRECTORY` |
| `ACL_WRITE_DATA` | `0x04` | `ACL_ADD_FILE` |
| `ACL_EXECUTE` | `0x08` | `ACL_SEARCH` |
| `ACL_DELETE` | `0x10` | — |
| `ACL_APPEND_DATA` | `0x20` | `ACL_ADD_SUBDIRECTORY` |
| `ACL_DELETE_CHILD` | `0x40` | — |
| `ACL_READ_ATTRIBUTES` | `0x80` | — |
| `ACL_WRITE_ATTRIBUTES` | `0x100` | — |
| `ACL_READ_EXTATTRIBUTES` | `0x200` | — |
| `ACL_WRITE_EXTATTRIBUTES` | `0x400` | — |
| `ACL_READ_SECURITY` | `0x800` | — |
| `ACL_WRITE_SECURITY` | `0x1000` | — |
| `ACL_CHANGE_OWNER` | `0x2000` | — |
| `ACL_SYNCHRONIZE` | `0x100000` | — |

#### Qualifiers
Qualifiers are 16-byte UUIDs (`guid_t`), **not** uid/gid integers. Use
`mbr_uid_to_uuid` / `mbr_gid_to_uuid` from `<membership.h>` to convert.
`acl_get_qualifier` returns a `void *` pointing to a `guid_t` that must be
freed with `acl_free`.

#### `acl_valid`
- Empty ACL: **valid** (returns 0). No mandatory base entries on macOS.
- Single `ACL_EXTENDED_ALLOW` entry: **valid**.

#### Unsupported functions (confirmed `ENOTSUP`)
- `acl_calc_mask` — returns `-1`, `errno=45` (`ENOTSUP`)
- `acl_delete_def_file` — returns `-1`, `errno=45` (`ENOTSUP`)

#### Working functions
- `acl_size` — works on macOS (returns size in bytes, e.g. 68 for 1 entry)
- `acl_to_text` / `acl_from_text` — round-trip confirmed
  - Text format: `!#acl 1\nuser:UUID:username:uid:allow:read`
- `acl_copy_ext` / `acl_copy_int` — available (acl_size works so buffer sizing is valid)
- Inheritance flags: `ACL_ENTRY_FILE_INHERIT`, `ACL_ENTRY_DIRECTORY_INHERIT`,
  `ACL_ENTRY_LIMIT_INHERIT`, `ACL_ENTRY_ONLY_INHERIT` — all available via
  `acl_get_flagset_np` / `acl_add_flag_np`

### Current Go implementation status (Darwin)

| Function | Status | Notes |
|---|---|---|
| `GetFileAccess` | ✅ Correct | Uses `ACL_TYPE_EXTENDED`, handles `ENOENT` |
| `GetFileDefault` | ✅ Correct (stub) | Returns empty ACL; not supported on macOS |
| `SetFileAccess` | ✅ Correct | Uses `ACL_TYPE_EXTENDED` |
| `SetFileDefault` | ✅ Correct (stub) | No-op; not meaningful on macOS |
| `DeleteDefaultACL` | ✅ Correct | Returns error "not supported on macOS" |
| `CalcMask` | ✅ Correct | Returns error "not supported on macOS" |
| `Valid` | ✅ Correct | `acl_valid` works; empty ACL is valid |
| `Tag types` | ❌ Not exposed | `ACL_EXTENDED_ALLOW`/`DENY` not exported in Go |
| `Permissions` | ❌ Not exposed | NFSv4 perm set not exported in Go |
| `Qualifiers` | ❌ Wrong type | Go code uses `int` for qualifiers; macOS requires 16-byte UUID |
| `Flags` | ❌ Not exposed | Inheritance flags (`ACL_ENTRY_FILE_INHERIT` etc.) not in Go |

### TODO: Darwin implementation tasks
(To be done incrementally — confirm with tests before proceeding)

1. **`SetFileAccess` / `SetFileDefault`**: Move to `acl_darwin.go`, use
   `ACL_TYPE_EXTENDED` and make `SetFileDefault` a documented no-op.
2. **`DeleteDefaultACL`**: Return `ErrNotSupported` on Darwin instead of
   silently failing.
3. **`CalcMask`**: Return `ErrNotSupported` on Darwin.
4. **Tag types**: Export `TagExtendedAllow` / `TagExtendedDeny` in Darwin build.
5. **Permissions**: Export the NFSv4 permission constants for Darwin.
6. **Qualifiers**: Darwin qualifier is a UUID. Expose `GetQualifierUUID` /
   `SetQualifierUUID` using `guid_t` and `<membership.h>` helpers.
7. **Flags**: Expose `acl_flag_t` constants and `acl_get_flagset_np` /
   `acl_add_flag_np` / `acl_clear_flags_np` / `acl_delete_flag_np`.

---

## Platform: Linux

### TODO: Probe + document
Run the equivalent probe on a Linux host to confirm:
- `ACL_TYPE_ACCESS` and `ACL_TYPE_DEFAULT` behavior
- Tag type values (`ACL_USER_OBJ`, `ACL_USER`, `ACL_GROUP_OBJ`, `ACL_GROUP`,
  `ACL_MASK`, `ACL_OTHER`) from `<acl/libacl.h>`
- Qualifier type (uid/gid as `int`, confirmed by existing code but needs probe)
- `acl_calc_mask` behavior
- `acl_get_perm` availability (`<acl/libacl.h>` extension)

---

## Platform: FreeBSD

### TODO: Probe + document
FreeBSD supports both POSIX.1e ACLs (on UFS with `tunefs -a enable`) and NFSv4
ACLs (on ZFS). Key known differences from the existing code comments:
- `acl_size` is broken/non-functional (FreeBSD r274722) — already stubbed.
- Need to confirm `ACL_TYPE_ACCESS` behavior.
- Need a probe program equivalent to `darwin_probe.c`.
