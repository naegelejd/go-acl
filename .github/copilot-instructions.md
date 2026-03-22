# Copilot Instructions

## File safety

- Never modify a file unless the user has explicitly asked you to change it.
- `TODO.md` is a personal scratch pad — never read from, write to, or delete it.

## Copyright headers

Every `.go` and `.c` source file must have a copyright header as its first line.
The current year is used; update it if the file is being modified and the year is stale.

Go files:
```go
// Copyright (c) 2026 Joseph Naegele. See LICENSE file.
```

C files:
```c
// Copyright (c) 2026 Joseph Naegele. See LICENSE file.
```

When creating a new file, always include this header. When editing an existing file,
update the year in the header to the current year if it differs.

## Documentation consistency

- Every exported identifier referenced in `CHANGELOG.md`, `README.md`, or any
  doc comment must use the **exact spelling** as declared in source.
- When renaming or adding an exported symbol, update all documentation that
  mentions it in the same change.
- Keep `docker/Dockerfile` usage comments, `README.md` command snippets, and
  `justfile` recipe names synchronized. Renaming a recipe requires updating all
  references.

## Go example functions

- Usage snippets in `README.md` must have corresponding runnable `Example*`
  functions in `example_*_test.go` files (package `acl_test`).
- Example functions must include all necessary imports and be self-contained.
- Platform-specific examples must carry the appropriate `//go:build` constraint
  (`linux`, `darwin`, etc.).
- Examples with deterministic output must include an `// Output:` comment so
  they are executed as tests by `go test`.

## CGo memory management

- Every `C.CString(...)` result must be assigned to a named variable and freed
  with `defer C.free(unsafe.Pointer(cs))` immediately after allocation.
- Every call to `acl_get_qualifier` must free the returned pointer with
  `C.acl_free(q)` after reading the value.
- Files that call `C.free` must include `#include <stdlib.h>` in their CGo
  preamble.

## CGo type safety

- Pass uid/gid values to C APIs as `C.uid_t` / `C.gid_t`, not as Go `int`.
  A Go `int` is 64 bits on amd64; `uid_t`/`gid_t` are 32 bits — the size
  mismatch silently corrupts qualifier values.

## Error handling

- Never silently discard errors from conversions whose incorrect silent values
  have security implications. In particular, always handle `strconv.Atoi` errors
  when converting uid/gid strings (a silently-zero uid grants root-level ACL
  entries).

## Recursive directory traversal

- Never mutate the loop's parent-path variable inside an iteration over
  directory children. Compute each child path into a new variable so that later
  siblings are joined against the original parent, not the previous child.
