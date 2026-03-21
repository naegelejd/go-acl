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
