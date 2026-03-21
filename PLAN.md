# Outstanding Tasks

See [CHANGES.md](CHANGES.md) for a full history of what has been done to
modernize this repository.

---

## FreeBSD

FreeBSD supports both POSIX.1e ACLs (UFS with `tunefs -a enable`) and NFSv4
ACLs (ZFS). Key known issues from the existing code:
- `acl_size` is broken/non-functional (FreeBSD r274722) — already stubbed.
- `addBaseEntries` in `acl_freebsd.go` is a no-op; needs confirmation.

- [ ] Write `probe/freebsd_probe.c` and run on a FreeBSD host or VM
- [ ] After probe, document confirmed `acl_get_file` / `acl_set_file` behavior
- [ ] Decide: POSIX.1e (UFS) or NFSv4 (ZFS) as the primary FreeBSD path
- [ ] Confirm whether `addBaseEntries` needs the same logic as Linux

---

## CI

- [ ] Consider adding a FreeBSD runner (via `cross-platform-actions/action`)
  once the FreeBSD probe is done

---

## Release

- [ ] Tag `v1.0.0` once any desired FreeBSD work is done
