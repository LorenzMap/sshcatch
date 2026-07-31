# Changelog

All notable changes to **sshcatch** are documented here.
This project follows [Keep a Changelog](https://keepachangelog.com/) and
[Semantic Versioning](https://semver.org/).

## [0.2.2] - 2026-07-31

Multiple host keys now used as default.

### Added

- **Three host keys instead of one.** ed25519, RSA-3072 and ecdsa-nistp256 are
  generated on first run if missing and stored together in one `sshcatch_host_key`
  file, so clients can pick their algorithm. Existing key files are read with
  `read_private_key_list()` and may hold any number of keys.

### Changed

- The startup summary prints the fingerprint of each key.
- **Startup failures go through a single handler.** `PermissionError` is no longer
  special-cased: it always blamed the port, even when the host key file was the
  real problem. The underlying error is shown instead - it already names the
  address and port.

### Fixed

- An empty, unreadable or passphrase-protected host key file now ends in a clean
  error message instead of a traceback.
- `authorized_keys` lines that do not start with a key say why they were refused.
  Options in front of the key (`from="..."`, `restrict`, ...) remain unsupported -
  sshcatch cannot enforce them, so such keys are rejected rather than silently
  accepted without their restrictions.


## [0.2.1] - 2026-07-29

Forwarding hardening and help/logging polish.

### Added

- **Non-TCP forwarding is now explicitly denied and logged.** UNIX-domain-socket
  forwards (`unix_connection_requested` / `unix_server_requested`) and layer-2/3
  TUN/TAP tunnels (`tun_requested` / `tap_requested`) are overridden to refuse
  and log the attempt via a central `_deny_tunnel()` helper (mirroring the SFTP
  `_deny_sftp`), instead of relying on asyncssh's silent default rejection. Only
  plain TCP forwards remain available, and only when `--forward` / `--reverse` is
  set. A new `log_tunnel()` helper adds a `TUNNEL` log category.
- **Two-tier `--help`.** `-h` prints a short usage summary (`_epilog_short`);
  `--help` prints the full reference (`_epilog_full`).

### Changed

- **Denial reasons are logged server-side only, never sent to the client**, so a
  probing client can't learn the policy from the error text.
- **Denial log level follows the SFTP convention:** always-denied protocols
  (UNIX / TUN / TAP) log at INFO (`-v`), while a TCP forward refused only because
  `--forward` / `--reverse` is off logs at WARNING (default).
- Internal: the SFTP deny helper was renamed `_deny` → `_deny_sftp` to stay
  consistent with the new `_deny_tunnel`.

### Security

- Tunnel-denial is now enforced and made visible on every path rather than
  silently dropped by asyncssh.


## [0.2.0] - 2026-07-19

Large rewrite of the SFTP layer and the logging system.

### Added

- **Subdirectory support** for SCP/SFTP. `map_path()` is overridden to normalize
  paths into the chroot, so `scp -r`, nested uploads/downloads and recursive
  `sftp` listings now work. The old "root directory only" restriction
  (`_require_flat`) is gone.
- **Single-connection mode** (`-1` / `--single`). Accepts the first successful
  authentication, closes the listener to free the port, and exits once that
  connection ends. Implemented via an asyncio future resolved in
  `auth_completed()`.
- **Tiered, verbosity-controlled logging.** New mutually exclusive `-q`/`--quiet`
  and `-v`/`--verbose` (repeatable) flags map to WARNING (default) / INFO (`-v`) /
  DEBUG (`-vv`). Every log helper now takes a `level`. The `--output` logfile
  always records everything (DEBUG) regardless of console verbosity.
- **Recursive-upload plumbing.** `mkdir` is allowed during uploads and
  `_ensure_parent()` auto-creates missing parent directories (logged as
  `MKPARENT`), so uploading a tree lands intact.
- **Directory listings** via `scandir` (download only), which also **hides
  protected files and symlinks** from the listing.
- **SCP log de-duplication**: identical SCP messages within a 1-second window are
  collapsed to cut noise.
- **Error-handling wrapper** `_execute_wrapped_log()` that reports
  `NOTFOUND` (FileNotFoundError) and `ERROR` (OSError) cleanly instead of raising
  raw tracebacks.
- **`--single` and banner details in the startup summary**, plus a
  `banner_preview()` helper that truncates long banners.

### Changed

- **Symlink handling redesigned.**
  - On **download**, symlinks are denied (`_require_not_symlink`) and hidden from
    listings — a transfer can never follow a link out of the chroot.
  - On **upload**, a symlink is no longer rejected outright; instead a small
    placeholder file recording the target is written, so recursive uploads that
    contain a link still complete.
- **SFTP server implementation.** Replaced the metaprogramming approach
  (`_SFTP_ALL_OPS` / `_SFTP_WHITELIST` / dynamic `setattr` of deny stubs) with
  explicit, individually-commented methods for every allowed and denied
  operation. Newly explicit denials: `open56`, `readlink`, `posix_rename`,
  `statvfs`, `fstatvfs`, `fsync`, `lock`, `unlock` (in addition to
  `remove`/`rename`/`rmdir`/`link`).
- **Post-auth banner delivery** is now reliable: it wraps asyncssh's
  `send_userauth_success` and fires exactly once, instead of being triggered from
  inside password/key validation.
- **Host key algorithm** changed from RSA-2048 to **ed25519**.
- **Protected files** are now matched by their path relative to the SCP directory
  (supports subdirectories) instead of just basename, and the **sshcatch script
  itself** (`__file__`) is now protected alongside the host key, authorized_keys
  and logfile.
- **Startup summary** is now emitted through the logger (so it also lands in
  `--output` and is suppressed by `-q`) rather than printed directly. The auth
  line now shows counts, e.g. `restricted (2 users, 1 key)`.
- **Connection-close logging** is level-aware: authenticated disconnects log at
  WARNING, unauthenticated ones at DEBUG.
- **Clean channel close.** `exit()` now calls `channel.exit(0)` so clients don't
  hang waiting for a session that never opens.
- Full offered public keys are now shown automatically at `-vv` (DEBUG) instead
  of requiring a dedicated flag.
- Help text / argument groups updated: "SCP / SFTP file transfer", refreshed
  `--scp-*` descriptions (symlink behavior, no subdirectory restriction).

### Removed

- **`-K` / `--full-keys` flag** — superseded by `-vv` verbosity.
- **Startup symlink scan** that refused to start if the SCP directory contained
  any symlink — replaced by the per-operation symlink handling above.

### Security

- Every SFTP operation is now explicitly allow-listed or denied, and symlink
  traversal out of the chroot is blocked on every path-taking operation rather
  than only checked once at startup.

## [0.1.1]

### Fixed

- **Hardened the flat-directory (no-subdirectory) check.** The upload/download
  path is now run through `posixpath.normpath()` before it is compared against
  its basename, so `./`-prefixed and other non-canonical paths are collapsed
  first and can no longer slip past the "root directory only" restriction.

## [0.1.0]

- Initial version published on GitHub.
