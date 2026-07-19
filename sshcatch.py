#!/usr/bin/env python3
"""
sshcatch - a quick-deploy SSH server for tunneling (local/remote/dynamic)
and simple SCP transfers (NEVER opens a shell!).
"""

import argparse
import asyncio
import logging
import os
import posixpath
import sys
import time
from pathlib import Path
from itertools import count

import asyncssh

__version__ = "0.2.0"

# ── Logging ───────────────────────────────────────────────────────────

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
PURPLE = "\033[95m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RST = "\033[0m"

#   WARNING (default) - general actions and connections
#   INFO    (-v)      - details for those connections and (blocked) actions
#                       that do not result from normal use
#   DEBUG   (-vv)     - connection setup and uninteresting SCP/SFTP operations
def configure_logging(output=None, timestamps=False, plain=False, console_level=logging.INFO):
    logger = logging.getLogger("sshcatch")
    logger.setLevel(logging.DEBUG)
    logger.propagate = False
    logger.handlers.clear()

    field = "plain" if plain else "colored"
    line = f"%({field})s %(message)s"
    if timestamps: line = "%(asctime)s " + line
    out = logging.StreamHandler(sys.stdout)
    out.setLevel(console_level)
    out.setFormatter(logging.Formatter(line, datefmt="%Y-%m-%d %H:%M:%S"))
    logger.addHandler(out)

    # File logging
    if output:
        file_handler = logging.FileHandler(output, mode="a", encoding="utf-8")
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(logging.Formatter("%(asctime)s %(plain)s %(message)s", datefmt="%Y-%m-%d %H:%M:%S"))
        logger.addHandler(file_handler)

def _log(tag, color, msg, addr=None, user=None, level=logging.INFO):
    logger = logging.getLogger("sshcatch")
    loc = (f"{BOLD}[{addr}]{RST}" if addr else "") + (f"{BOLD}[{user}]{RST}" if user else "")
    colored = f"{color}[{tag}]{RST}" + loc
    plain = f"[{tag}]" + (f"[{addr}]" if addr else "") + (f"[{user}]" if user else "")
    logger.log(level, msg, extra={"colored": colored, "plain": plain})

def log_conn(msg, addr=None, user=None, level=logging.DEBUG):
    _log("+", GREEN, msg, addr, user, level)

def log_auth(msg, success=False, addr=None, user=None, level=logging.WARNING):
    _log("AUTH", GREEN if success else YELLOW, msg, addr, user, level)

def log_scp(msg, addr=None, user=None, level=logging.INFO):
    _log("SCP", PURPLE, msg, addr, user, level)

def log_tunnel(msg, addr=None, user=None):
    _log("TUNNEL", CYAN, msg, addr, user, logging.WARNING)

def log_info(msg, addr=None, user=None, level=logging.DEBUG):
    _log("*", BOLD, msg, addr, user, level)

def addr_str(host, port):
    if ":" in str(host): return f"[{host}]:{port}"
    else: return f"{host}:{port}"

def banner_preview(text, n=50):
    s = " ".join(text.split())
    return (s[:n] + "…") if len(s) > n else s


# ── SFTP server ───────────────────────────────────────────────────────

class SFTPCatchServer(asyncssh.SFTPServer):
    def __init__(self, chan, chroot, allow_upload, allow_download, protected_files=()):
        super().__init__(chan, chroot=chroot)
        self._chroot_local = os.fsdecode(chroot)
        self._allow_upload = allow_upload
        self._allow_download = allow_download
        self._protected_files = set(protected_files)
        conn = chan.get_connection()
        self._user = conn.get_extra_info("username") or "?"
        peer = conn.get_extra_info("peername")
        self._addr = addr_str(peer[0], peer[1]) if peer else "?"
        self._last_log = (None, 0.0)
        self._log_scp("Session opened", logging.DEBUG)

    def _log_scp(self, msg, level=logging.INFO):
        last_msg, last_msg_ts = self._last_log
        # SCP log can be noisy so we dedup messages in 1s timeframes
        if msg == last_msg and time.monotonic() - last_msg_ts < 1.0:
            return
        self._last_log = (msg, time.monotonic())
        log_scp(msg, addr=self._addr, user=self._user, level=level)

    def _deny(self, detail, reason="Not allowed"):
        level = logging.INFO if reason == "Not allowed" else logging.WARNING
        self._log_scp(f"DENIED {detail}", level)
        raise asyncssh.SFTPPermissionDenied(reason)

    def _execute_wrapped_log(self, path, fn, *args):
        try: return fn(*args)
        except FileNotFoundError:
            self._log_scp(f"NOTFOUND {self._local_path(path)}", logging.WARNING)
            raise
        except OSError as e:
            self._log_scp(f"ERROR {self._local_path(path)} ({e.strerror or e})", logging.WARNING)
            raise

    # ── path checks ──────────────────────────────────────────────

    def map_path(self, path):
        # Overwrite to be more secure than default implementation
        normpath = b"/" + posixpath.normpath(posixpath.join(b"/", path)).lstrip(b"/")
        return super().map_path(normpath)

    def _require_not_protected(self, path):
        # Prevent access to protected files in the scp dir
        rel = posixpath.normpath(posixpath.join(b"/", path)).lstrip(b"/")
        if os.fsdecode(rel) in self._protected_files:
            self._deny(f"PROTECTED {self._local_path(path)}")

    def _require_not_symlink(self, path):
        local = Path(os.fsdecode(self.map_path(path)))
        for component in (local, *local.parents):
            # check if chroot root reached
            if component == Path(self._chroot_local): break  
            if component.is_symlink():
                self._deny(f"SYMLINK {self._local_path(path)}", "Symlinks are not allowed")

    def _unique_write_path(self, path):
        # Check if the upload overwrites something - keep subdirectories intact
        # Watch out: asyncssh SFTP uses posixpath independently of the actual OS
        # map_path resolves paths into the chroot
        if not Path(os.fsdecode(self.map_path(path))).exists():
            return path
        # Simply add a number until we are unique (staying in the same directory)
        d = posixpath.dirname(path)
        stem, ext = posixpath.splitext(posixpath.basename(path))
        for n in count(1):
            next_path = posixpath.join(d, b"%s_%d%s" % (stem, n, ext))
            if not Path(os.fsdecode(self.map_path(next_path))).exists():
                return next_path

    def _ensure_parent(self, path):
        parent = Path(os.fsdecode(self.map_path(path))).parent
        if not parent.is_dir():
            parent.mkdir(parents=True, exist_ok=True)
            self._log_scp(f"MKPARENT {self._local_path(path)}", logging.INFO)

    def _local_path(self, path):
        return self.reverse_map_path(self.map_path(path)).decode(errors="replace")

    def _local_path_log(self, path):
        local = self._local_path(path)
        raw = path.decode(errors="replace")
        raw_cmp = raw.removeprefix('./').removeprefix('/').removesuffix('/')
        if raw_cmp != local.removeprefix('/'):
            self._log_scp(f"PATH {raw} -> {local}", logging.INFO)
        return local

    # ── General file/session handling ─────────────────────────────

    def open(self, path, pflags, attrs):
        # Allow (gated): the core transfer op - read=download, write=upload
        self._require_not_protected(path)
        self._require_not_symlink(path)
        is_write = bool(pflags & (0x02 | 0x04 | 0x08))  # WRITE|APPEND|CREAT

        if is_write and not self._allow_upload:
            self._deny(f"WRITE {self._local_path(path)}", "Upload is disabled")
        if not is_write and not self._allow_download:
            self._deny(f"READ {self._local_path(path)}", "Download is disabled")

        # Prevent overwriting on upload
        if is_write:
            unique = self._unique_write_path(path)
            if unique != path:
                self._log_scp(f"EXISTS {self._local_path(path)} -> "
                              f"{self._local_path(unique)}", logging.WARNING)
                path = unique
            self._ensure_parent(path)

        result = self._execute_wrapped_log(path, super().open, path, pflags, attrs)
        label = "WRITE" if is_write else "READ"
        self._log_scp(f"{label} {self._local_path_log(path)}", logging.WARNING)
        return result

    def stat(self, path):
        # Allow: size/perms before a transfer
        self._require_not_protected(path)
        self._require_not_symlink(path)
        return self._execute_wrapped_log(path, super().stat, path)

    def lstat(self, path):
        # Allow: like stat but dont follow symlinks
        self._require_not_protected(path)
        self._require_not_symlink(path)
        return self._execute_wrapped_log(path, super().lstat, path)

    def exit(self):
        # Allow: lifecycle - force clean positive channel close so clients don't hang
        self._log_scp("Session closed", logging.DEBUG)
        try: self.channel.exit(0)
        except Exception: pass
        return super().exit()

    # close     - Allow: close a file handle after read/write
    # realpath  - Allow: symlinks to local path (needed for "."/"..")
    # fstat     - Allow: stat on an already-open handle

    # Internal base-class helpers we should not touch without a good reason:
    #   map_path, reverse_map_path, format_user, format_group,
    #   format_longname, convert_attrs

    # ── UPLOAD operations ─────────────────────────────────────────

    def mkdir(self, path, attrs):
        # Allow (upload only): needed to create directories during recursive uploads
        if not self._allow_upload:
            self._deny(f"MKDIR {self._local_path(path)}", "Upload is disabled")
        self._require_not_protected(path)
        self._require_not_symlink(path)
        self._ensure_parent(path)
        result = self._execute_wrapped_log(path, super().mkdir, path, attrs)
        self._log_scp(f"MKDIR {self._local_path_log(path)}", logging.WARNING)
        return result

    def symlink(self, old, new):
        # Allow (upload only): write a placeholder recording the target
        if not self._allow_upload:
            self._deny(f"SYMLINK {self._local_path(new)}", "Upload is disabled")
        self._require_not_protected(new)
        self._require_not_symlink(new)
        new = self._unique_write_path(new)
        self._ensure_parent(new)
        target = old.decode(errors="replace")
        Path(os.fsdecode(self.map_path(new))).write_text(f"symlink -> {target}\n")
        self._log_scp(f"SYMLINK {self._local_path(new)} -> {target} (placeholder)",
                      logging.WARNING)

    def setstat(self, path, attrs):
        # Allow (upload only): perms/timestamps on uploaded files
        if not self._allow_upload:
            self._deny(f"SETSTAT {self._local_path(path)}", "Upload is disabled")
        self._require_not_protected(path)
        self._require_not_symlink(path)
        result = self._execute_wrapped_log(path, super().setstat, path, attrs)
        self._log_scp(f"SETSTAT {self._local_path(path)}", logging.DEBUG)
        return result

    def fsetstat(self, file_obj, attrs):
        # Allow (upload only): same as setstat on an already-open handle
        if not self._allow_upload:
            self._deny("FSETSTAT", "Upload is disabled")
        self._log_scp("FSETSTAT", logging.DEBUG)
        return super().fsetstat(file_obj, attrs)

    def lsetstat(self, path, attrs):
        # Noop (upload only): set link's timestamps but we use placeholders (noop so uploads don't abort)
        if not self._allow_upload:
            self._deny(f"LSETSTAT {self._local_path(path)}", "Upload is disabled")
        self._log_scp(f"LSETSTAT {self._local_path(path)} (ignored)", logging.DEBUG)

    # write     - file upload after open

    # ── DOWNLOAD operations ───────────────────────────────────────

    async def scandir(self, path):
        # Allow (download only): directory listing for recursive downloads
        if not self._allow_download:
            self._deny(f"LISTDIR {self._local_path(path)}", "Download is disabled")
        self._require_not_symlink(path)
        self._log_scp(f"LISTDIR {self._local_path_log(path)}", logging.DEBUG)
        # hide protected files and symlinks
        async for name in super().scandir(path):
            if name.filename not in (b".", b".."):
                mapped = self.map_path(posixpath.join(path, name.filename))
                relative = self.reverse_map_path(mapped).decode(errors="replace").lstrip("/")
                if relative in self._protected_files:
                    continue
                if os.path.islink(os.fsdecode(mapped)):
                    self._log_scp(f"SKIP symlink {relative}", logging.DEBUG)
                    continue
            yield name
    
    # read      - file download after open

    # ── DENIED operations ─────────────────────────────────────────

    def remove(self, path):
        # Deny: no deleting files
        self._deny(f"DELETE {self._local_path(path)}")

    def rename(self, old, new):
        # Deny: no moving or renaming
        self._deny(f"RENAME {self._local_path(old)}")

    def rmdir(self, path):
        # Deny: no removing directories
        self._deny(f"RMDIR {self._local_path(path)}")

    def link(self, old, new):
        # Deny: no hard links
        self._deny(f"LINK {self._local_path(old)}")

    def open56(self, path, desired_access, flags, attrs):
        # Deny: SFTPv4+ open (we use sftp_version=3 anyway)
        self._deny(f"OPEN56 {self._local_path(path)}")

    def readlink(self, path):
        # Deny: we deliberately dont use symlinks
        self._deny(f"READLINK {self._local_path(path)}")

    def posix_rename(self, oldpath, newpath):
        # Deny: no moving or renaming
        self._deny(f"POSIX_RENAME {self._local_path(oldpath)}")

    def statvfs(self, path):
        # Deny: leaks host filesystem stats (size/free space), not needed for transfers
        self._deny(f"STATVFS {self._local_path(path)}")

    def fstatvfs(self, file_obj):
        # Deny: same as statvfs but on file handle
        self._deny("FSTATVFS")

    def fsync(self, file_obj):
        # Deny: flush-to-disk on a handle; uploads complete fine without it.
        self._deny("FSYNC")

    def lock(self, file_obj, offset, length, flags):
        # Deny: byte-range locks serve no purpose here and only add surface.
        self._deny("LOCK")

    def unlock(self, file_obj, offset, length):
        # Deny: see lock().
        self._deny("UNLOCK")


# ── SSH server factory ────────────────────────────────────────────────

def make_server_factory(args, single_future=None):
    # Set up authentication once at startup to keep the runtime simpler
    users = {}
    if args.user:
        for entry in args.user:
            u, p = entry.split(":", 1)
            users[u] = p

    auth_keys_fps = set()
    if args.authorized_keys:
        for i, line in enumerate(args.authorized_keys.read_text().splitlines(), 1):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            try:
                k = asyncssh.import_public_key(line)
                fp = k.get_fingerprint()
                auth_keys_fps.add(fp)
                log_info(f"Loaded key     line={i}  fingerprint={fp}")
            except Exception as e:
                log_info(f"Invalid key    line={i}  {e}", level=logging.WARNING)

    # --open-auth set: always return true
    if args.open_auth: accept_password = lambda u, p: True
    # --user set: check password
    elif users: accept_password = lambda u, p: users.get(u) == p
    # default: deny everything
    else: accept_password = lambda u, p: False

    # --open-auth set: always return true
    if args.open_auth: accept_key = lambda fp: True
    # --authorized-keys set: check the key
    elif auth_keys_fps: accept_key = lambda fp: fp in auth_keys_fps
    # default: deny everything
    else: accept_key = lambda fp: False

    log_only = not (args.scp_upload or args.scp_download or args.forward or args.reverse)

    class SSHCatchServer(asyncssh.SSHServer):
        def connection_made(self, conn):
            self._conn = conn
            # wrap asyncssh send_userauth_success to send post-auth-banner
            if args.post_auth_banner:
                self._orig_send_success = conn.send_userauth_success
                conn.send_userauth_success = self._wrapped_send_success
            self._version_logged = False
            self._authenticated = False
            # save last key fingerprint to dedup key probe/sign
            self._last_key_fp = None
            self._post_sent = False
            peer = conn.get_extra_info("peername")
            self._addr = addr_str(peer[0], peer[1]) if peer else "?"
            log_conn("Connection opened", addr=self._addr)

        def _log_client_version(self):
            if self._version_logged: return
            version = self._conn.get_extra_info("client_version")
            if version:
                self._version_logged = True
                log_conn(f"Client version: {version}", addr=self._addr, level=logging.INFO)

        def connection_lost(self, exc):
            # fallback for clients that grab the banner and drop without auth
            self._log_client_version()
            user = self._conn.get_extra_info("username")
            level = logging.WARNING if self._authenticated else logging.DEBUG
            if exc: log_conn(f"Connection lost: {exc}", addr=self._addr, user=user, level=level)
            else: log_conn("Connection closed", addr=self._addr, user=user, level=level)

        # -- banner ---------------------------------------------------
        
        def _send_banner(self, text):
            # Send auth messages so we never have to open a session 
            self._conn.send_auth_banner(text if text.endswith("\n") else text + "\n")

        def begin_auth(self, username):
            self._log_client_version()
            if args.pre_auth_banner:
                self._send_banner(args.pre_auth_banner)
            return True

        def _post_auth(self):
            # guard: send_userauth_success should only fire once per connection
            if args.post_auth_banner and not self._post_sent:
                self._post_sent = True
                self._send_banner(args.post_auth_banner)

        async def _wrapped_send_success(self, *args, **kwargs):
            try: self._post_auth()
            except Exception: pass
            return await self._orig_send_success(*args, **kwargs)

        # -- authentication -------------------------------------------

        def public_key_auth_supported(self):
            # always accept offers so we can log them
            return True  

        def validate_public_key(self, username, key):
            fp = key.get_fingerprint()
            accepted = accept_key(fp)
            # we log only the first time we see a key because clients
            #   may send probe first and then sign
            if fp != self._last_key_fp:   
                self._last_key_fp = fp
                if accepted: log_auth(f"Key accepted: {fp}", success=True, addr=self._addr, user=username)
                else: log_auth(f"Key rejected: {fp}", success=False, addr=self._addr, user=username)
                log_auth(f"{' '*14}{key.export_public_key().decode().strip()}", addr=self._addr, user=username, level=logging.INFO)
            return accepted

        def password_auth_supported(self):
            # always accept passwords so we can log them
            return True

        def validate_password(self, username, password):
            accepted = accept_password(username, password)
            if accepted:
                log_auth(f"Password accepted: {password}", success=True, addr=self._addr, user=username)
            else:
                log_auth(f"Password rejected: {password}", success=False, addr=self._addr, user=username)
            return accepted

        def auth_completed(self):
            self._authenticated = True
            # Resolve the future to release the bind port
            if single_future is not None and not single_future.done():
                single_future.set_result(self._conn)
            # Schedule to close the connection if we dont need it
            if log_only: 
                asyncio.get_running_loop().call_later(0.5, self._conn.close)

        # -- tunneling ------------------------------------------------

        def connection_requested(self, dest_host, dest_port, orig_host, orig_port):
            user = self._conn.get_extra_info("username")
            if not args.forward:
                log_tunnel(f"DENIED forward {addr_str(orig_host, orig_port)} -> "
                           f"{addr_str(dest_host, dest_port)}", addr=self._addr, user=user)
                return False
            log_tunnel(f"Forward {addr_str(orig_host, orig_port)} -> "
                       f"{addr_str(dest_host, dest_port)}", addr=self._addr, user=user)
            return True

        def server_requested(self, listen_host, listen_port):
            user = self._conn.get_extra_info("username")
            if not args.reverse:
                log_tunnel(f"DENIED reverse {addr_str(listen_host, listen_port)}", addr=self._addr, user=user)
                return False
            log_tunnel(f"Reverse listen on {addr_str(listen_host, listen_port)}", addr=self._addr, user=user)

            def accept(orig_host, orig_port):
                # Log the connection - real target is requested/resolved on the
                #   client so we can't show it (decided against packet inspection)
                log_tunnel(f"Reverse {addr_str(orig_host, orig_port)} on "
                           f"{addr_str(listen_host, listen_port)}", addr=self._addr, user=user)
                return True
            return accept

    return SSHCatchServer, len(users), len(auth_keys_fps)


# ── Server start ──────────────────────────────────────────────────────

async def start_server(args):
    # Handle Host key
    key_path = args.host_key if args.host_key else Path.cwd()
    if key_path.is_dir(): 
        key_path = key_path / "sshcatch_host_key"
    if not key_path.parent.is_dir():
        raise FileNotFoundError(f"Host key directory does not exist: {key_path.parent}")

    if key_path.is_file():
        host_key = asyncssh.read_private_key(str(key_path))
        log_info(f"Read host key: {key_path}")
    else:
        host_key = asyncssh.generate_private_key("ssh-ed25519")
        host_key.write_private_key(str(key_path))
        log_info(f"Generated host key: {key_path}")
        if os.name == "posix": key_path.chmod(0o600)
        else: log_info("Please make sure the permissions on the host key are securely set!", level=logging.WARNING)
    fingerprint = host_key.get_fingerprint()

    # for single-connection mode - resolving releases the bind on the listen port
    single_future = asyncio.get_running_loop().create_future() if args.single else None

    # Build the connection options for the ssh server
    server_factory, n_users, n_keys = make_server_factory(args, single_future)
    opts = {
        "server_factory": server_factory,
        "server_host_keys": [host_key],
        # SFTPv3 only so all transfers use open() and not open56()
        "sftp_version": 3,
    }
    if args.version_banner: 
        opts["server_version"] = args.version_banner

    has_scp = args.scp_upload or args.scp_download
    if has_scp:
        scp_dir = args.scp_dir.resolve()
        protected_files = set()
        for p in (key_path, args.authorized_keys, args.output, Path(__file__)):
            if p is None: continue
            try: rel = p.resolve().relative_to(scp_dir)
            except ValueError: continue
            protected_files.add(rel.as_posix())
        if protected_files:
            log_info(f"Protected in scp dir: {', '.join(sorted(protected_files))}")
        opts["sftp_factory"] = lambda chan: SFTPCatchServer(
            chan, chroot=str(scp_dir),
            allow_upload=args.scp_upload, allow_download=args.scp_download,
            protected_files=protected_files,
        )
        opts["allow_scp"] = True
    else:
        # We dont even create the SFTP Server if we dont have to 
        def denied_sftp(chan):
            conn = chan.get_connection()
            user = conn.get_extra_info("username") or "?"
            peer = conn.get_extra_info("peername")
            addr = addr_str(peer[0], peer[1]) if peer else "?"
            log_scp("DENIED SFTP", addr=addr, user=user, level=logging.WARNING)
            raise asyncssh.SFTPPermissionDenied("SCP/SFTP is disabled")
        opts["sftp_factory"] = denied_sftp
        # We allow logins however so we can log connections and credentials
        opts["allow_scp"] = True

    # Create our options object so everything is validated against asyncssh before we print it
    options = await asyncssh.SSHServerConnectionOptions.construct(**opts)

    # Print Startup Information
    if args.bind: bind = addr_str(args.bind, args.port)
    else: bind = f"{addr_str('0.0.0.0', args.port)} {addr_str('::', args.port)}"
    if args.open_auth: auth_mode = "open (accept any)"
    elif args.user or args.authorized_keys:
        parts = []
        if args.user: parts.append(f"{n_users} user{'s'*(n_users!=1)}")
        if args.authorized_keys: parts.append(f"{n_keys} key{'s'*(n_keys!=1)}")
        auth_mode = f"restricted ({', '.join(parts)})"
    else: auth_mode = "reject all (no auth configured)"
    features = []
    if args.forward: features.append("forward-tunnel")
    if args.reverse: features.append("reverse-tunnel")
    if args.scp_upload: features.append("scp-upload")
    if args.scp_download: features.append("scp-download")
    if not features: features.append("log-only (connect & close)")

    # Startup summary - logged at default tier, so it lands in --output too and
    #   is hidden by -q (like any other default-tier line)
    summary = [f"Listen ........ {bind}",
               f"Auth .......... {auth_mode}",
               f"Features ...... {', '.join(features)}"]
    if args.single: summary.append("Mode .......... single-connection")
    if has_scp: summary.append(f"SCP dir ....... {args.scp_dir.resolve()}")
    summary.append(f"Version ....... SSH-2.0-{options.version.decode()}")
    if args.pre_auth_banner: summary.append(f"Pre-auth ...... {banner_preview(args.pre_auth_banner)}")
    if args.post_auth_banner: summary.append(f"Post-auth ..... {banner_preview(args.post_auth_banner)}")
    summary.append(f"Host key ...... {fingerprint}")
    summary.append(f"Key file ...... {key_path}")
    log_info("sshcatch\n" + "\n".join(f"  {line}" for line in summary), level=logging.WARNING)

    acceptor = await asyncssh.listen(host=args.bind, port=args.port, options=options)
    if single_future is not None:
        # blocks until future is resolved (after first successful auth)
        held_conn = await single_future
        acceptor.close()
        log_info("Listener closed (single-connection mode) - port released", level=logging.WARNING)
        # keep running until the connection ends
        await held_conn.wait_closed()       
        log_info("Held connection closed - exiting", level=logging.WARNING)
    else:
        # run forever
        await asyncio.Event().wait()  


# ── Main ──────────────────────────────────────────────────────────────

# Quick --version-banner presets: keyword -> realistic 'SSH-2.0-<value>' banner.
VERSION_PRESETS = {
    "ubuntu":   "OpenSSH_9.6p1 Ubuntu-3ubuntu13.5",
    "debian":   "OpenSSH_9.2p1 Debian-2+deb12u3",
    "dropbear": "dropbear_2022.83",
    "windows":  "OpenSSH_for_Windows_9.5",
    "macos":    "OpenSSH_9.8",
}

_description="""\
sshcatch - a quick-deploy SSH server for tunneling (local/remote/dynamic)
and simple SCP transfers (NEVER opens a shell!).
By default all features are disabled: connections are logged and
closed. Use flags to enable features.
"""

_epilog="""\
examples:
  %(prog)s                                           Log-only (capture creds)
  %(prog)s -u user:pass --scp-download               Allow one user to download via SCP/SFTP
  %(prog)s --open-auth --forward                     Allow ANYONE! to tunnel through this SSH server
  # My favorite one
  #   Allows reverse tunnels and uploads via SCP for the keys in ./authorized_keys
  #   while posing as an Ubuntu SSH server on port 2222
  %(prog)s --reverse --authorized-keys ./authorized-keys --scp-upload --version-banner ubuntu -p 2222
"""

def main():
    parser = argparse.ArgumentParser(
        description=_description,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=_epilog)
    parser.add_argument("--version", action="version",
                        version=f"%(prog)s {__version__}")
    parser.add_argument("-p", "--port", type=int, default=22,
                        help="listen port (default: 22)")
    parser.add_argument("-b", "--bind", default="",
                        help="bind address (default: all IPv4/v6 interfaces)")
    parser.add_argument("--host-key", metavar="FILE", type=Path,
                        help="server host key file (default: auto-generate)")
    parser.add_argument("-1", "--single", action="store_true",
                        help="close the listener after first successful authentication "
                             "(and exit when that connection ends)")

    auth = parser.add_argument_group("authentication")
    auth.add_argument("-u", "--user", action="append", metavar="USER:PASS",
                      help="allowed user:password (repeatable)")
    auth.add_argument("--open-auth", action="store_true",
                      help="accept any credentials (open mode)")
    auth.add_argument("--authorized-keys", metavar="FILE", type=Path,
                      help="authorized_keys file for key auth (username independent)")

    tunnel = parser.add_argument_group("tunneling")
    tunnel.add_argument("--forward", action="store_true",
                        help="enable forward tunnels (client: ssh -NL / -ND)")
    tunnel.add_argument("--reverse", action="store_true",
                        help="enable reverse tunnels (client: ssh -NR)")

    scp = parser.add_argument_group("SCP / SFTP file transfer")
    scp.add_argument("--scp-upload", action="store_true",
                     help="enable file upload (SCP/SFTP write) - "
                          "files get suffix instead of overwriting - "
                          "symlinks become placeholder files")
    scp.add_argument("--scp-download", action="store_true",
                     help="enable file download (SCP/SFTP read) - "
                          "symlinks are denied")
    scp.add_argument("--scp-dir", default=Path.cwd(), metavar="DIR", type=Path,
                     help="directory for SCP/SFTP (default: cwd) - "
                          "sensitive files (host-key, authorized_keys, logfile) are protected")

    banners = parser.add_argument_group("banners")
    banners.add_argument("--version-banner", metavar="STRING",
                         help="sent as 'SSH-2.0-STRING' version banner - "
                             f"presets (case-insensitive): {', '.join(VERSION_PRESETS)}")
    banners.add_argument("--pre-auth-banner", metavar="STRING",
                         help="banner shown to every client before login")
    banners.add_argument("--post-auth-banner", metavar="STRING",
                         help="banner shown only to clients that authenticate successfully")

    logs = parser.add_argument_group("logging")
    verbosity = logs.add_mutually_exclusive_group()
    verbosity.add_argument("-q", "--quiet", action="store_true",
                           help="print nothing on console")
    verbosity.add_argument("-v", "--verbose", action="count", default=0,
                           help="print additional information to the console (repeatable)")
    logs.add_argument("-o", "--output", metavar="FILE", type=Path,
                      help="append the log to FILE (plain with timestamps)")
    logs.add_argument("-t", "--timestamps", action="store_true",
                      help="prefix console lines with a timestamp")
    logs.add_argument("--plain", action="store_true",
                      help="disable ANSI colors on the console")

    args = parser.parse_args()

    # Validate the log output path
    if args.output and not args.output.parent.is_dir():
        parser.error(f"Log directory does not exist: {args.output.parent}")

    # Set up logging before anything logs
    if args.quiet:          console_level = logging.ERROR
    elif args.verbose >= 2: console_level = logging.DEBUG
    elif args.verbose == 1: console_level = logging.INFO
    else:                   console_level = logging.WARNING
    configure_logging(output=args.output, timestamps=args.timestamps,
                      plain=args.plain, console_level=console_level)

    # Handle version-banner presets
    if args.version_banner:
        args.version_banner = VERSION_PRESETS.get(
            args.version_banner.lower(), args.version_banner)

    # Validate user format
    if args.user:
        for entry in args.user:
            if ":" not in entry:
                parser.error(f"Invalid user format '{entry}', expected USER:PASS")

    # Validate scp-dir
    if args.scp_upload or args.scp_download:
        scp_dir = args.scp_dir.resolve()
        if not scp_dir.is_dir():
            parser.error(f"SCP directory does not exist: {scp_dir}")

    # Validate authorized-keys
    if args.authorized_keys and not args.authorized_keys.is_file():
        parser.error(f"Authorized-keys file not found: {args.authorized_keys}")

    try: asyncio.run(start_server(args))
    except PermissionError:
        parser.error(f"Permission denied - port {args.port} requires root")
    except OSError as e:
        parser.error(f"Could not start server: {e}")
    except KeyboardInterrupt:
        print()


if __name__ == "__main__":
    main()
