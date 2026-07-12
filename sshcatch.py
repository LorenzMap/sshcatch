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
from pathlib import Path
from itertools import count

import asyncssh

__version__ = "0.1.1"

# ── Logging ─--────────────────────────────────────────────────────────

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
PURPLE = "\033[95m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RST = "\033[0m"

def configure_logging(output=None, timestamps=False, plain=False):
    logger = logging.getLogger("sshcatch")
    logger.setLevel(logging.INFO)
    logger.propagate = False
    logger.handlers.clear()

    # Setup console logging
    field = "plain" if plain else "colored"
    line = f"%({field})s %(message)s"
    if timestamps:
        line = "%(asctime)s " + line
    out = logging.StreamHandler(sys.stdout)
    out.setFormatter(logging.Formatter(line, datefmt="%Y-%m-%d %H:%M:%S"))
    logger.addHandler(out)

    # Setup File Logging
    if output:
        file_handler = logging.FileHandler(output, mode="a", encoding="utf-8")
        file_handler.setFormatter(logging.Formatter("%(asctime)s %(plain)s %(message)s",
                                          datefmt="%Y-%m-%d %H:%M:%S"))
        logger.addHandler(file_handler)

def _log(tag, color, msg, addr=None, user=None):
    logger = logging.getLogger("sshcatch")
    loc = (f"{BOLD}[{addr}]{RST}" if addr else "") + (f"{BOLD}[{user}]{RST}" if user else "")
    colored = f"{color}[{tag}]{RST}" + loc
    plain = f"[{tag}]" + (f"[{addr}]" if addr else "") + (f"[{user}]" if user else "")
    logger.info(msg, extra={"colored": colored, "plain": plain})

def log_conn(msg, addr=None, user=None):
    _log("+", GREEN, msg, addr, user)

def log_auth(msg, success=False, addr=None, user=None):
    _log("AUTH", GREEN if success else YELLOW, msg, addr, user)

def log_scp(msg, addr=None, user=None):
    _log("SCP", PURPLE, msg, addr, user)

def log_tunnel(msg, addr=None, user=None):
    _log("TUNNEL", CYAN, msg, addr, user)

def log_info(msg, addr=None, user=None):
    _log("*", BOLD, msg, addr, user)

def addr_str(host, port):
    if ":" in str(host): return f"[{host}]:{port}"
    else: return f"{host}:{port}"


# ── SFTP server ───────────────────────────────────────────────────────

DENY = asyncssh.SFTPPermissionDenied

class SFTPCatchServer(asyncssh.SFTPServer):
    def __init__(self, chan, chroot, allow_upload, allow_download, protected_files=()):
        super().__init__(chan, chroot=chroot)
        self._root = Path(chroot)
        self._allow_upload = allow_upload
        self._allow_download = allow_download
        self._protected_files = set(protected_files)
        conn = chan.get_connection()
        self._user = conn.get_extra_info("username") or "?"
        peer = conn.get_extra_info("peername")
        self._addr = addr_str(peer[0], peer[1]) if peer else "?"
        self._log_scp("Session opened")

    def _log_scp(self, msg):
        log_scp(msg, addr=self._addr, user=self._user)

    # ── path checks ──────────────────────────────────────────────

    def _require_flat(self, path):
        # Simple check if subdirectories are used - full 'name' must be equal to basename
        #   after unecessary ./ are collapsed
        name = posixpath.normpath(path).lstrip(b"/")
        if name in (b"", b".", b"..") or name != posixpath.basename(name):
            self._log_scp(f"DENIED ACCESS {path.decode(errors='replace')}")
            raise DENY("Access restricted to root directory")

    def _require_not_protected(self, path):
        # Prevent access to protected files in the scp dir 
        #   (authorized_keys, host key, log file)
        if os.fsdecode(posixpath.basename(path)) in self._protected_files:
            self._log_scp(f"DENIED PROTECTED {path.decode(errors='replace')}")
            raise DENY("Not allowed")

    def _unique_write_path(self, path):
        # Check if the upload overwrites something
        # Watch out: asyncssh SFTP uses posixpath independently of the actual OS
        base = posixpath.basename(path)
        if not (self._root / os.fsdecode(base)).exists():
            return path
        # Simply add a number until we are unique
        stem, ext = posixpath.splitext(base)
        for n in count(1):
            name = b"%s_%d%s" % (stem, n, ext)
            if not (self._root / os.fsdecode(name)).exists():
                return b"/" + name

    # ── session / file handling ──────────────────────────────────

    def open(self, path, pflags, attrs):
        self._require_flat(path)
        self._require_not_protected(path)
        is_write = bool(pflags & (0x02 | 0x04 | 0x08))  # WRITE|APPEND|CREAT

        if is_write and not self._allow_upload:
            self._log_scp(f"DENIED WRITE {path.decode(errors='replace')}")
            raise DENY("Upload is disabled")
        if not is_write and not self._allow_download:
            self._log_scp(f"DENIED READ {path.decode(errors='replace')}")
            raise DENY("Download is disabled")

        # Prevent overwriting existing files
        if is_write:
            unique = self._unique_write_path(path)
            if unique != path:
                self._log_scp(f"EXISTS {path.decode(errors='replace')} -> "
                              f"{unique.decode(errors='replace')}")
                path = unique

        label = "WRITE" if is_write else "READ"
        self._log_scp(f"{label} {path.decode(errors='replace')}")
        return super().open(path, pflags, attrs)

    def exit(self):
        self._log_scp("Session closed")
        return super().exit()

    # ── blocked operation overwritten for better logging ────────────

    def remove(self, path):
        self._log_scp(f"DENIED DELETE {path.decode(errors='replace')}")
        raise DENY("Not allowed")

    def rename(self, old, new):
        self._log_scp(f"DENIED RENAME {old.decode(errors='replace')}")
        raise DENY("Not allowed")

    def mkdir(self, path, attrs):
        self._log_scp(f"DENIED MKDIR {path.decode(errors='replace')}")
        raise DENY("Not allowed")

    def rmdir(self, path):
        self._log_scp(f"DENIED RMDIR {path.decode(errors='replace')}")
        raise DENY("Not allowed")

    def link(self, old, new):
        self._log_scp(f"DENIED LINK {old.decode(errors='replace')}")
        raise DENY("Not allowed")

    def symlink(self, old, new):
        self._log_scp(f"DENIED SYMLINK {old.decode(errors='replace')}")
        raise DENY("Not allowed")

    def scandir(self, path):
        self._log_scp(f"DENIED LISTDIR {path.decode(errors='replace')}")
        raise DENY("Not allowed")

# Overwriting every possible method on our SFTP server to prevent
#  unintended access
# Will probably break on bigger asyncssh updates
_SFTP_ALL_OPS = {
    # file I/O
    "open", "open56", "close", "read", "write",
    # attributes
    "stat", "lstat", "fstat", "setstat", "lsetstat", "fsetstat",
    # directory
    "scandir", "mkdir", "rmdir",
    # path ops
    "realpath", "readlink", "symlink", "link", "rename", "posix_rename", "remove",
    # filesystem
    "statvfs", "fstatvfs", "fsync",
    # locking
    "lock", "unlock",
    # lifecycle
    "exit",
    # internal helpers (called by base class, not by SFTP packets)
    "map_path", "reverse_map_path",
    "format_user", "format_group", "format_longname",
    "convert_attrs",
}

# Only these are allowed because they are required for basic filetransfer
#   Most of them follow symlinks, which we prevent by checking the scp directory
#   for them before start and don't even allow the server to run if they exist
_SFTP_WHITELIST = {
    "open",      # overridden above (with subdirectory prevention)
    "close",     # required to close file handles after read/write
    "read",      # required for file download (SCP get)
    "write",     # required for file upload (SCP put)
    "stat",      # SCP protocol queries file size/perms before transfer
    "lstat",     # like stat, but doesn't follow symlinks
    "fstat",     # stat on open file handle
    "setstat",   # SCP sets permissions and timestamps after upload
    "fsetstat",  # same as setstat but on an open file handle
    "realpath",  # resolves "." and ".." for path canonicalization
    "exit",      # overridden above
    # internal helpers - blocking these would break the server
    "map_path", "reverse_map_path",
    "format_user", "format_group", "format_longname",
    "convert_attrs",
}

def _make_sftp_deny(method_name):
    # Lets do some funky overwriting
    def denied(self, *args, **kwargs):
        self._log_scp(f"DENIED {method_name}")
        raise DENY("Not allowed")
    denied.__name__ = method_name
    return denied

# Block everything not whitelisted 
#   and skip methods already overridden in our class
for _name in _SFTP_ALL_OPS - _SFTP_WHITELIST:
    if _name not in SFTPCatchServer.__dict__:
        setattr(SFTPCatchServer, _name, _make_sftp_deny(_name))


# ── SSH server factory ────────────────────────────────────────────────

def make_server_factory(args):
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
                log_info(f"Invalid key    line={i}  {e}")

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
            self._version_logged = False
            # save last key fingerprint to dedup key probe/sign
            self._last_key_fp = None
            # track if we already sent the post-auth banner
            self._post_sent = False
            peer = conn.get_extra_info("peername")
            self._addr = addr_str(peer[0], peer[1]) if peer else "?"
            log_conn("Connection opened", addr=self._addr)

        def _log_client_version(self):
            if self._version_logged: return
            version = self._conn.get_extra_info("client_version")
            if version:
                self._version_logged = True
                log_conn(f"Client version: {version}", addr=self._addr)

        def connection_lost(self, exc):
            # fallback for clients that grab the banner and drop without auth
            self._log_client_version()
            user = self._conn.get_extra_info("username")
            if exc: log_conn(f"Connection lost: {exc}", addr=self._addr, user=user)
            else: log_conn("Connection closed", addr=self._addr, user=user)

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
            # guarded because key auth may call this twice (probe + sign)
            if args.post_auth_banner and not self._post_sent:
                self._post_sent = True
                self._send_banner(args.post_auth_banner)

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
                if args.full_keys: log_auth(f"               {key.export_public_key().decode().strip()}", addr=self._addr, user=username)
            if accepted:
                self._post_auth()
                # Schedule to close the connection if we dont need it 
                if log_only: self._schedule_close()
            return accepted

        def password_auth_supported(self):
            # always accept passwords so we can log them
            return True

        def validate_password(self, username, password):
            accepted = accept_password(username, password)
            if accepted:
                log_auth(f"Password accepted: {password}", success=True, addr=self._addr, user=username)
                self._post_auth()
                # Schedule to close the connection if we dont need it 
                if log_only: self._schedule_close()
            else:
                log_auth(f"Password rejected: {password}", success=False, addr=self._addr, user=username)
            return accepted

        def _schedule_close(self):
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

    return SSHCatchServer


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
        host_key = asyncssh.generate_private_key("ssh-rsa", key_size=2048)
        host_key.write_private_key(str(key_path))
        log_info(f"Generated host key: {key_path}")
        if os.name == "posix": key_path.chmod(0o600)
        else: log_info(f"Please make sure the permissions on the host key are securely set!")
    fingerprint = host_key.get_fingerprint()

    # Build the connection options for the ssh server
    opts = {
        "server_factory": make_server_factory(args),
        "server_host_keys": [host_key],
        # SFTPv3 only so all transfers use open() and not open56()
        "sftp_version": 3,
    }
    if args.version_banner: 
        opts["server_version"] = args.version_banner

    has_scp = args.scp_upload or args.scp_download
    if has_scp:
        scp_dir = args.scp_dir.resolve()
        protected_files = {
            p.resolve().name
            for p in (key_path, args.authorized_keys, args.output)
            if p is not None and p.resolve().parent == scp_dir
        }
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
            log_scp("DENIED SFTP", addr=addr, user=user)
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
    elif args.user or args.authorized_keys: auth_mode = "restricted"
    else: auth_mode = "reject all (no auth configured)"
    features = []
    if args.forward: features.append("forward-tunnel")
    if args.reverse: features.append("reverse-tunnel")
    if args.scp_upload: features.append("scp-upload")
    if args.scp_download: features.append("scp-download")
    if not features: features.append("log-only (connect & close)")

    if args.plain: print(f"\n-- sshcatch --")
    else: print(f"\n{BOLD}sshcatch{RST}")
    print(f"  Listen ........ {bind}")
    print(f"  Auth .......... {auth_mode}")
    print(f"  Features ...... {', '.join(features)}")
    if has_scp: print(f"  SCP dir ....... {args.scp_dir.resolve()}")
    print(f"  Version ....... SSH-2.0-{options.version.decode()}")
    if args.pre_auth_banner: print(f"  Pre-auth ...... set")
    if args.post_auth_banner: print(f"  Post-auth ..... set")
    print(f"  Host key ...... {fingerprint}")
    print(f"  Key file ...... {key_path}")
    print()

    await asyncssh.listen(host=args.bind, port=args.port, options=options)
    await asyncio.Event().wait()  # run forever


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
  %(prog)s -K                                        Log-only (capture creds and full public keys)
  %(prog)s -u user:pass --scp-download               Allow one user to download via SCP/SFTP
  %(prog)s --open-auth --forward                     Allow ANYONE! to tunnel through this SSH server
  # My favorite one
  #   Allows reverse tunnels and uploads via SCP for the keys in ./authorized_keys
  #   while posing as a ubuntu SSH server on port 2222
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

    auth = parser.add_argument_group("authentication")
    auth.add_argument("-u", "--user", action="append", metavar="USER:PASS",
                      help="allowed user:password (repeatable)")
    auth.add_argument("--open-auth", action="store_true",
                      help="accept any credentials (open mode)")
    auth.add_argument("--authorized-keys", metavar="FILE", type=Path,
                      help="authorized_keys file for key auth (username independent)")
    auth.add_argument("-K", "--full-keys", action="store_true",
                      help="log the full offered public key, not just its fingerprint")

    tunnel = parser.add_argument_group("tunneling")
    tunnel.add_argument("--forward", action="store_true",
                        help="enable forward tunnels (client: ssh -NL / -ND)")
    tunnel.add_argument("--reverse", action="store_true",
                        help="enable reverse tunnels (client: ssh -NR)")

    scp = parser.add_argument_group("SCP / file transfer")
    scp.add_argument("--scp-upload", action="store_true",
                     help="enable file upload (SCP/SFTP write) - subdirectories are disabled - "
                          "files get suffix instead of overwriting")
    scp.add_argument("--scp-download", action="store_true",
                     help="enable file download (SCP/SFTP read) - subdirectories are disabled")
    scp.add_argument("--scp-dir", default=Path.cwd(), metavar="DIR", type=Path,
                     help="directory for SCP/SFTP (default: cwd) - subdirectories are disabled - "
                          "host-key (and optional authorized_keys and logfile) are protected")

    banners = parser.add_argument_group("banners")
    banners.add_argument("--version-banner", metavar="STRING",
                         help="sent as 'SSH-2.0-STRING' version banner - "
                             f"presets (case-insensitive): {', '.join(VERSION_PRESETS)}")
    banners.add_argument("--pre-auth-banner", metavar="STRING",
                         help="banner shown to every client before login")
    banners.add_argument("--post-auth-banner", metavar="STRING",
                         help="banner shown only to clients that authenticate successfully")

    logs = parser.add_argument_group("logging")
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
    configure_logging(output=args.output, timestamps=args.timestamps, plain=args.plain)

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
        # Scan for symlinks that point outside the chroot
        for entry in scp_dir.rglob("*"):
            if entry.is_symlink():
                parser.error(f"Symlink in SCP dir! We don't do that! ({entry})")

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
