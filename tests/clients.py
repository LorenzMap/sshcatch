"""Test clients for sshcatch.

Two backends, split by capability:

* **asyncssh** - drives every behavioural test (auth policy, tunnels, SFTP
  file-ops, banner/version/host-key introspection). It speaks passwords
  non-interactively and probes a shell-less server cleanly, which the OpenSSH
  CLI cannot.
* **OpenSSH CLI (+ sshpass)** - drives the interop tests only, to prove a real
  client talks to sshcatch.

The tests were generated using Claude Opus 4.8 from my handwritten testcases. 
I manually checked all of them and made some adjustments. However, I was not
as diligent regarding code quality and style as with the main 'sshcatch.py'
file.
"""
import asyncio, contextlib, os, re, socket, subprocess, sys
from pathlib import Path

import asyncssh

# ── paths / patterns ──────────────────────────────────────────────
REPO = Path(__file__).resolve().parent.parent
SRC  = REPO / "sshcatch.py"
PY   = sys.executable            # the venv interpreter that has asyncssh
ANSI = re.compile(r"\x1b\[[0-9;]*m")
TS   = re.compile(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}")


def run(coroutine):
    return asyncio.run(coroutine)


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def port_open(port):
    with socket.socket() as s:
        s.settimeout(0.5)
        try:
            s.connect(("127.0.0.1", port))
            return True
        except OSError:
            return False


def gen_key(path):
    """Write a fresh ed25519 keypair to *path* (+ .pub); return the Path"""
    path = Path(path)
    k = asyncssh.generate_private_key("ssh-ed25519")
    k.write_private_key(path)
    path.with_suffix(".pub").write_text(k.export_public_key().decode())
    path.chmod(0o600)             # OpenSSH refuses group/world-readable keys
    return path


def sshcatch_cmd():
    """Base argv to launch sshcatch wrapped in `coverage run` when SSHCATCH_COV
    is set (see the --coverage pytest flag) (off by default)"""
    if os.environ.get("SSHCATCH_COV"):
        # per-process data files come from the rcfile's [tool.coverage.run]
        # parallel=true; run `coverage combine` afterwards. combine reports
        # "skipped N" for processes whose coverage was identical to another
        # (e.g. repeated identical launches) that is lossless dedup, not lost
        # coverage
        return [PY, "-m", "coverage", "run",
                "--rcfile", str(REPO / "pyproject.toml"), str(SRC)]
    return [PY, str(SRC)]


def run_cli(*args):
    """Run sshcatch once (no live client) and return (returncode, output)"""
    r = subprocess.run([*sshcatch_cmd(), *args], capture_output=True, text=True)
    return r.returncode, r.stdout + r.stderr


# ── asyncssh backend ──────────────────────────────────────────────
@contextlib.asynccontextmanager
async def connect(port, username="u", password="x", **kw):
    kw.setdefault("known_hosts", None)
    kw.setdefault("client_keys", None)
    kw.setdefault("preferred_auth", ["password"])
    conn = await asyncio.wait_for(
        asyncssh.connect("127.0.0.1", port=port, username=username,
                         password=password, **kw), 6)
    try: yield conn
    finally: conn.close()


@contextlib.asynccontextmanager
async def sftp(port, **auth):
    async with connect(port, **auth) as c:
        async with c.start_sftp_client() as s:
            yield s


def _try(coro_fn):
    try: return run(coro_fn())
    except Exception: return False


def sftp_call(port, action, **auth):
    """Open an SFTP session and await ``action(sftp)``; return its result

    ``action`` is a callable taking the client and returning a coroutine, e.g.
    ``lambda f: f.get("a.txt", "/tmp/a")`` Errors propagate
    """
    async def go():
        async with sftp(port, **auth) as f:
            return await action(f)
    return run(go())


def sftp_ok(port, action, **auth):
    """True if the SFTP ``action`` succeeds, False if the server refuses it"""
    try:
        sftp_call(port, action, **auth)
        return True
    except Exception:
        return False


def pw_login(port, user, pw):
    async def go():
        async with connect(port, username=user, password=pw):
            return True
    return _try(go)


def key_login(port, keyfile):
    async def go():
        async with connect(port, username="u", client_keys=[keyfile],
                           preferred_auth=["publickey"]):
            return True
    return _try(go)


def kbdint_login(port, user="u", pw="x"):
    """True if keyboard-interactive auth succeeds (asyncssh answers the prompt with *pw*)"""
    async def go():
        async with connect(port, username=user, password=pw,
                           preferred_auth=["keyboard-interactive"]):
            return True
    return _try(go)


def login_dropped_by_server(port, wait=1.5, **auth):
    """Log in, hold the session, and report whether the *server* closes it within *wait*

    True in log-only mode (no features): the server accepts, logs, then hangs up
    """
    async def go():
        async with connect(port, **auth) as c:
            try:
                await asyncio.wait_for(c.wait_closed(), wait)
                return True                       # server closed us
            except asyncio.TimeoutError:
                return False                      # still open
    return run(go())


def server_version(port, **auth):
    async def go():
        async with connect(port, **auth) as c:
            v = c.get_extra_info("server_version")
            return v.decode() if isinstance(v, bytes) else str(v)
    try:  return run(go())
    except Exception as e: return f"err:{e}"


def pinned_hostkey(port, alg):
    """Force a single server-host-key algorithm; return what got negotiated"""
    async def go():
        async with connect(port, server_host_key_algs=[alg]) as c:
            return c.get_server_host_key().get_algorithm()
    try: return run(go())
    except Exception as e:
        return f"err:{type(e).__name__}: {e}"


class _BannerClient(asyncssh.SSHClient):
    def __init__(self):
        self.got = []

    def auth_banner_received(self, msg, lang):
        self.got.append(msg)


def collect_banners(port, username, password, wait=0.0):
    """Return the auth banners the server sent (works even on failed auth)"""
    async def go():
        b = _BannerClient()
        try:
            c, _ = await asyncio.wait_for(asyncssh.create_connection(
                lambda: b, "127.0.0.1", port=port, username=username,
                password=password, known_hosts=None, client_keys=None,
                preferred_auth=["password"]), 6)
            if wait:
                await asyncio.sleep(wait)
            c.close()
        except asyncssh.PermissionDenied:
            pass
        return b.got
    return run(go())


def forward_flow(port):
    """Open a local (direct-tcpip) forward to a throwaway echo server"""
    async def go():
        echo_port = free_port()

        async def handle(r, w):
            data = await r.read(100)
            w.write(b"echo:" + data)
            await w.drain()
            w.close()

        srv = await asyncio.start_server(handle, "127.0.0.1", echo_port)
        try:
            async with connect(port) as c:
                try:
                    r, w = await asyncio.wait_for(
                        c.open_connection("127.0.0.1", echo_port), 6)
                    w.write(b"hi")
                    return await asyncio.wait_for(r.read(100), 6)
                except Exception as e:
                    return f"denied:{type(e).__name__}"
        finally:
            srv.close()
            await srv.wait_closed()
    return run(go())


def reverse_probe(port):
    """Ask for a remote (reverse) port listener"""
    async def go():
        async with connect(port) as c:
            try:
                lst = await asyncio.wait_for(
                    c.forward_remote_port("127.0.0.1", 0, "127.0.0.1", 9), 6)
                lst.close()
                return "accepted"
            except Exception as e:
                return f"denied:{type(e).__name__}"
    return run(go())


def unix_forward_probe(port):
    """direct-streamlocal must always be refused"""
    async def go():
        async with connect(port) as c:
            try:
                await asyncio.wait_for(
                    c.open_unix_connection("/tmp/sshcatch_test.sock"), 6)
                return "accepted"
            except Exception as e:
                return f"denied:{type(e).__name__}"
    return run(go())


def unix_reverse_probe(port):
    """streamlocal-forward must always be refused"""
    async def go():
        async with connect(port) as c:
            try:
                lst = await asyncio.wait_for(
                    c.forward_remote_path("/tmp/sshcatch_test.sock", "127.0.0.1", 9), 6)
                lst.close()
                return "accepted"
            except Exception as e:
                return f"denied:{type(e).__name__}"
    return run(go())


def tun_probe(port):
    """Layer-3 TUN tunnel (ssh -w) - must always be refused"""
    async def go():
        async with connect(port) as c:
            try:
                await asyncio.wait_for(c.open_tun(0), 6)
                return "accepted"
            except Exception as e:
                return f"denied:{type(e).__name__}"
    return run(go())


def tap_probe(port):
    """Layer-2 TAP tunnel - must always be refused"""
    async def go():
        async with connect(port) as c:
            try:
                await asyncio.wait_for(c.open_tap(0), 6)
                return "accepted"
            except Exception as e:
                return f"denied:{type(e).__name__}"
    return run(go())


# ── OpenSSH CLI backend (interop) ─────────────────────────────────
BASE_OPTS = ["-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
             "-o", "LogLevel=ERROR"]
KEY_OPTS  = BASE_OPTS + ["-o", "BatchMode=yes"]
# BatchMode disables password prompts, so password auth uses the base set and
# forces keyboard-less password via sshpass.
PW_OPTS   = BASE_OPTS + ["-o", "PreferredAuthentications=password",
                         "-o", "PubkeyAuthentication=no"]


def _key_args(key):
    return ["-i", key] if key else []


def cli_scp_get(port, remote, local, key=None, recursive=False):
    r = ["-r"] if recursive else []
    return subprocess.run(["scp", *r, *KEY_OPTS, *_key_args(key), "-P", str(port),
                           f"u@127.0.0.1:{remote}", local],
                          capture_output=True).returncode


def cli_scp_put(port, local, remote, key=None, recursive=False):
    r = ["-r"] if recursive else []
    return subprocess.run(["scp", *r, *KEY_OPTS, *_key_args(key), "-P", str(port),
                           local, f"u@127.0.0.1:{remote}"],
                          capture_output=True).returncode


def cli_sftp(port, script, key=None):
    """Run an sftp batch (key auth); return (returncode, stdout+stderr)."""
    r = subprocess.run(["sftp", *KEY_OPTS, *_key_args(key), "-P", str(port),
                        "-b", "-", "u@127.0.0.1"],
                       input=script, capture_output=True, text=True)
    return r.returncode, r.stdout + r.stderr


def cli_scp_pw(port, user, pw, remote, local):
    """Download *remote* by password auth via sshpass; return (rc, out)

    Uses scp rather than `sftp -b`: batch-mode sftp forces BatchMode=yes, which
    disables the password prompt sshpass needs to answer
    """
    r = subprocess.run(["sshpass", "-p", pw, "scp", *PW_OPTS, "-P", str(port),
                        f"{user}@127.0.0.1:{remote}", local],
                       capture_output=True, text=True)
    return r.returncode, r.stdout + r.stderr


def cli_keyscan(port, types="rsa,ecdsa,ed25519"):
    scan = subprocess.run(["ssh-keyscan", "-p", str(port), "-t", types, "127.0.0.1"],
                          capture_output=True, text=True).stdout
    return {l.split()[1] for l in scan.splitlines()
            if not l.startswith("#") and len(l.split()) > 1}
