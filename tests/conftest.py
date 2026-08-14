"""Shared pytest fixtures + an upfront check that the tools we need exist"""
import importlib.util
import os, shutil, subprocess, time
from pathlib import Path

import pytest

if importlib.util.find_spec("asyncssh") is None:
    raise pytest.UsageError(
        "Missing test prerequisite(s): asyncssh (python module)\n"
        "Run pytest with the repo venv interpreter, e.g. `.venv/bin/python -m pytest`.")

from clients import ANSI, free_port, gen_key, port_open, sshcatch_cmd

# pyproject.toml setup
#   [tool.coverage.run]
#   source = ["sshcatch"]
#   parallel = true    # one data file per spawned process; `coverage combine` merges them
#   sigterm = true     # the server fixture stops sshcatch with terminate() (SIGTERM)
#   branch = true

# External binaries the suite relies on. asyncssh (imported in clients.py) drives
# the behavioural tests; these drive the interop tests (sshpass for passwords).
REQUIRED_TOOLS = ["ssh", "scp", "sftp", "ssh-keyscan", "ssh-keygen", "sshpass"]


def pytest_addoption(parser):
    parser.addoption("--coverage", action="store_true", default=False,
                     help="Measure coverage of the spawned sshcatch.py processes "
                          "(writes .coverage.* files; run `coverage combine` after)")


def pytest_configure(config):
    """Fail fast, with one clear message, if a required external tool is missing"""
    missing = [t for t in REQUIRED_TOOLS if shutil.which(t) is None]
    if missing:
        raise pytest.UsageError(
            "Missing test prerequisite(s): " + ", ".join(missing) +
            "\nInstall them, e.g. `apt install openssh-client sshpass`.")
    # Bridge the flag to an env var so both the server fixture and run_cli
    # (a plain module function without pytest config) launch under coverage.
    if config.getoption("--coverage"):
        os.environ["SSHCATCH_COV"] = "1"


class Server:
    """A running sshcatch process plus its observable output

    ``stop()`` is idempotent: a test calls it (via ``.console`` / ``.raw``) to
    read what the server printed, and fixture teardown calls it again to clean
    up - the second call is a no-op
    """

    def __init__(self, proc, port, log_path):
        self.proc = proc
        self.port = port
        self._log_path = log_path
        self._raw = None

    def stop(self):
        if self._raw is None:
            if self.proc.poll() is None:
                self.proc.terminate()
                try:
                    self.proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self.proc.kill()
            self._raw = self.proc.stdout.read() if self.proc.stdout else ""
        return self.console

    @property
    def raw(self):
        """Console output with ANSI colour intact (for the colour test)"""
        if self._raw is None:
            self.stop()
        return self._raw

    @property
    def console(self):
        """Console output, ANSI stripped."""
        return ANSI.sub("", self.raw)

    @property
    def log(self):
        """Contents of the -o log file, or '' if none was requested"""
        if self._log_path and self._log_path.exists():
            return self._log_path.read_text()
        return ""


@pytest.fixture
def server(tmp_path):
    """Factory that spawns configured sshcatch instances and cleans them up

    Usage: ``s = server("--open-auth", "--forward")`` then drive ``s.port``
    Pass ``capture=True`` to read ``s.console`` afterwards, ``log=path`` for -o
    """
    started = []

    def _start(*args, log=None, plain=True, capture=False,
               bind="127.0.0.1", hostkey=None, port=None):
        port = port or free_port()
        host_key_file = Path(hostkey) if hostkey else tmp_path / f"host_key_{port}"
        log = Path(log) if log else None
        cmd = [*sshcatch_cmd(), "-p", str(port), "-b", bind,
               "--host-key", host_key_file, *args]
        if plain: cmd.append("--plain")
        if log: cmd += ["-o", log]
        out = subprocess.PIPE if capture else subprocess.DEVNULL
        p = subprocess.Popen(cmd, stdout=out, stderr=subprocess.PIPE, text=True)
        for _ in range(50):
            if port_open(port) or p.poll() is not None:
                break
            time.sleep(0.1)
        time.sleep(0.3)
        s = Server(p, port, log)
        started.append(s)
        return s

    yield _start
    for s in started:
        s.stop()


@pytest.fixture(scope="session")
def client_key(tmp_path_factory):
    """A reusable ed25519 client keypair; returns the private-key path"""
    key_dir = tmp_path_factory.mktemp("ckey")
    return gen_key(key_dir / "ckey")
