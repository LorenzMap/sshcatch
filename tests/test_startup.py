"""Startup failures: every one goes through one handler and names its own cause"""
import os
import shutil
import subprocess

import asyncssh
import pytest

from clients import run_cli


def test_busy_port_reported(server, tmp_path):
    """A busy port should be reported as 'address already in use'"""
    host_key_file = tmp_path / "host_key"
    asyncssh.generate_private_key("ssh-ed25519").write_private_key(host_key_file)
    s = server("--open-auth", hostkey=host_key_file)   # occupies the port
    rc, out = run_cli("-p", str(s.port), "-b", "127.0.0.1", "--host-key", host_key_file)
    assert rc != 0 and "address already in use" in out, out.strip()[-100:]


def test_garbage_host_key_reported(tmp_path):
    """A garbage host-key file should be reported as unusable"""
    bad = tmp_path / "garbage"
    bad.write_text("not a key at all\n")
    rc, out = run_cli("-p", "0", "--host-key", bad)
    assert rc != 0 and "No usable host key" in out, out.strip()[-100:]


@pytest.mark.skipif(not shutil.which("ssh-keygen"),
                    reason="ssh-keygen needed to write an encrypted key")
def test_encrypted_host_key_reported(tmp_path):
    """An encrypted host-key file should be reported as unreadable"""
    enc = tmp_path / "encrypted"
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "secret", "-f", enc],
                   check=True, capture_output=True)
    rc, out = run_cli("-p", "0", "--host-key", enc)
    assert rc != 0 and "Could not read host key file" in out, out.strip()[-100:]


def test_missing_host_key_dir_reported(tmp_path):
    """A missing host-key directory should be reported"""
    rc, out = run_cli("-p", "0", "--host-key", tmp_path / "no_such_dir" / "host_key")
    assert rc != 0 and "Host key directory does not exist" in out, out.strip()[-100:]


@pytest.mark.skipif(os.geteuid() == 0, reason="root can write into a read-only dir")
def test_unwritable_key_file_not_blamed_on_port(tmp_path):
    """An unwritable key file should be reported as a permission error, not a port issue"""
    # port 22 on purpose: the old handler wrongly blamed missing root here
    ro = tmp_path / "readonly"
    ro.mkdir()
    ro.chmod(0o500)
    try:
        rc, out = run_cli("-p", "22", "--host-key", ro / "host_key")
    finally:
        ro.chmod(0o700)
    assert rc != 0 and "Permission denied" in out and "requires root" not in out, \
        out.strip()[-100:]
