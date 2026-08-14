"""Host-key generation, reuse, negotiation and back-compat"""
import os
import time

import asyncssh
import pytest

from clients import pinned_hostkey, pw_login

HK_ALGS = ["ssh-ed25519", "ssh-rsa", "ecdsa-sha2-nistp256"]


# ── generation & reuse ────────────────────────────────────────────
def test_first_run_generates_one_key_per_type(server, tmp_path):
    """The first run should generate one host key per type into a single file"""
    host_key_file = tmp_path / "multi_host_key"
    s = server("--open-auth", hostkey=host_key_file, capture=True)
    time.sleep(0.3)
    out = s.console

    keys = asyncssh.read_private_key_list(host_key_file)
    algs = [k.get_algorithm() for k in keys]
    assert algs == HK_ALGS, algs

    from cryptography.hazmat.primitives.serialization import load_ssh_private_key
    rsa = next(k for k in keys if k.get_algorithm() == "ssh-rsa")
    bits = load_ssh_private_key(rsa.export_private_key(), None).key_size
    assert bits == 3072, bits

    assert host_key_file.read_text().count("BEGIN OPENSSH PRIVATE KEY") == 3
    if os.name == "posix":
        assert oct(host_key_file.stat().st_mode & 0o777) == "0o600"

    lines = [l for l in out.splitlines() if "Host key" in l]
    assert len(lines) == 3, lines
    assert all(any(f"({a})" in l for l in lines) for a in HK_ALGS), lines


def test_host_key_file_reused(server, tmp_path):
    """An existing host-key file should be reused, not regenerated"""
    host_key_file = tmp_path / "reused_host_key"
    server("--open-auth", hostkey=host_key_file).stop()
    before = host_key_file.read_bytes()
    server("--open-auth", hostkey=host_key_file).stop()
    assert before == host_key_file.read_bytes()


# ── negotiation & single key files ────────────────────────────────
@pytest.mark.parametrize("alg,expect", [
    ("ssh-ed25519",         "ssh-ed25519"),
    ("ecdsa-sha2-nistp256", "ecdsa-sha2-nistp256"),
    ("rsa-sha2-512",        "ssh-rsa"),
])
def test_pinned_host_key_negotiates(server, tmp_path, alg, expect):
    """Every generated type should be negotiable by a pinned client"""
    s = server("--open-auth", hostkey=tmp_path / "host_key")
    assert pinned_hostkey(s.port, alg) == expect


def test_single_key_file(server, tmp_path):
    """A single-key file should load and serve its one key"""
    host_key_file = tmp_path / "single_host_key"
    asyncssh.generate_private_key("ssh-ed25519").write_private_key(host_key_file)
    before = host_key_file.read_bytes()
    # start with --mimic to test if warning of missing host keys is printed correctly
    s = server("--open-auth", "-vv", "--mimic", "debian", hostkey=host_key_file,
               capture=True)
    ok = pw_login(s.port, "u", "x")
    time.sleep(0.3)
    out = s.console

    lines = [l for l in out.splitlines() if "Host key" in l]
    assert "(1 key)" in out
    assert before == host_key_file.read_bytes()
    assert len(lines) == 1, lines
    assert ok is True
    assert "Host-keys missing" in out and "ssh-rsa" in out
