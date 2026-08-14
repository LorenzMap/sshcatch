"""Test basics using the *real* OpenSSH client tools"""
from clients import (cli_keyscan, cli_scp_get, cli_scp_put, cli_scp_pw,
                     cli_sftp, gen_key)

HK_ALGS = {"ssh-ed25519", "ssh-rsa", "ecdsa-sha2-nistp256"}

def _scpdir(tmp_path):
    scp_dir = tmp_path / "scp"
    scp_dir.mkdir(exist_ok=True)
    return scp_dir


# ── password auth via sshpass ─────────────────────────────────────
def test_password_auth(server, tmp_path):
    """A real client should log in with the right password (via sshpass) and be rejected with a wrong one"""
    scp_dir = _scpdir(tmp_path)
    (scp_dir / "probe.txt").write_text("loot")
    s = server("-u", "bob:right", "--scp-download", "--scp-dir", scp_dir)
    rc_ok, _ = cli_scp_pw(s.port, "bob", "right", "probe.txt", tmp_path / "ok")
    rc_bad, out = cli_scp_pw(s.port, "bob", "wrong", "probe.txt", tmp_path / "bad")
    assert rc_ok == 0 and (tmp_path / "ok").read_text() == "loot"
    assert rc_bad != 0 and "Permission denied" in out, out


# ── public-key auth ───────────────────────────────────────────────
def test_key_login(server, tmp_path, client_key):
    """A real client should log in by public key and a wrong key should be rejected"""
    scp_dir = _scpdir(tmp_path)
    authorized_keys_file = tmp_path / "authorized_keys"
    authorized_keys_file.write_text(client_key.with_suffix(".pub").read_text())
    other = gen_key(tmp_path / "other")
    s = server("--authorized-keys", authorized_keys_file, "--scp-download",
               "--scp-dir", scp_dir)
    rc_ok, _ = cli_sftp(s.port, "quit\n", key=client_key)
    rc_bad, out = cli_sftp(s.port, "quit\n", key=other)
    assert rc_ok == 0
    assert rc_bad != 0, out


# ── scp transfers ─────────────────────────────────────────────────
def test_scp_download(server, tmp_path, client_key):
    """Real scp should download a file"""
    scp_dir = _scpdir(tmp_path)
    (scp_dir / "secret.txt").write_text("loot")
    s = server("--open-auth", "--scp-download", "--scp-dir", scp_dir)
    downloaded_file = tmp_path / "downloaded.txt"
    rc = cli_scp_get(s.port, "secret.txt", downloaded_file, key=client_key)
    assert rc == 0 and downloaded_file.read_text() == "loot"


def test_scp_upload(server, tmp_path, client_key):
    """Real scp should upload a file"""
    scp_dir = _scpdir(tmp_path)
    source_file = tmp_path / "upload_source"
    source_file.write_text("payload")
    s = server("--open-auth", "--scp-upload", "--scp-dir", scp_dir)
    rc = cli_scp_put(s.port, source_file, "new.txt", key=client_key)
    assert rc == 0 and (scp_dir / "new.txt").read_text() == "payload"


def test_scp_recursive_roundtrip(server, tmp_path, client_key):
    """Real scp -r should round-trip a directory tree"""
    scp_dir = _scpdir(tmp_path)
    tree = tmp_path / "recursive_tree"
    (tree / "inner").mkdir(parents=True)
    (tree / "a.txt").write_text("A")
    (tree / "inner" / "b.txt").write_text("B")
    base = tree.name
    s = server("--open-auth", "--scp-upload", "--scp-download", "--scp-dir", scp_dir)

    rc_up = cli_scp_put(s.port, tree, ".", key=client_key, recursive=True)
    ua, ub = scp_dir / base / "a.txt", scp_dir / base / "inner" / "b.txt"
    assert rc_up == 0 and ua.read_text() == "A" and ub.read_text() == "B"

    back = tmp_path / "back"
    back.mkdir()
    rc_dn = cli_scp_get(s.port, base, back, key=client_key, recursive=True)
    da, db = back / base / "a.txt", back / base / "inner" / "b.txt"
    assert rc_dn == 0 and da.read_text() == "A" and db.read_text() == "B"


# ── ssh-keyscan sees the served host-key types ────────────────────
def test_keyscan_sees_all_types(server, tmp_path):
    """ssh-keyscan should see all three served host-key types"""
    s = server("--open-auth", hostkey=tmp_path / "host_key")
    assert cli_keyscan(s.port) == HK_ALGS, sorted(cli_keyscan(s.port))

# Hostkeys for --mimic are tested via 'ssh -vvv' in 'test_mimic.py'

# ── raw path traversal (only a real client sends '..' verbatim) ───
def test_path_traversal_chroot(server, tmp_path, client_key):
    """Path traversals must stay inside the chroot"""
    scp_dir = _scpdir(tmp_path)
    (scp_dir / "sub").mkdir()
    (scp_dir / "loot.txt").write_text("loot")
    (scp_dir / "sub" / "x.txt").write_text("y")
    s = server("--open-auth", "--scp-download", "--scp-dir", scp_dir, "-vv", capture=True)

    def sftp_get(name, remote):
        dest = tmp_path / name
        rc, out = cli_sftp(s.port, f"get {remote} {dest}\n", key=client_key)
        return rc, dest, out

    # check 'normal' path usage
    for name, remote, expect in [
        ("parent_traversal", "../loot.txt",     "loot"),   # .. in root is clamped to root
        ("absolute_path",    "/loot.txt",       "loot"),   # absolute path is re-rooted into chroot
        ("internal_updir",   "sub/../loot.txt", "loot"),   # internal .. normalizes back inside
        ("clean_relative",   "sub/x.txt",       "y"),      # ordinary relative path
    ]:
        rc, dest, out = sftp_get(name, remote)
        assert rc == 0, (name, remote, out)
        assert dest.read_text() == expect, (name, remote)

    # check 'malicious' traversals
    for name, remote in [
        ("deep_traversal",   "../../../../etc/passwd"),
        ("absolute_escape",  "/etc/passwd"),
        ("double_slash",     "//etc/passwd"),
        ("triple_slash",     "///etc/passwd"),
    ]:
        rc, dest, out = sftp_get(name, remote)
        assert rc != 0, (name, remote, out)
        assert not dest.exists(), name

    # scp shares the server-side path handling so quick check is enough
    assert cli_scp_get(s.port, "../loot.txt", tmp_path / "scp_in", key=client_key) == 0
    assert (tmp_path / "scp_in").read_text() == "loot"
    assert cli_scp_get(s.port, "/etc/passwd", tmp_path / "scp_escape", key=client_key) != 0
    assert not (tmp_path / "scp_escape").exists()

    out = s.console
    # check if things are logged as expected
    assert "PATH /../loot.txt -> /loot.txt" in out
    assert "PATH /sub/../loot.txt -> /loot.txt" in out
    assert "READ /loot.txt" in out and "READ /sub/x.txt" in out, out[-300:]
    assert "READ /etc/passwd" not in out
