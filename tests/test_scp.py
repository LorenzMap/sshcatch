"""SCP/SFTP file-op policy, driven by the asyncssh SFTP client"""
import os
import time

import asyncssh
import pytest

from clients import sftp_call, sftp_ok


def _scpdir(tmp_path):
    scp_dir = tmp_path / "scp"
    scp_dir.mkdir(exist_ok=True)
    return scp_dir


# ── transfer direction (upload / download gating) ─────────────────
def test_scp_download_allows_get_blocks_put(server, tmp_path):
    """--scp-download should allow downloads and block uploads"""
    scp_dir = _scpdir(tmp_path)
    (scp_dir / "secret.txt").write_text("loot")
    s = server("--open-auth", "--scp-download", "--scp-dir", scp_dir)
    downloaded_file = tmp_path / "downloaded.txt"

    assert sftp_ok(s.port, lambda f: f.get("secret.txt", downloaded_file))
    assert downloaded_file.read_text() == "loot"
    (tmp_path / "up.txt").write_text("x")
    assert not sftp_ok(s.port, lambda f: f.put(tmp_path / "up.txt", "up.txt"))
    assert not (scp_dir / "up.txt").exists()


def test_scp_upload_allows_put_blocks_get(server, tmp_path):
    """--scp-upload should allow uploads and block downloads"""
    scp_dir = _scpdir(tmp_path)
    (scp_dir / "exists.txt").write_text("original")
    s = server("--open-auth", "--scp-upload", "--scp-dir", scp_dir)
    (tmp_path / "upload_payload").write_text("payload")

    assert sftp_ok(s.port, lambda f: f.put(tmp_path / "upload_payload", "new.txt"))
    assert (scp_dir / "new.txt").exists()
    # overwrite attempt -> stored with a suffix, original left intact
    (tmp_path / "overwrite_attempt").write_text("attacker")
    sftp_ok(s.port, lambda f: f.put(tmp_path / "overwrite_attempt", "exists.txt"))
    assert (scp_dir / "exists.txt").read_text() == "original"
    assert (scp_dir / "exists_1.txt").exists()
    # download must be blocked
    assert not sftp_ok(s.port, lambda f: f.get("exists.txt", tmp_path / "blocked_download"))


def test_sftp_denied_when_transfer_disabled(server, tmp_path):
    """With no --scp-* flag, the SFTP subsystem should refuse to open and log DENIED SFTP"""
    s = server("--open-auth", capture=True)
    assert not sftp_ok(s.port, lambda f: f.listdir("."))
    time.sleep(0.3)
    assert "DENIED SFTP" in s.console


# ── chroot protection (host key, symlinks) ────────────────────────
def test_protected_files_hidden(server, tmp_path, client_key):
    """Sensitive sshcatch files in the scp dir (host key, authorized_keys, -o log) should be
    hidden, undownloadable, and leak no metadata"""
    # upload protection does not need a test because of overwrite protection
    scp_dir = _scpdir(tmp_path)
    host_key_file = scp_dir / "hostkey"
    authorized_keys_file = scp_dir / "authorized_keys"
    authorized_keys_file.write_text(client_key.with_suffix(".pub").read_text())
    log_file = scp_dir / "run.log"
    (scp_dir / "normal.txt").write_text("ok")
    s = server("--open-auth", "--authorized-keys", authorized_keys_file,
               "--scp-download", "--scp-dir", scp_dir, "-vv",
               hostkey=host_key_file, log=log_file, capture=True)

    names = sftp_call(s.port, lambda f: f.listdir("."))
    assert "normal.txt" in names, names                             # ordinary file is visible
    for hidden in ("hostkey", "authorized_keys", "run.log"):
        assert hidden not in names, names                           # not listed
        assert not sftp_ok(s.port, lambda f: f.get(hidden, tmp_path / f"stolen_{hidden}"))
        assert not sftp_ok(s.port, lambda f: f.stat(hidden))        # no metadata either
    assert "DENIED PROTECTED" in s.console


def test_symlink_download(server, tmp_path):
    """On download, symlinks should be hidden and denied while real files still work"""
    scp_dir = _scpdir(tmp_path)
    (scp_dir / "real.txt").write_text("loot")
    (scp_dir / "link.txt").symlink_to("real.txt")            # in-tree symbolic link (ln -s)
    (scp_dir / "escape.txt").symlink_to("/etc/passwd")       # symbolic link pointing outside chroot
    s = server("--open-auth", "--scp-download", "--scp-dir", scp_dir, "-vv", capture=True)

    names = sftp_call(s.port, lambda f: f.listdir("."))
    assert "link.txt" not in names and "escape.txt" not in names, names
    assert "real.txt" in names
    assert not sftp_ok(s.port, lambda f: f.get("link.txt", tmp_path / "link_download"))
    assert sftp_ok(s.port, lambda f: f.get("real.txt", tmp_path / "real_download"))
    assert "DENIED SYMLINK" in s.console and "SKIP symlink" in s.console


def test_symlink_upload(server, tmp_path):
    """On upload, a symlink should be stored as a placeholder, never a real link"""
    scp_dir = _scpdir(tmp_path)
    s = server("--open-auth", "--scp-upload", "--scp-dir", scp_dir, "-vv", capture=True)

    sftp_call(s.port, lambda f: f.symlink("/etc/passwd", "mylink"))
    placeholder_file = scp_dir / "mylink"
    assert placeholder_file.exists() and not placeholder_file.is_symlink()
    assert "symlink -> /etc/passwd" in placeholder_file.read_text()
    assert "SYMLINK /mylink -> /etc/passwd (placeholder)" in s.console


# ── path & destructive-op handling ────────────────────────────────
def test_upload_parents(server, tmp_path):
    """Uploading into a non-existent nested path should auto-create the parents"""
    scp_dir = _scpdir(tmp_path)
    source_file = tmp_path / "payload"
    source_file.write_text("payload")
    s = server("--open-auth", "--scp-upload", "--scp-dir", scp_dir, "-vv", capture=True)
    assert sftp_ok(s.port, lambda f: f.put(source_file, "deep/nested/f.txt"))
    dst = scp_dir / "deep" / "nested" / "f.txt"
    assert dst.exists() and dst.read_text() == "payload"
    assert "MKPARENT /deep/nested/f.txt" in s.console


def test_destructive_denied(server, tmp_path):
    """A denied delete / rename / rmdir attempt should leave the data untouched"""
    scp_dir = _scpdir(tmp_path)
    (scp_dir / "keep.txt").write_text("keep")
    (scp_dir / "adir").mkdir()
    s = server("--open-auth", "--scp-upload", "--scp-download", "--scp-dir",
               scp_dir, "-vv")

    assert not sftp_ok(s.port, lambda f: f.remove("keep.txt"))
    assert not sftp_ok(s.port, lambda f: f.rename("keep.txt", "moved.txt"))
    assert not sftp_ok(s.port, lambda f: f.rmdir("adir"))
    assert (scp_dir / "keep.txt").read_text() == "keep"   # data survives the attempt
    assert not (scp_dir / "moved.txt").exists()
    assert (scp_dir / "adir").is_dir()


# ── denied SFTP ops (per-op refusal) ──────────────────────────────
# Server-mode presets: only the op under test should be the reason for the deny.
BOTH = ("--scp-upload", "--scp-download")
DOWNLOAD = ("--scp-download",)
UPLOAD = ("--scp-upload",)
_ATTRS = asyncssh.SFTPAttrs(permissions=0o600)


async def _on_handle(f, method, *args):
    """Open probe.txt for read and run an op on the file handle (fsync/lock/setstat...)"""
    async with f.open("probe.txt", "r") as fh:
        await getattr(fh, method)(*args)


# (server method name, server flags, client action, expected DENIED tag)
DENY_OPS = [
    # always denied, regardless of mode
    ("remove",       BOTH,     lambda f: f.remove("probe.txt"),                "DELETE /probe.txt"),
    ("rename",       BOTH,     lambda f: f.rename("probe.txt", "x"),           "RENAME /probe.txt"),
    ("rmdir",        BOTH,     lambda f: f.rmdir("d"),                         "RMDIR /d"),
    ("link",         BOTH,     lambda f: f.link("probe.txt", "x"),             "LINK /probe.txt"),
    ("readlink",     BOTH,     lambda f: f.readlink("probe.txt"),              "READLINK /probe.txt"),
    ("posix_rename", BOTH,     lambda f: f.posix_rename("probe.txt", "x"),     "POSIX_RENAME /probe.txt"),
    ("statvfs",      BOTH,     lambda f: f.statvfs("."),                       "STATVFS /"),
    ("fstatvfs",     BOTH,     lambda f: _on_handle(f, "statvfs"),             "FSTATVFS"),
    ("fsync",        BOTH,     lambda f: _on_handle(f, "fsync"),               "FSYNC"),
    # write/metadata ops - refused when upload is off
    ("mkdir",        DOWNLOAD, lambda f: f.mkdir("d"),                         "MKDIR /d"),
    ("symlink",      DOWNLOAD, lambda f: f.symlink("/etc/passwd", "l"),        "SYMLINK /l"),
    ("setstat",      DOWNLOAD, lambda f: f.setstat("probe.txt", _ATTRS),       "SETSTAT /probe.txt"),
    ("fsetstat",     DOWNLOAD, lambda f: _on_handle(f, "setstat", _ATTRS),     "FSETSTAT"),
    # listing - refused when download is off
    ("scandir",      UPLOAD,   lambda f: f.listdir("."),                       "LISTDIR /"),
]

@pytest.mark.parametrize("method,flags,action,tag", DENY_OPS, ids=[o[0] for o in DENY_OPS])
def test_denied_sftp_op(server, tmp_path, method, flags, action, tag):
    """Each disallowed SFTP op should be refused and logged with its DENIED tag"""
    scp_dir = _scpdir(tmp_path)
    (scp_dir / "probe.txt").write_text("x")
    s = server("--open-auth", *flags, "--scp-dir", scp_dir, "-vv", capture=True)
    assert not sftp_ok(s.port, action)
    time.sleep(0.3)
    assert f"DENIED {tag}" in s.console, s.console[-200:]


# ── error reporting (NOTFOUND / permission) ───────────────────────
def test_notfound_deduped(server, tmp_path):
    """A missing-file request should log NOTFOUND once, deduped even when repeated in a session"""
    scp_dir = _scpdir(tmp_path)
    s = server("--open-auth", "--scp-download", "--scp-dir", scp_dir, capture=True)

    async def get_missing_repeatedly(f):
        for _ in range(3):                                # same op, same session, within 1s
            try:
                await f.get("missing.txt", tmp_path / "download_target")
            except Exception:
                pass
    sftp_call(s.port, get_missing_repeatedly)
    time.sleep(0.3)
    out = s.console                                       # NOTFOUND is WARNING -> default tier
    assert "NOTFOUND /missing.txt" in out
    assert out.count("NOTFOUND /missing.txt") == 1, out.count("NOTFOUND /missing.txt")


@pytest.mark.skipif(os.geteuid() == 0, reason="root bypasses file permissions")
def test_unreadable_file_reports_error(server, tmp_path):
    """A download of a server-side file with no read permission should fail and log ERROR"""
    scp_dir = _scpdir(tmp_path)
    secret = scp_dir / "secret.txt"
    secret.write_text("top")
    secret.chmod(0o000)
    s = server("--open-auth", "--scp-download", "--scp-dir", scp_dir, "-vv", capture=True)
    try:
        assert not sftp_ok(s.port, lambda f: f.get("secret.txt", tmp_path / "stolen"))
    finally:
        secret.chmod(0o600)    # let tmp_path cleanup remove it
    time.sleep(0.3)
    assert "ERROR /secret.txt (Permission denied)" in s.console