"""Authentication policy and credential capture"""
import time

import asyncssh
import pytest

from clients import gen_key, key_login, pw_login


# ── auth policy (which credentials are accepted) ──────────────────
def test_default_reject_all(server, client_key):
    """Without an auth flag, every password and key should be denied"""
    s = server()
    assert pw_login(s.port, "x", "y") is False
    assert key_login(s.port, client_key) is False


def test_open_auth_accepts_any_credentials(server, client_key):
    """--open-auth should accept any password and any public key"""
    s = server("--open-auth")
    assert pw_login(s.port, "anyone", "whatever") is True
    assert key_login(s.port, client_key) is True


@pytest.mark.parametrize("user,pw,expect", [
    ("bob", "s3cret", True),    # correct pair
    ("bob", "nope",   False),   # wrong password
    ("eve", "s3cret", False),   # wrong username
])
def test_user_pass(server, user, pw, expect):
    """-u USER:PASS should accept the exact pair and reject a wrong user or password"""
    s = server("-u", "bob:s3cret")
    assert pw_login(s.port, user, pw) is expect


def test_authorized_keys_gates_by_key(server, client_key, tmp_path):
    """--authorized-keys should accept a listed key and reject an unlisted one"""
    authorized_keys_file = tmp_path / "authorized_keys"
    authorized_keys_file.write_text(client_key.with_suffix(".pub").read_text())
    other = gen_key(tmp_path / "other")
    s = server("--authorized-keys", authorized_keys_file)
    assert key_login(s.port, client_key) is True
    assert key_login(s.port, other) is False


# ── authorized_keys parsing & summary ─────────────────────────────
def test_authorized_keys_parsing(server, client_key, tmp_path):
    """Only 'keytype base64' lines should load; option/garbage lines should be refused"""
    authorized_keys_file = tmp_path / "authorized_keys"
    pubkey_fields = client_key.with_suffix(".pub").read_text().split()
    key = f"{pubkey_fields[0]} {pubkey_fields[1]}"
    authorized_keys_file.write_text(
        "# a comment line\n\n"
        f"{key} NT SYSTEM\n"                       # line 3 - loads
        f'from="10.0.0.1" {key} admin@box\n'       # line 4 - refused
        f'command="echo hi there",no-pty {key}\n'  # line 5 - refused
        "ssh-ed25519 NOT-BASE64-AT-ALL broken\n"   # line 6 - refused
        "garbage\n")                               # line 7 - refused
    s = server("--authorized-keys", authorized_keys_file, "-vv", capture=True)
    ok = key_login(s.port, client_key)
    time.sleep(0.3)
    out = s.console
    loaded  = [l for l in out.splitlines() if "Loaded key" in l]
    refused = [l for l in out.splitlines() if "Invalid key" in l]

    assert len(loaded) == 1 and "line=3" in loaded[0], loaded
    assert ok is True                                        # the valid key works
    assert len(refused) == 4, refused
    assert all("Must start with 'keytype base64'" in l for l in refused), refused
    assert "restricted (1 key)" in out                       # summary counts 1


def test_auth_summary(server, tmp_path):
    """The Auth line should count allowed users and *valid* keys (invalid ignored)"""
    authorized_keys_file = tmp_path / "authorized_keys"
    keys = [asyncssh.generate_private_key("ssh-ed25519").export_public_key()
            .decode().strip() for _ in range(2)]
    authorized_keys_file.write_text("\n".join(keys + ["not-a-valid-key"]) + "\n")
    s = server("-u", "a:pw", "-u", "b:pw", "--authorized-keys", authorized_keys_file,
               capture=True)
    time.sleep(0.3)
    auth = next((l for l in s.console.splitlines() if "Auth" in l), "")
    assert "restricted (2 users, 2 keys)" in auth, auth


# ── credential capture (what auth attempts get logged) ────────────
def test_full_public_key_logging(server, client_key):
    """The full public key should be captured on the console at -vv (hidden by default)"""
    s = server("--open-auth", capture=True)
    key_login(s.port, client_key)
    time.sleep(0.3)
    assert "ssh-ed25519 AAAA" not in s.console

    s2 = server("--open-auth", "-vv", capture=True)
    key_login(s2.port, client_key)
    time.sleep(0.3)
    assert "ssh-ed25519 AAAA" in s2.console


def test_rejected_key_is_captured(server, tmp_path, client_key):
    """A key that fails auth should still be captured: fingerprint and full key logged"""
    # only some *other* key is allowed, so client_key is offered and rejected
    allowed = gen_key(tmp_path / "allowed")
    authorized_keys_file = tmp_path / "authorized_keys"
    authorized_keys_file.write_text(allowed.with_suffix(".pub").read_text())
    s = server("--authorized-keys", authorized_keys_file, "-vv", capture=True)
    assert key_login(s.port, client_key) is False
    time.sleep(0.3)
    out = s.console
    assert "Key rejected:" in out
    assert "ssh-ed25519 AAAA" in out


def test_password_capture(server):
    """Accepted and rejected passwords should be captured with their username"""
    s = server("-u", "bob:pw", capture=True)
    pw_login(s.port, "bob", "pw")
    pw_login(s.port, "bob", "BADPW")
    time.sleep(0.3)
    out = s.console
    assert "Password accepted: pw" in out and "Password rejected: BADPW" in out, out[-120:]
    accepted = next(l for l in out.splitlines() if "Password accepted" in l)
    assert "[bob]" in accepted, accepted
