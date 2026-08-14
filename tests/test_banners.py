"""Version string and pre/post-auth banners"""
import time

import pytest

from clients import collect_banners, server_version


# ── version string ────────────────────────────────────────────────
@pytest.mark.parametrize("flags,expect", [
    ([],                                                  "AsyncSSH"),
    (["--mimic", "none"],                                 "AsyncSSH"),
    (["--mimic", "debian"],                               "OpenSSH_8.4p1 Debian"),
    (["--mimic", "dropbear"],                             "dropbear_2024.86"),
    (["--version-banner", "MyCustomSSH_1.0"],             "MyCustomSSH_1.0"),
    (["--mimic", "dropbear", "--version-banner", "MyCustomSSH_1.0"], "MyCustomSSH_1.0"),
])
def test_version_banner(server, flags, expect):
    """The version banner should track the --mimic preset and --version-banner override"""
    s = server("--open-auth", *flags)
    v = server_version(s.port)
    assert expect in v, v


# ── pre / post-auth banners ───────────────────────────────────────
def test_pre_auth_banner_shown_on_failed_auth(server):
    """--pre-auth-banner should be shown even when auth fails"""
    s = server("-u", "bob:right", "--pre-auth-banner", "LEGAL-NOTICE")
    got = collect_banners(s.port, "bob", "wrong")
    assert any("LEGAL-NOTICE" in m for m in got), got


def test_post_auth_banner_shown_after_auth(server):
    """--post-auth-banner should be shown after a successful auth"""
    s = server("--open-auth", "--post-auth-banner", "WELCOME-IN")
    got = collect_banners(s.port, "u", "x", wait=0.4)
    assert any("WELCOME-IN" in m for m in got), got


# ── startup summary preview ───────────────────────────────────────
def test_startup_banner_preview(server):
    """The startup summary should show a one-line, truncated preview of the banners"""
    long_pre = "Unauthorized access prohibited.\n" + "X" * 80
    s = server("--pre-auth-banner", long_pre, "--post-auth-banner", "Hi there",
               capture=True)
    time.sleep(0.3)
    out = s.console.splitlines()
    pre = next((l for l in out if "Pre-auth" in l), "")
    post = next((l for l in out if "Post-auth" in l), "")
    assert "Unauthorized access prohibited. X" in pre and "…" in pre, pre
    assert "Hi there" in post and "…" not in post, post
