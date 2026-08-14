"""Console/file logging, verbosity tiers and formatting"""
import time

from clients import ANSI, TS, pw_login


# ── formatting (colour, timestamps) ───────────────────────────────
def test_plain_vs_color(server):
    """Console output should carry ANSI colour by default and none with --plain"""
    s_color = server("--open-auth", plain=False, capture=True)
    pw_login(s_color.port, "u", "x")
    time.sleep(0.2)
    assert ANSI.search(s_color.raw)

    s_plain = server("--open-auth", plain=True, capture=True)
    pw_login(s_plain.port, "u", "x")
    time.sleep(0.2)
    assert not ANSI.search(s_plain.raw)


def test_timestamps(server):
    """-t should prefix console log lines with a timestamp"""
    s = server("--open-auth", "-t", capture=True)
    pw_login(s.port, "u", "x")
    time.sleep(0.2)
    assert any(TS.match(l) for l in s.console.splitlines()), s.console[:120]


# ── verbosity tiers ───────────────────────────────────────────────
def _console(server, *flags, log_file=None):
    """Authenticated login that then disconnects and returns the console output"""
    s = server("--open-auth", "--forward", *flags, capture=True, log=log_file)
    pw_login(s.port, "alice", "pw")
    time.sleep(0.4)
    return s


def test_verbosity_default(server):
    """The default tier should show captures and startup but hide version and churn"""
    out = _console(server).console
    assert "Password accepted" in out
    assert "Connection closed" in out
    assert "Host key" in out                       # startup banner
    assert "Client version" not in out             # hidden at default
    assert "Connection opened" not in out          # hidden at default


def test_verbosity_quiet(server):
    """-q should silence the console completely"""
    out = _console(server, "-q").console
    assert "Host key" not in out
    assert "Password accepted" not in out
    assert "Connection closed" not in out
    assert out.strip() == "", repr(out[:80])


def test_verbosity_v(server):
    """-v should add client-version/status lines but not connection churn"""
    out = _console(server, "-v").console
    assert "Client version" in out
    assert "Password accepted" in out
    assert "Connection opened" not in out


def test_verbosity_vv(server):
    """-vv should add connection/SFTP churn"""
    out = _console(server, "-vv").console
    assert "Connection opened" in out


# ── -o log file ───────────────────────────────────────────────────
def test_output_file_is_full_debug(server, tmp_path):
    """The -o file should hold the full DEBUG log even when the console is silent"""
    log_file = tmp_path / "server.log"
    s = _console(server, "-q", log_file=log_file)
    assert s.console.strip() == ""                    # console should be quiet
    log_text = s.log
    assert "Connection opened" in log_text            # DEBUG tier
    assert "Client version" in log_text               # INFO tier
    assert "Connection closed" in log_text            # WARNING tier
