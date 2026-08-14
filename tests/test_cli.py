"""argparse stuff --version/-h/--help and input validation"""
import re

from clients import SRC, run_cli


def test_version_and_help():
    """--version, -h and --help should exit 0; -h is short, --help is full"""
    version = re.search(r'__version__ = "(.+?)"', SRC.read_text()).group(1)
    rc, out = run_cli("--version")
    assert rc == 0 and version in out, out
    rc_short, short = run_cli("-h")
    rc_full, full = run_cli("--help")
    assert rc_short == 0 and "for the full help!" in short
    assert rc_full == 0 and "examples:" in full
    assert len(full.splitlines()) > len(short.splitlines()), "full help should be longer than -h"


def test_validation_errors(tmp_path):
    """Bad user format and missing paths should be rejected with clear errors"""
    rc, out = run_cli("--user", "noColonHere", "-p", "0")
    assert rc != 0 and "USER:PASS" in out, out.strip()[-100:]
    rc, out = run_cli("--scp-download", "--scp-dir", tmp_path / "missing_scp_dir", "-p", "0")
    assert rc != 0 and "does not exist" in out, out.strip()[-100:]
    rc, out = run_cli("--authorized-keys", tmp_path / "missing_authorized_keys", "-p", "0")
    assert rc != 0 and "not found" in out, out.strip()[-100:]
    rc, out = run_cli("-o", tmp_path / "no_such_dir" / "output.log", "-p", "0")
    assert rc != 0 and "Log directory" in out, out.strip()[-100:]
    rc, out = run_cli("-p", "notanumber")
    assert rc != 0 and "invalid int value" in out, out.strip()[-100:]

# --mimic argparse arguments in 'test_mimic.py'