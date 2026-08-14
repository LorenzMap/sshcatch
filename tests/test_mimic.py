"""Handshake mimicry"""
import subprocess
import time

import pytest

from clients import PY, REPO, kbdint_login, run_cli

# ── --mimic argparse surface + startup summary ────────────────────
def test_unknown_mimic_rejected():
    """An unknown --mimic preset should be rejected"""
    rc, out = run_cli("--mimic", "notapreset", "-p", "0")
    assert rc != 0 and "invalid choice" in out, out.strip()[-100:]


def test_mimic_off_by_default(server):
    """Mimic should be off unless explicitly requested"""
    s = server("--open-auth", capture=True)
    time.sleep(0.2)
    out = s.console
    assert "Mimic ......... none" in out, \
        next((l for l in out.splitlines() if "Mimic" in l), "")


def test_mimic_preset_case_insensitive(server):
    """--mimic should fold preset names to lower-case (type=str.lower)"""
    s = server("--open-auth", "--mimic", "DROPBEAR", capture=True)
    time.sleep(0.2)
    out = s.console
    assert "Mimic ......... dropbear" in out, \
        next((l for l in out.splitlines() if "Mimic" in l), "")

# warnings on missing hostkeys is tested in 'test_single_key_file' ('test_hostkeys.py')

# ── auth surface under mimic ──────────────────────────────────────
def test_mimic_drops_keyboard_interactive(server):
    """--mimic should drop keyboard-interactive auth that asyncssh would otherwise offer"""
    plain = server("--open-auth")
    assert kbdint_login(plain.port) is True
    disguised = server("--open-auth", "--mimic", "debian")
    assert kbdint_login(disguised.port) is False


# ── handshake mimicry (capture.py vs real-server refs) ────────────
REFS    = REPO / "mimic-refs"
CAPTURE = REFS / "capture.py"

def _capture(*args):
    """Return only the lines capture.py reports as changed"""
    out = subprocess.run([PY, CAPTURE, *args], capture_output=True, text=True).stdout
    return [l for l in out.splitlines()
            if l.startswith(("-", "+")) and not l.startswith(("---", "+++"))]


@pytest.mark.parametrize("preset,ref", [
    ("debian",   "debian11.txt"),
    ("dropbear", "dropbear.txt"),
])
def test_mimic_matches_real_server(server, preset, ref):
    """A preset should reproduce the real server's handshake apart from the host key"""
    s = server("--open-auth", "--mimic", preset)
    changed = _capture("127.0.0.1", str(s.port), "-d", REFS / ref)
    # Differing Host-Key is exactly 2 lines ('+' and '-') in diff
    assert len(changed) == 2 and all("Server host key" in l for l in changed), changed[:4]


def test_mimic_none_is_asyncssh(server):
    """Without a mimic, the handshake should not pass as the real server"""
    s = server("--open-auth", "--mimic", "none")
    changed = _capture("127.0.0.1", str(s.port), "-d", REFS / "debian11.txt")
    assert len(changed) > 10, len(changed)
    assert any("AsyncSSH" in l for l in changed), \
        next((l for l in changed if "software version" in l), "")


@pytest.mark.parametrize("ours,real", [
    ("sshcatch_mimic_debian.txt",   "debian11.txt"),
    ("sshcatch_mimic_dropbear.txt", "dropbear.txt"),
])
def test_committed_refs_current(ours, real):
    """The committed sshcatch traces should still match the reference server"""
    changed = _capture("-d", REFS / real, REFS / ours)
    assert len(changed) == 2 and all("Server host key" in l for l in changed), changed[:4]
