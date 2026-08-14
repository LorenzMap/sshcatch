"""Listener modes log-only, --single, -b."""
import asyncio
import time

from clients import connect, login_dropped_by_server, port_open, pw_login, run


# ── log-only (no features enabled) ────────────────────────────────
def test_log_only_accepts_logs_and_closes(server):
    """With no feature flag, a login should be accepted, logged, then closed by the server"""
    s = server("--open-auth", capture=True)
    assert login_dropped_by_server(s.port) is True
    time.sleep(0.3)
    assert "Connection closed" in s.console


# ── --single ──────────────────────────────────────────────────────
def test_single_connection_lifecycle(server):
    """--single should release the port after the first auth and exit once that connection ends"""
    s = server("--open-auth", "--single", "--forward")
    assert port_open(s.port) is True

    async def hold_briefly():
        async with connect(s.port):
            await asyncio.sleep(0.4)
            assert port_open(s.port) is False    # port gone while the connection is held
            assert s.proc.poll() is None         # ... but the process is still alive
    run(hold_briefly())

    time.sleep(1.0)
    assert s.proc.poll() is not None             # exited after the connection closed


# ── -b bind ───────────────────────────────────────────────────────
def test_bind_localhost_reachable(server):
    """-b should bring up a reachable, usable listener"""
    s = server("--open-auth", bind="127.0.0.1")
    assert pw_login(s.port, "u", "x") is True
