"""Port-forwarding policy"""
from clients import (forward_flow, reverse_probe, tap_probe, tun_probe,
                     unix_forward_probe, unix_reverse_probe)


# ── local (direct-tcpip) forwarding ───────────────────────────────
def test_forward_carries_data(server):
    """--forward should let a local (direct-tcpip) forward carry data"""
    s = server("--open-auth", "--forward")
    assert forward_flow(s.port) == b"echo:hi"


def test_forward_denied_without_flag(server):
    """Local forwarding should be denied without --forward"""
    s = server("--open-auth")
    r = forward_flow(s.port)
    assert isinstance(r, str) and r.startswith("denied"), repr(r)


# ── reverse (remote) forwarding ───────────────────────────────────
def test_reverse_accepts_remote_listen(server):
    """--reverse should allow a remote (reverse) port listener"""
    s = server("--open-auth", "--reverse")
    assert reverse_probe(s.port) == "accepted"


def test_reverse_denied_without_flag(server):
    """Reverse forwarding should be denied without --reverse"""
    s = server("--open-auth")
    assert reverse_probe(s.port).startswith("denied")


# ── UNIX-domain sockets (always denied) ───────────────────────────
def test_unix_forward_denied_even_with_forward(server):
    """UNIX-domain-socket forwards should always be denied"""
    s = server("--open-auth", "--forward")
    r = unix_forward_probe(s.port)
    assert isinstance(r, str) and r.startswith("denied"), repr(r)


def test_unix_reverse_denied_even_with_reverse(server):
    """UNIX-domain reverse forwarding should always be denied"""
    s = server("--open-auth", "--reverse")
    r = unix_reverse_probe(s.port)
    assert isinstance(r, str) and r.startswith("denied"), repr(r)


# ── layer-2/3 tunnels (always denied) ─────────────────────────────
def test_tun_denied_even_with_tcp_flags(server):
    """Layer-3 TUN tunnels (ssh -w) should always be denied"""
    s = server("--open-auth", "--forward", "--reverse")
    assert tun_probe(s.port).startswith("denied"), tun_probe(s.port)


def test_tap_denied_even_with_tcp_flags(server):
    """Layer-2 TAP tunnels should always be denied"""
    s = server("--open-auth", "--forward", "--reverse")
    assert tap_probe(s.port).startswith("denied"), tap_probe(s.port)
