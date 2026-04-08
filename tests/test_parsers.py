"""Unit tests for log line parsers."""

from threat_pipeline.parsers import parse_ssh_line, parse_system_line


def test_parse_ssh_failed_password():
    line = (
        "Jan 15 10:23:45 demo sshd[1234]: Failed password for root from 192.168.1.10 port 22 ssh2"
    )
    p = parse_ssh_line(line)
    assert p.event_subtype == "ssh_failed_password"
    assert p.src_ip == "192.168.1.10"
    assert p.user == "root"


def test_parse_ssh_invalid_user():
    line = "Jan 15 10:23:45 demo sshd[1]: Invalid user ftp from 10.0.0.5 port 1234 ssh2"
    p = parse_ssh_line(line)
    assert p.event_subtype == "ssh_invalid_user"
    assert p.src_ip == "10.0.0.5"
    assert p.user == "ftp"


def test_parse_ssh_accepted():
    line = (
        "Jan 15 10:23:45 demo sshd[1]: Accepted publickey for alice from 203.0.113.1 port 22 ssh2"
    )
    p = parse_ssh_line(line)
    assert p.event_subtype == "ssh_accepted"
    assert p.src_ip == "203.0.113.1"
    assert p.user == "alice"


def test_parse_system_kernel():
    line = "Jan 15 10:00:01 demo kernel: [    0.0] init"
    p = parse_system_line(line)
    assert p.event_subtype == "kernel"
    assert "kernel" in p.message
