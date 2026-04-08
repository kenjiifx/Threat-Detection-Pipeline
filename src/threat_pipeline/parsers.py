"""Parse syslog and OpenSSH auth.log lines into structured fields."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from dataclasses import dataclass

_SYSLOG_PREFIX = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<rest>.+)$"
)

# OpenSSH (typical Debian/Ubuntu auth.log)
_RE_FAILED_PASSWORD = re.compile(
    r"sshd\[\d+\]:\s+Failed password for(?: invalid user)?\s+(?P<user>\S+)\s+from\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+port\s+\d+",
    re.IGNORECASE,
)
_RE_INVALID_USER = re.compile(
    r"sshd\[\d+\]:\s+Invalid user\s+(?P<user>\S+)\s+from\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+port\s+\d+",
    re.IGNORECASE,
)
_RE_ACCEPTED = re.compile(
    r"sshd\[\d+\]:\s+Accepted\s+(?:publickey|password|keyboard-interactive)\s+for\s+(?P<user>\S+)\s+from\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+port\s+\d+",
    re.IGNORECASE,
)


def _parse_syslog_timestamp(ts: str) -> datetime | None:
    """Parse 'Jan 15 10:23:45' using current year (auth.log style)."""
    now = datetime.now(timezone.utc)
    for fmt in ("%b %d %H:%M:%S",):
        try:
            dt = datetime.strptime(f"{ts} {now.year}", f"{fmt} %Y")
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


@dataclass(frozen=True)
class ParsedLine:
    event_time: datetime | None
    hostname: str | None
    message: str
    src_ip: str | None
    user: str | None
    event_subtype: str | None
    severity: str | None


def parse_ssh_line(line: str) -> ParsedLine:
    line = line.strip()
    if not line:
        return ParsedLine(None, None, line, None, None, None, None)

    m = _SYSLOG_PREFIX.match(line)
    event_time: datetime | None = None
    hostname: str | None = None
    body = line
    if m:
        event_time = _parse_syslog_timestamp(m.group("ts"))
        hostname = m.group("host")
        body = m.group("rest")

    src_ip = None
    user = None
    subtype: str | None = None

    fm = _RE_FAILED_PASSWORD.search(body)
    if fm:
        user = fm.group("user")
        src_ip = fm.group("ip")
        subtype = "ssh_failed_password"
    else:
        im = _RE_INVALID_USER.search(body)
        if im:
            user = im.group("user")
            src_ip = im.group("ip")
            subtype = "ssh_invalid_user"
        else:
            am = _RE_ACCEPTED.search(body)
            if am:
                user = am.group("user")
                src_ip = am.group("ip")
                subtype = "ssh_accepted"

    if subtype is None and "sshd" in body.lower():
        subtype = "ssh_other"

    return ParsedLine(
        event_time=event_time,
        hostname=hostname,
        message=line,
        src_ip=src_ip,
        user=user,
        event_subtype=subtype,
        severity=None,
    )


def parse_system_line(line: str) -> ParsedLine:
    """Generic syslog line for non-SSH system logs."""
    line = line.strip()
    if not line:
        return ParsedLine(None, None, line, None, None, None, None)

    m = _SYSLOG_PREFIX.match(line)
    event_time: datetime | None = None
    hostname: str | None = None
    body = line
    if m:
        event_time = _parse_syslog_timestamp(m.group("ts"))
        hostname = m.group("host")
        body = m.group("rest")

    subtype = "kernel" if body.lower().startswith("kernel") else "other"
    return ParsedLine(
        event_time=event_time,
        hostname=hostname,
        message=line,
        src_ip=None,
        user=None,
        event_subtype=subtype,
        severity=None,
    )
