"""Parse the 8080 NN_WAN.html page.

The page embeds a JavaScript variable named ``WanConnStr``.  Each connection is
separated by ``}`` and its fields by ``|``.  For the INTERNET PPPoE record the
account is field 9 and the password is field 10, base64 encoded by the web UI.
"""

from __future__ import annotations

import base64
import re
import urllib.parse

from .models import WanInfo

WAN_RE = re.compile(r'var\s+WanConnStr\s*=\s*"([^"]*)"', re.S)
WAN_RE_SINGLE = re.compile(r"var\s+WanConnStr\s*=\s*'([^']*)'", re.S)


class WanParseError(ValueError):
    """Raised when the WAN page does not contain a usable connection."""


def decode_password(value: str) -> str:
    """Decode the base64 value used by the ``WanPassword_text`` field."""
    raw = (value or "").strip()
    if not raw:
        return ""
    # Some firmware variants URL-encode the base64 before emitting it.
    if "%" in raw:
        raw = urllib.parse.unquote(raw)
    raw = raw.replace(" ", "+")
    padded = raw + "=" * (-len(raw) % 4)
    try:
        data = base64.b64decode(padded, validate=False)
    except Exception as exc:  # noqa: BLE001 - report a stable message
        raise WanParseError(f"宽带密码不是有效的 Base64: {exc}") from exc
    for encoding in ("utf-8", "gb18030", "latin-1"):
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            continue
    return data.decode("latin-1", errors="replace")


def _fields(record: str) -> list[str]:
    return [part.strip() for part in record.split("|")]


def parse_wan_connstr(html: str) -> WanInfo:
    """Return the INTERNET WAN record from a NN_WAN.html document."""
    if not html:
        raise WanParseError("页面为空")
    match = WAN_RE.search(html) or WAN_RE_SINGLE.search(html)
    if not match:
        raise WanParseError("未找到 WanConnStr（可能未登录或页面结构已变化）")

    records = [r for r in match.group(1).split("}") if r.strip()]
    candidates: list[list[str]] = []
    for record in records:
        fields = _fields(record)
        if len(fields) < 11:
            continue
        name = fields[0].upper()
        if "INTERNET" in name:
            candidates.append(fields)

    if not candidates:
        # Fall back to any record that looks like an account-bearing PPPoE row.
        for record in records:
            fields = _fields(record)
            if len(fields) >= 11 and "@" in fields[9]:
                candidates.append(fields)

    if not candidates:
        raise WanParseError("WanConnStr 中没有 INTERNET 连接")

    # Prefer a row with a non-empty account; that is the PPPoE row.
    fields = next((f for f in candidates if f[9]), candidates[0])
    account = fields[9]
    password = decode_password(fields[10]) if len(fields) > 10 else ""
    return WanInfo(
        service=fields[0],
        account=account,
        password=password,
        vlan=fields[6] if len(fields) > 6 else "",
        mtu=fields[8] if len(fields) > 8 else "",
        ifname=fields[14] if len(fields) > 14 else "",
    )
