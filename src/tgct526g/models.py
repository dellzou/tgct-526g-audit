"""Data models shared by the CLI and the desktop UI."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any


def now_text() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def mask_secret(value: str, keep: int = 1) -> str:
    if not value:
        return ""
    if len(value) <= keep:
        return "*" * len(value)
    return value[:keep] + "*" * (len(value) - keep)


@dataclass
class Target:
    """A single router under test."""

    host: str = "192.168.1.1"
    username: str = "useradmin"
    password: str = "ni7tk"
    ta_password: str = "nE7jA%5m"
    timeout: float = 8.0

    def normalized_host(self) -> str:
        host = self.host.strip()
        if host.lower().startswith("http://"):
            host = host[7:]
        elif host.lower().startswith("https://"):
            host = host[8:]
        host = host.rstrip("/")
        if host.endswith(":80"):
            host = host[:-3]
        return host

    @property
    def origin(self) -> str:
        return "http://" + self.normalized_host()

    def with_port(self, port: int) -> "Target":
        host = self.normalized_host()
        if ":" in host:
            host = host.rsplit(":", 1)[0]
        return Target(
            host=f"{host}:{port}",
            username=self.username,
            password=self.password,
            ta_password=self.ta_password,
            timeout=self.timeout,
        )


@dataclass
class WanInfo:
    service: str = ""
    account: str = ""
    password: str = ""
    vlan: str = ""
    mtu: str = ""
    ifname: str = ""


@dataclass
class AuditResult:
    target: str = ""
    model: str = ""
    serial: str = ""
    firmware: str = ""
    mac: str = ""
    wan_ip: str = ""
    broadband_account: str = ""
    broadband_password: str = ""
    superadmin_user: str = "telecomadmin"
    superadmin_password: str = ""
    superadmin_is_default: bool = False
    wan_service: str = ""
    vlan: str = ""
    mtu: str = ""
    ifname: str = ""
    elapsed: float = 0.0
    started_at: str = field(default_factory=now_text)
    finished_at: str = ""
    error: str = ""
    notes: list[str] = field(default_factory=list)

    def to_dict(self, redact: bool = False) -> dict[str, Any]:
        data = asdict(self)
        if redact:
            data["broadband_password"] = mask_secret(self.broadband_password, 1)
            data["superadmin_password"] = mask_secret(self.superadmin_password, 1)
        return data

    def summary_text(self, redact: bool = False) -> str:
        def value(text: str) -> str:
            return text if text else "—"

        account = value(self.broadband_account)
        password = value(self.broadband_password)
        if redact:
            password = mask_secret(password, 1)
        ta = "可用（默认口令）" if self.superadmin_is_default else ("不可用" if self.superadmin_password == "" else "可用")
        lines = [
            "TGCT-526G 宽带账号及超密获取结果",
            "=" * 32,
            f"目标        : {value(self.target)}",
            f"设备型号    : {value(self.model)}",
            f"序列号      : {value(self.serial)}",
            f"固件版本    : {value(self.firmware)}",
            f"MAC         : {value(self.mac)}",
            f"WAN IP      : {value(self.wan_ip)}",
            f"宽带账号    : {account}",
            f"宽带密码    : {password}",
            f"连接名称    : {value(self.wan_service)}",
            f"VLAN / MTU  : {value(self.vlan)} / {value(self.mtu)}",
            f"接口        : {value(self.ifname)}",
            f"超管检测    : {ta}",
            f"超管账号    : {self.superadmin_user}",
            f"超管口令    : {mask_secret(self.superadmin_password, 1) if redact else value(self.superadmin_password)}",
            f"耗时        : {self.elapsed:.2f}s",
            f"时间        : {self.started_at}",
        ]
        if self.error:
            lines.append(f"错误        : {self.error}")
        if self.notes:
            lines.append("备注        :")
            lines.extend(f"  - {n}" for n in self.notes)
        return "\n".join(lines)
