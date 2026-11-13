"""Read-only M1 audit workflow."""

from __future__ import annotations

import threading
import time
from typing import Callable

from .client import AuditError, RateLimitError, Session, polite_pause
from .models import AuditResult, Target, now_text
from .wan import WanParseError, parse_wan_connstr

LogFn = Callable[[str, str], None]


class AuditCancelled(RuntimeError):
    pass


def _noop_log(_level: str, _message: str) -> None:
    return


def format_mac(raw: str) -> str:
    value = (raw or "").replace(":", "").replace("-", "").upper()
    if len(value) == 12:
        return ":".join(value[i : i + 2] for i in range(0, 12, 2))
    return raw or ""


def run_audit(
    target: Target,
    log: LogFn | None = None,
    stop_event: threading.Event | None = None,
) -> AuditResult:
    """Run the M1 read-only audit and return a result object.

    No WAN save, reboot, factory reset, FTP write, or telnet enable is performed.
    """
    log = log or _noop_log
    started = time.monotonic()
    result = AuditResult(target=target.normalized_host(), started_at=now_text())

    def check_stop() -> None:
        if stop_event is not None and stop_event.is_set():
            raise AuditCancelled("用户已停止检测")

    def step(level: str, message: str) -> None:
        check_stop()
        log(level, message)

    try:
        step("STEP", f"连接 {target.origin} …")
        session = Session(target)
        session.login_luci()
        step("OK", f"普通用户 {target.username} 登录成功")

        info = session.get_gwinfo()
        result.model = str(info.get("ProductCls") or info.get("DevType") or "")
        result.serial = str(info.get("ProductSN") or "")
        result.firmware = str(info.get("SWVer") or "")
        result.mac = format_mac(str(info.get("MAC") or ""))
        result.wan_ip = str(info.get("WANIP") or "")
        result.broadband_account = str(info.get("wanAcnt") or "")
        step("OK", f"设备识别：{result.model or '未知型号'}")
        if result.broadband_account:
            step("OK", f"宽带账号：{result.broadband_account}")
        else:
            step("WARN", "网关信息中没有 wanAcnt，可能不是 PPPoE 或页面字段已变化")

        step("STEP", "检测默认超管口令 telecomadmin / nE7jA%5m …")
        ta_ok, _ = session.check_ta_default(target.ta_password)
        result.superadmin_is_default = ta_ok
        if ta_ok:
            result.superadmin_password = target.ta_password
            step("OK", "默认超管口令可用")
            step("STEP", "登录 8080 装维后台并读取 WAN 配置 …")
            polite_pause()
            html = session.login_8080(target.ta_password)
            wan = parse_wan_connstr(html)
            result.broadband_account = wan.account or result.broadband_account
            result.broadband_password = wan.password
            result.wan_service = wan.service
            result.vlan = wan.vlan
            result.mtu = wan.mtu
            result.ifname = wan.ifname
            if wan.password:
                step("OK", f"宽带密码已获取（{len(wan.password)} 位，日志不显示明文）")
            else:
                step("WARN", "WAN 记录存在，但密码字段为空")
                result.notes.append("WAN 记录存在但密码为空，可能不是 PPPoE 或字段已变化")
        else:
            step("WARN", "默认超管口令不可用；M1 不进行口令爆破")
            result.notes.append(
                "默认超管口令不可用。M1 不会爆破；可等待 M2/M3 的配置提取/RCE 后端。"
            )

        if not result.broadband_account:
            raise AuditError("未能获取宽带账号")
        if not result.broadband_password:
            result.notes.append("宽带密码未获取，报告只包含账号和元数据")

    except AuditCancelled:
        result.error = "已停止"
        step("WARN", "检测已停止")
    except RateLimitError as exc:
        result.error = str(exc)
        step("ERROR", str(exc))
        result.notes.append("8080 锁定是临时的；请等待 60 秒后重新运行")
    except (AuditError, WanParseError) as exc:
        result.error = str(exc)
        step("ERROR", str(exc))
    except Exception as exc:  # noqa: BLE001 - GUI must never crash on a router reply
        result.error = f"未预期错误：{exc}"
        step("ERROR", result.error)
    finally:
        result.elapsed = time.monotonic() - started
        result.finished_at = now_text()
        # Do not call step() here: a stop request would raise a second time.
        log("INFO", f"本次检测耗时 {result.elapsed:.2f}s")
    return result
