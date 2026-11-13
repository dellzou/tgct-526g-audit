"""Read-only credential audit workflow."""

from __future__ import annotations

import threading
import time
from typing import Callable

from .client import AuditError, RateLimitError, Session, check_tcp, polite_pause
from .models import AuditResult, Target, now_text
from .wan import WanParseError, parse_wan_connstr

LogFn = Callable[[str, str], None]
ProgressFn = Callable[[str, str, str], None]

CHECK_KEYS = ("login", "device", "account", "ta", "wan")
DEFAULT_TA = "nE7jA%5m"


class AuditCancelled(RuntimeError):
    pass


def _noop_log(_level: str, _message: str) -> None:
    return


def _noop_progress(_key: str, _status: str, _message: str) -> None:
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
    progress: ProgressFn | None = None,
) -> AuditResult:
    """Run the M1 read-only audit and return a result object.

    No WAN save, reboot, factory reset, FTP write, or telnet enable is performed.
    """
    log = log or _noop_log
    progress = progress or _noop_progress
    started = time.monotonic()
    result = AuditResult(
        target=target.normalized_host(),
        admin_port=target.admin_port,
        started_at=now_text(),
    )
    active_key = "login"

    def check_stop() -> None:
        if stop_event is not None and stop_event.is_set():
            raise AuditCancelled("用户已停止检测")

    def step(level: str, message: str) -> None:
        check_stop()
        log(level, message)

    def set_check(key: str, status: str, message: str) -> None:
        result.checks[key] = {"status": status, "message": message}
        try:
            progress(key, status, message)
        except Exception:
            pass

    try:
        for key in CHECK_KEYS:
            set_check(key, "wait", "等待")

        step("STEP", f"连接 {target.origin} …")
        if not check_tcp(target.normalized_host(), target.port):
            raise AuditError(
                f"{target.port} 端口不可达。请确认电脑连着该路由器的 LAN/WiFi，"
                "管理地址没有填错，80 端口没有被关闭。"
            )
        step("OK", f"{target.port} 端口可达")
        if not check_tcp(target.normalized_host(), target.admin_port):
            step("WARN", f"{target.admin_port} 端口不可达；超管/WAN 密码步骤可能失败")
            result.notes.append(f"{target.admin_port} 端口不可达，装维后台可能已关闭。")

        active_key = "login"
        set_check("login", "run", "登录中")
        session = Session(target)
        session.login_luci()
        set_check("login", "ok", f"{target.username} 登录成功")
        step("OK", f"普通用户 {target.username} 登录成功")

        active_key = "device"
        set_check("device", "run", "读取中")
        info = session.get_gwinfo()
        result.model = str(info.get("ProductCls") or info.get("DevType") or "")
        result.serial = str(info.get("ProductSN") or "")
        result.firmware = str(info.get("SWVer") or "")
        result.mac = format_mac(str(info.get("MAC") or ""))
        result.wan_ip = str(info.get("WANIP") or "")
        result.broadband_account = str(info.get("wanAcnt") or "")
        set_check("device", "ok", result.model or "已识别")
        step("OK", f"设备识别：{result.model or '未知型号'}")

        active_key = "account"
        if result.broadband_account:
            set_check("account", "ok", result.broadband_account)
            step("OK", f"宽带账号：{result.broadband_account}")
        else:
            set_check("account", "warn", "未找到 wanAcnt")
            step("WARN", "网关信息中没有 wanAcnt，可能不是 PPPoE 或页面字段已变化")

        active_key = "ta"
        set_check("ta", "run", "检测中")
        label = "默认超管口令" if target.ta_password == DEFAULT_TA else "自定义超管口令"
        step("STEP", f"检测{label}（telecomadmin）…")
        ta_ok, ta_body = session.check_ta_default(target.ta_password)
        result.superadmin_is_default = bool(ta_ok and target.ta_password == DEFAULT_TA)
        if ta_ok:
            result.superadmin_password = target.ta_password
            status = "默认口令可用" if result.superadmin_is_default else "自定义口令可用"
            set_check("ta", "ok", status)
            step("OK", f"{status}，继续读取 WAN 配置")
            active_key = "wan"
            set_check("wan", "run", "读取中")
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
                set_check("wan", "ok", f"密码 {len(wan.password)} 位")
                step("OK", f"宽带密码已获取（{len(wan.password)} 位，日志不显示明文）")
            else:
                set_check("wan", "warn", "密码为空")
                step("WARN", "WAN 记录存在，但密码字段为空")
                result.notes.append("WAN 记录存在但密码为空，可能不是 PPPoE 或字段已变化")
        else:
            set_check("ta", "warn", "超管口令不可用")
            set_check("wan", "skip", "跳过：需要超管口令")
            step("WARN", "超管口令不可用；M1 不进行口令爆破")
            if "禁止登录" in ta_body or "超过三次" in ta_body:
                result.notes.append("主登录被临时限制，请等待约 60 秒再试。")
            result.notes.append(
                "超管口令不可用。M1 不会爆破；可等待 M2 的配置提取/RCE 恢复后端。"
            )

        if not result.broadband_account:
            raise AuditError("未能获取宽带账号。请确认设备是 PPPoE 上网，或把日志反馈给维护者。")
        if not result.broadband_password:
            result.notes.append("宽带密码未获取，报告只包含账号和元数据")

    except AuditCancelled:
        result.error = "已停止"
        set_check(active_key, "warn", "已停止")
        step("WARN", "检测已停止")
    except RateLimitError as exc:
        result.error = str(exc)
        set_check(active_key, "err", "被临时锁定")
        step("ERROR", str(exc))
        result.notes.append("8080 锁定是临时的；请等待 60 秒后重新运行")
    except (AuditError, WanParseError) as exc:
        result.error = str(exc)
        set_check(active_key, "err", str(exc)[:40])
        step("ERROR", str(exc))
    except Exception as exc:  # noqa: BLE001 - GUI must never crash on a router reply
        result.error = f"未预期错误：{exc}"
        set_check(active_key, "err", "未预期错误")
        step("ERROR", result.error)
    finally:
        result.elapsed = time.monotonic() - started
        result.finished_at = now_text()
        # Do not call step() here: a stop request would raise a second time.
        log("INFO", f"本次检测耗时 {result.elapsed:.2f}s")
    return result
