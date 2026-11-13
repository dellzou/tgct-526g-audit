"""Light-theme Windows desktop UI for the M1.2 read-only audit."""

from __future__ import annotations

import argparse
import ctypes
import glob
import json
import os
import queue
import subprocess
import sys
import tempfile
import threading
import tkinter as tk
import traceback
from datetime import datetime
from tkinter import filedialog, messagebox, simpledialog, ttk

from .appconfig import load_config, save_config
from .audit import AuditCancelled, run_audit
from .crypto import CryptoUnavailable, encrypt_bytes
from .license_text import LICENSE_SUMMARY, LICENSE_TEXT, LICENSE_TITLE
from .models import AuditResult, Target
from .version import APP_NAME, BUILD_CHANNEL, __version__

# --------------------------------------------------------------------------- theme
BG = "#F3F6FA"
SIDEBAR = "#FFFFFF"
CARD = "#FFFFFF"
TEXT = "#111827"
MUTED = "#6B7280"
BORDER = "#E5E7EB"
ACCENT = "#0F9D8A"
ACCENT_DARK = "#0B7C6D"
ACCENT_SOFT = "#E6F6F3"
BLUE = "#2563EB"
GREEN = "#047857"
GREEN_SOFT = "#D1FAE5"
AMBER = "#B45309"
AMBER_SOFT = "#FEF3C7"
RED = "#B91C1C"
RED_SOFT = "#FEE2E2"
LOG_BG = "#F8FAFC"
LOG_TEXT = "#334155"

FONT = "Microsoft YaHei UI"
MONO = "Consolas"


def _log_dir() -> str:
    candidates = [
        os.path.join(os.environ.get("LOCALAPPDATA") or os.path.expanduser("~"), "TGCT526G", "logs"),
        os.path.join(tempfile.gettempdir(), "TGCT526G", "logs"),
        os.path.join(os.getcwd(), "logs"),
    ]
    for path in candidates:
        try:
            os.makedirs(path, exist_ok=True)
            probe = os.path.join(path, ".write-test")
            with open(probe, "w", encoding="utf-8") as handle:
                handle.write("ok")
            os.remove(probe)
            return path
        except OSError:
            continue
    return "."


def _new_logfile() -> str:
    folder = _log_dir()
    try:
        old_logs = sorted(
            glob.glob(os.path.join(folder, "audit-*.log")),
            key=os.path.getmtime,
            reverse=True,
        )
        for old in old_logs[20:]:
            os.remove(old)
    except OSError:
        pass
    return os.path.join(folder, f"audit-{datetime.now():%Y%m%d-%H%M%S}.log")


def _write_crash_log(exc_type, exc, tb) -> str:
    path = os.path.join(_log_dir(), f"crash-{datetime.now():%Y%m%d-%H%M%S}.log")
    try:
        with open(path, "w", encoding="utf-8") as handle:
            handle.write("".join(traceback.format_exception(exc_type, exc, tb)))
    except OSError:
        pass
    return path


def _install_crash_hooks() -> None:
    def excepthook(exc_type, exc, tb):
        _write_crash_log(exc_type, exc, tb)
        try:
            if sys.__stderr__ is not None:
                sys.__stderr__.write("".join(traceback.format_exception(exc_type, exc, tb)))
        except Exception:
            pass

    sys.excepthook = excepthook
    try:
        threading.excepthook = lambda args: _write_crash_log(
            args.exc_type,
            args.exc_value,
            args.exc_traceback,
        )
    except Exception:
        pass


def _asset_path(name: str) -> str:
    base = getattr(sys, "_MEIPASS", None)
    if not base:
        base = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    return os.path.join(base, "assets", name)


def _system_dpi() -> int:
    """Return the effective Windows DPI, falling back to 96."""
    if sys.platform != "win32":
        return 96
    try:
        return int(ctypes.windll.user32.GetDpiForSystem())
    except Exception:
        pass
    try:
        hdc = ctypes.windll.user32.GetDC(0)
        dpi = int(ctypes.windll.gdi32.GetDeviceCaps(hdc, 88))  # LOGPIXELSX
        ctypes.windll.user32.ReleaseDC(0, hdc)
        return dpi or 96
    except Exception:
        return 96


def _enable_dpi_awareness() -> int:
    """Make Tk render at native resolution instead of being bitmap-scaled."""
    if sys.platform != "win32":
        return 96
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(2)  # per-monitor aware
    except Exception:
        try:
            ctypes.windll.user32.SetProcessDPIAware()
        except Exception:
            pass
    return _system_dpi()


class App:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title(f"{APP_NAME} v{__version__}")
        self.root.configure(bg=BG)
        self._apply_ui_scale()
        self._center()

        self.queue: queue.Queue = queue.Queue()
        self.worker: threading.Thread | None = None
        self.stop_event = threading.Event()
        self.current_result: AuditResult | None = None
        self.logfile = _new_logfile()
        self.pages: dict[str, tk.Frame] = {}
        self.nav_buttons: dict[str, tk.Button] = {}
        self.current_page = "overview"
        self._help_filled = False
        self._license_filled = False

        self.vars = {
            "model": tk.StringVar(value="—"),
            "serial": tk.StringVar(value="—"),
            "firmware": tk.StringVar(value="—"),
            "mac": tk.StringVar(value="—"),
            "wan_ip": tk.StringVar(value="—"),
            "account": tk.StringVar(value="—"),
            "password": tk.StringVar(value="—"),
            "ta": tk.StringVar(value="—"),
            "elapsed": tk.StringVar(value="—"),
        }
        self.host_var = tk.StringVar(value="192.168.1.1")
        self.user_var = tk.StringVar(value="useradmin")
        self.pass_var = tk.StringVar(value="ni7tk")
        self.ta_var = tk.StringVar(value="nE7jA%5m")
        self.admin_port_var = tk.StringVar(value="8080")
        self.check_vars: dict[str, tk.StringVar] = {}
        self.check_labels: dict[str, tk.Label] = {}
        saved = load_config()
        self.host_var.set(str(saved.get("host") or self.host_var.get()))
        self.user_var.set(str(saved.get("username") or self.user_var.get()))
        self.admin_port_var.set(str(saved.get("admin_port") or self.admin_port_var.get()))

        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        self.root.report_callback_exception = self._report_callback_exception
        self._build()
        self._set_icon()
        self.show_page("overview")
        self._poll()

    # ------------------------------------------------------------------ layout
    def _apply_ui_scale(self) -> None:
        """Scale the window and Tk fonts for the current display DPI.

        The previous build was DPI-unaware, so Windows bitmap-scaled the whole
        window and text looked blurry.  We now declare per-monitor awareness and
        choose a scale that both follows the DPI and fits the work area.
        """
        dpi = _system_dpi()
        screen_w = self.root.winfo_screenwidth()
        screen_h = self.root.winfo_screenheight()
        scale = min(
            dpi / 96.0,
            max(0.85, (screen_w - 40) / 1240.0),
            max(0.85, (screen_h - 90) / 780.0),
        )
        self.ui_scale = max(0.85, min(scale, 1.5))
        # Tk's default scaling is 96/72; keep font metrics consistent with the
        # pixel geometry chosen above.
        self.root.tk.call("tk", "scaling", (96.0 * self.ui_scale) / 72.0)
        self.root.minsize(
            int(1100 * self.ui_scale),
            int(680 * self.ui_scale),
        )

    def _center(self) -> None:
        self.root.update_idletasks()
        width = int(1240 * self.ui_scale)
        height = int(780 * self.ui_scale)
        x = max(0, (self.root.winfo_screenwidth() - width) // 2)
        y = max(0, (self.root.winfo_screenheight() - height) // 2 - 20)
        self.root.geometry(f"{width}x{height}+{x}+{y}")

    def _set_icon(self) -> None:
        path = _asset_path("icon.ico")
        if os.path.exists(path):
            try:
                self.root.iconbitmap(path)
            except tk.TclError:
                pass

    def _build(self) -> None:
        self.root.grid_rowconfigure(0, weight=1)
        self.root.grid_columnconfigure(1, weight=1)

        self._build_sidebar()
        main = tk.Frame(self.root, bg=BG)
        main.grid(row=0, column=1, sticky="nsew")
        main.grid_rowconfigure(1, weight=1)
        main.grid_columnconfigure(0, weight=1)

        header = tk.Frame(main, bg=BG)
        header.grid(row=0, column=0, sticky="ew", padx=26, pady=(16, 8))
        header.grid_columnconfigure(0, weight=1)

        title_box = tk.Frame(header, bg=BG)
        title_box.grid(row=0, column=0, sticky="w")
        tk.Label(
            title_box,
            text=APP_NAME,
            bg=BG,
            fg=TEXT,
            font=(FONT, 17, "bold"),
            anchor="w",
        ).pack(anchor="w")
        tk.Label(
            title_box,
            text="M1.2 · LuCI 登录 / WAN 凭据读取 / 超管检测",
            bg=BG,
            fg=MUTED,
            font=(FONT, 9),
            anchor="w",
        ).pack(anchor="w", pady=(3, 0))

        self.status_pill = tk.Label(
            header,
            text="待检测",
            bg="#E5E7EB",
            fg=MUTED,
            font=(FONT, 9, "bold"),
            padx=12,
            pady=5,
        )
        self.status_pill.grid(row=0, column=1, sticky="e")

        self.page_host = tk.Frame(main, bg=BG)
        self.page_host.grid(row=1, column=0, sticky="nsew", padx=26, pady=(0, 22))
        self.page_host.grid_rowconfigure(0, weight=1)
        self.page_host.grid_columnconfigure(0, weight=1)

        self.pages["overview"] = self._build_overview()
        self.pages["log"] = self._build_log()
        self.pages["help"] = self._build_help()
        self.pages["license"] = self._build_license()
        for page in self.pages.values():
            page.grid(row=0, column=0, sticky="nsew")
            page.grid_remove()

    def _build_sidebar(self) -> None:
        side = tk.Frame(self.root, bg=SIDEBAR, width=232)
        side.grid(row=0, column=0, sticky="ns")
        side.grid_propagate(False)

        brand = tk.Frame(side, bg=SIDEBAR)
        brand.pack(fill="x", padx=18, pady=(22, 28))
        logo = tk.Label(
            brand,
            text="TG",
            bg=ACCENT,
            fg="white",
            font=(FONT, 13, "bold"),
            width=3,
            height=1,
        )
        logo.pack(side="left")
        brand_text = tk.Frame(brand, bg=SIDEBAR)
        brand_text.pack(side="left", padx=(10, 0))
        tk.Label(
            brand_text,
            text="TGCT-526G",
            bg=SIDEBAR,
            fg=TEXT,
            font=(FONT, 11, "bold"),
            anchor="w",
        ).pack(anchor="w")
        tk.Label(
            brand_text,
            text="宽带账号及超密获取",
            bg=SIDEBAR,
            fg=MUTED,
            font=(FONT, 9),
            anchor="w",
        ).pack(anchor="w")

        nav_items = [
            ("overview", "概览"),
            ("log", "运行日志"),
            ("help", "使用说明"),
            ("license", "协议"),
        ]
        for key, label in nav_items:
            button = tk.Button(
                side,
                text=label,
                anchor="w",
                bg=SIDEBAR,
                fg=TEXT,
                activebackground=ACCENT_SOFT,
                activeforeground=ACCENT_DARK,
                bd=0,
                relief="flat",
                highlightthickness=0,
                padx=20,
                pady=11,
                font=(FONT, 10),
                cursor="hand2",
                command=lambda k=key: self.show_page(k),
            )
            button.pack(fill="x", padx=10, pady=2)
            self.nav_buttons[key] = button

        tk.Frame(side, bg=BORDER, height=1).pack(fill="x", padx=20, pady=14)

        tip = tk.Frame(side, bg=SIDEBAR)
        tip.pack(fill="x", padx=20, pady=(0, 8))
        tk.Label(
            tip,
            text="只读模式",
            bg=ACCENT_SOFT,
            fg=ACCENT_DARK,
            font=(FONT, 8, "bold"),
            padx=8,
            pady=3,
        ).pack(anchor="w")
        tk.Label(
            tip,
            text="不会修改 WAN、重启\n或恢复出厂设置。",
            bg=SIDEBAR,
            fg=MUTED,
            font=(FONT, 8),
            justify="left",
            anchor="w",
        ).pack(anchor="w", pady=(6, 0))

        footer = tk.Frame(side, bg=SIDEBAR)
        footer.pack(side="bottom", fill="x", padx=20, pady=18)
        tk.Label(
            footer,
            text=f"v{__version__} · {BUILD_CHANNEL}",
            bg=SIDEBAR,
            fg=MUTED,
            font=(FONT, 8),
            anchor="w",
        ).pack(anchor="w")
        tk.Label(
            footer,
            text="非商业许可",
            bg=SIDEBAR,
            fg="#9CA3AF",
            font=(FONT, 8),
            anchor="w",
        ).pack(anchor="w", pady=(2, 0))

    def _build_overview(self) -> tk.Frame:
        page = tk.Frame(self.page_host, bg=BG)
        page.grid_columnconfigure(0, minsize=350)
        page.grid_columnconfigure(1, weight=1)
        page.grid_rowconfigure(0, weight=1)

        left = self._card(page)
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 16))
        right = self._card(page)
        right.grid(row=0, column=1, sticky="nsew")

        self._build_form(left)
        self._build_result(right)
        return page

    def _card(self, parent: tk.Widget) -> tk.Frame:
        return tk.Frame(
            parent,
            bg=CARD,
            highlightbackground=BORDER,
            highlightthickness=1,
            bd=0,
        )

    def _section_title(self, parent: tk.Widget, title: str, subtitle: str = "") -> None:
        tk.Label(
            parent,
            text=title,
            bg=CARD,
            fg=TEXT,
            font=(FONT, 12, "bold"),
            anchor="w",
        ).pack(fill="x")
        if subtitle:
            tk.Label(
                parent,
                text=subtitle,
                bg=CARD,
                fg=MUTED,
                font=(FONT, 8),
                anchor="w",
                justify="left",
                wraplength=300,
            ).pack(fill="x", pady=(4, 0))

    def _build_form(self, card: tk.Frame) -> None:
        body = tk.Frame(card, bg=CARD)
        body.pack(fill="both", expand=True, padx=20, pady=14)
        self._section_title(body, "目标设备", "填写路由器管理地址和背面普通账号。")

        button_row = tk.Frame(body, bg=CARD)
        button_row.pack(fill="x", pady=(12, 4))
        self.start_btn = self._button(
            button_row,
            "开始检测",
            self.start_audit,
            primary=True,
            width=12,
        )
        self.start_btn.pack(side="left")
        self.stop_btn = self._button(
            button_row,
            "停止",
            self.stop_audit,
            primary=False,
            width=7,
        )
        self.stop_btn.pack(side="left", padx=(10, 0))
        self.stop_btn.configure(state="disabled")

        style = ttk.Style()
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure(
            "Audit.Horizontal.TProgressbar",
            troughcolor="#E5E7EB",
            background=ACCENT,
            bordercolor="#E5E7EB",
            lightcolor=ACCENT,
            darkcolor=ACCENT,
        )
        self.progress = ttk.Progressbar(
            body,
            mode="indeterminate",
            style="Audit.Horizontal.TProgressbar",
        )
        self.progress.pack(fill="x", pady=(6, 0))

        self._labeled_entry(body, "管理地址", self.host_var, "例如 192.168.1.1")
        self._labeled_entry(body, "普通用户名", self.user_var, "路由器背面，通常 useradmin")
        self._labeled_entry(body, "普通密码", self.pass_var, "路由器背面，默认 ni7tk", show="*")

        advanced = tk.Frame(body, bg=CARD)
        advanced.pack(fill="x", pady=(10, 0))
        for index, (label, variable, show) in enumerate(
            [
                ("超管口令", self.ta_var, "*"),
                ("8080 端口", self.admin_port_var, ""),
            ]
        ):
            column = tk.Frame(advanced, bg=CARD)
            column.pack(side="left", fill="x", expand=True, padx=(0, 8) if index == 0 else (8, 0))
            tk.Label(
                column,
                text=label,
                bg=CARD,
                fg=MUTED,
                font=(FONT, 8),
                anchor="w",
            ).pack(fill="x", pady=(0, 3))
            tk.Entry(
                column,
                textvariable=variable,
                bg="#F9FAFB",
                fg=TEXT,
                insertbackground=TEXT,
                relief="flat",
                bd=0,
                highlightthickness=1,
                highlightbackground=BORDER,
                highlightcolor=ACCENT,
                font=(FONT, 10),
                show=show,
            ).pack(fill="x", ipady=5)

    def _labeled_entry(
        self,
        parent: tk.Widget,
        label: str,
        variable: tk.StringVar,
        hint: str,
        show: str = "",
    ) -> None:
        tk.Label(
            parent,
            text=label,
            bg=CARD,
            fg=MUTED,
            font=(FONT, 8),
            anchor="w",
        ).pack(fill="x", pady=(8, 3))
        entry = tk.Entry(
            parent,
            textvariable=variable,
            bg="#F9FAFB",
            fg=TEXT,
            insertbackground=TEXT,
            relief="flat",
            bd=0,
            highlightthickness=1,
            highlightbackground=BORDER,
            highlightcolor=ACCENT,
            font=(FONT, 10),
            show=show,
        )
        entry.pack(fill="x", ipady=5)
        tk.Label(
            parent,
            text=hint,
            bg=CARD,
            fg="#9CA3AF",
            font=(FONT, 7),
            anchor="w",
        ).pack(fill="x", pady=(3, 0))

    def _build_result(self, card: tk.Frame) -> None:
        body = tk.Frame(card, bg=CARD)
        body.pack(fill="both", expand=True, padx=20, pady=14)

        head = tk.Frame(body, bg=CARD)
        head.pack(fill="x")
        tk.Label(
            head,
            text="检测结果",
            bg=CARD,
            fg=TEXT,
            font=(FONT, 12, "bold"),
            anchor="w",
        ).pack(side="left")
        self.res_state = tk.Label(
            head,
            text="等待检测",
            bg=CARD,
            fg=MUTED,
            font=(FONT, 8),
        )
        self.res_state.pack(side="right")

        tk.Frame(body, bg=BORDER, height=1).pack(fill="x", pady=(8, 4))

        rows = [
            ("model", "设备型号"),
            ("serial", "序列号"),
            ("firmware", "固件版本"),
            ("mac", "MAC"),
            ("wan_ip", "WAN IP"),
            ("account", "宽带账号"),
            ("password", "宽带密码"),
            ("ta", "超管检测"),
            ("elapsed", "耗时"),
        ]
        for key, label in rows:
            row = tk.Frame(body, bg=CARD)
            row.pack(fill="x", pady=2)
            tk.Label(
                row,
                text=label,
                bg=CARD,
                fg=MUTED,
                font=(FONT, 9),
                width=10,
                anchor="w",
            ).pack(side="left")
            if key == "password":
                self.pwd_entry = tk.Entry(
                    row,
                    textvariable=self.vars[key],
                    state="readonly",
                    readonlybackground=CARD,
                    fg=ACCENT_DARK,
                    relief="flat",
                    bd=0,
                    highlightthickness=0,
                    font=(MONO, 10, "bold"),
                )
                self.pwd_entry.pack(side="left", fill="x", expand=True, ipady=3)
                self._copy_button(row, key).pack(side="right", padx=(6, 0))
            else:
                fg = ACCENT_DARK if key == "account" else TEXT
                font = (MONO, 10, "bold") if key == "account" else (FONT, 9)
                tk.Label(
                    row,
                    textvariable=self.vars[key],
                    bg=CARD,
                    fg=fg,
                    font=font,
                    anchor="w",
                    justify="left",
                    wraplength=300,
                ).pack(side="left", fill="x", expand=True)
                if key in ("account", "serial"):
                    self._copy_button(row, key).pack(side="right", padx=(6, 0))

        checklist_head = tk.Frame(body, bg=CARD)
        checklist_head.pack(fill="x", pady=(8, 2))
        tk.Label(
            checklist_head,
            text="检测项",
            bg=CARD,
            fg=TEXT,
            font=(FONT, 9, "bold"),
            anchor="w",
        ).pack(side="left")

        checklist = tk.Frame(body, bg=CARD)
        checklist.pack(fill="x")
        for key, label in [
            ("login", "普通登录"),
            ("device", "设备识别"),
            ("account", "宽带账号"),
            ("ta", "超管检测"),
            ("wan", "WAN 密码"),
        ]:
            row = tk.Frame(checklist, bg=CARD)
            row.pack(fill="x", pady=0)
            dot = tk.Label(
                row,
                text="●",
                bg=CARD,
                fg="#CBD5E1",
                font=(FONT, 7),
                width=2,
                anchor="w",
            )
            dot.pack(side="left")
            tk.Label(
                row,
                text=label,
                bg=CARD,
                fg=MUTED,
                font=(FONT, 8),
                width=9,
                anchor="w",
            ).pack(side="left")
            var = tk.StringVar(value="等待")
            self.check_vars[key] = var
            self.check_labels[key] = dot
            tk.Label(
                row,
                textvariable=var,
                bg=CARD,
                fg=MUTED,
                font=(FONT, 8),
                anchor="w",
            ).pack(side="left", fill="x", expand=True)

        self.result_hint = tk.Label(
            body,
            text="填写目标后点击“开始检测”。",
            bg=CARD,
            fg=MUTED,
            font=(FONT, 8),
            wraplength=480,
            justify="left",
            anchor="w",
        )
        self.result_hint.pack(fill="x", pady=(8, 6))

        actions = tk.Frame(body, bg=CARD)
        actions.pack(fill="x", pady=(2, 0))
        self._button(actions, "复制结果", self.copy_result, primary=False, width=8).pack(side="left")
        self._button(actions, "保存报告", self.save_report, primary=False, width=8).pack(
            side="left", padx=(8, 0)
        )
        self._button(actions, "打开日志", self.open_log_folder, primary=False, width=8).pack(
            side="left", padx=(8, 0)
        )

    def _copy_button(self, parent: tk.Widget, key: str) -> tk.Button:
        return tk.Button(
            parent,
            text="复制",
            command=lambda k=key: self.copy_value(k),
            bg=CARD,
            fg=BLUE,
            activebackground=CARD,
            activeforeground=BLUE,
            bd=0,
            relief="flat",
            highlightthickness=0,
            font=(FONT, 8),
            cursor="hand2",
            width=4,
        )

    def _button(
        self,
        parent: tk.Widget,
        text: str,
        command,
        primary: bool,
        width: int = 10,
    ) -> tk.Button:
        if primary:
            bg, fg, active_bg = ACCENT, "white", ACCENT_DARK
            font = (FONT, 9, "bold")
        else:
            bg, fg, active_bg = "#FFFFFF", TEXT, "#F3F4F6"
            font = (FONT, 9)
        button = tk.Button(
            parent,
            text=text,
            command=command,
            bg=bg,
            fg=fg,
            activebackground=active_bg,
            activeforeground=fg,
            disabledforeground="#9CA3AF",
            bd=0,
            relief="flat",
            highlightthickness=1,
            highlightbackground=BORDER if not primary else ACCENT,
            padx=10,
            pady=7,
            width=width,
            font=font,
            cursor="hand2",
        )
        button.bind(
            "<Enter>",
            lambda _e, b=button, c=active_bg: b.configure(bg=c)
            if str(b["state"]) != "disabled"
            else None,
        )
        button.bind(
            "<Leave>",
            lambda _e, b=button, c=bg: b.configure(bg=c)
            if str(b["state"]) != "disabled"
            else None,
        )
        return button

    def _build_log(self) -> tk.Frame:
        page = tk.Frame(self.page_host, bg=BG)
        card = self._card(page)
        card.pack(fill="both", expand=True)
        body = tk.Frame(card, bg=CARD)
        body.pack(fill="both", expand=True, padx=20, pady=18)

        head = tk.Frame(body, bg=CARD)
        head.pack(fill="x")
        tk.Label(
            head,
            text="运行日志",
            bg=CARD,
            fg=TEXT,
            font=(FONT, 12, "bold"),
        ).pack(side="left")
        self._button(head, "清空", self.clear_log, primary=False, width=6).pack(side="right")
        self._button(head, "打开日志文件夹", self.open_log_folder, primary=False, width=13).pack(
            side="right", padx=(0, 8)
        )

        tk.Label(
            body,
            text=f"日志同时写入：{self.logfile}",
            bg=CARD,
            fg=MUTED,
            font=(FONT, 7),
            anchor="w",
        ).pack(fill="x", pady=(6, 8))

        text_frame = tk.Frame(body, bg=LOG_BG, highlightbackground=BORDER, highlightthickness=1)
        text_frame.pack(fill="both", expand=True)
        self.log_text = tk.Text(
            text_frame,
            bg=LOG_BG,
            fg=LOG_TEXT,
            insertbackground=LOG_TEXT,
            relief="flat",
            bd=0,
            padx=12,
            pady=10,
            wrap="word",
            font=(MONO, 9),
            state="disabled",
        )
        scroll = ttk.Scrollbar(text_frame, command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=scroll.set)
        scroll.pack(side="right", fill="y")
        self.log_text.pack(side="left", fill="both", expand=True)
        self.log_text.tag_configure("INFO", foreground="#475569")
        self.log_text.tag_configure("STEP", foreground=BLUE)
        self.log_text.tag_configure("OK", foreground=GREEN)
        self.log_text.tag_configure("WARN", foreground=AMBER)
        self.log_text.tag_configure("ERROR", foreground=RED)
        return page

    def _build_help(self) -> tk.Frame:
        page = tk.Frame(self.page_host, bg=BG)
        card = self._card(page)
        card.pack(fill="both", expand=True)
        body = tk.Frame(card, bg=CARD)
        body.pack(fill="both", expand=True, padx=20, pady=18)
        self.help_text = tk.Text(
            body,
            bg=CARD,
            fg=TEXT,
            relief="flat",
            bd=0,
            wrap="word",
            padx=4,
            pady=2,
            font=(FONT, 10),
            state="disabled",
            spacing1=2,
            spacing3=4,
        )
        scroll = ttk.Scrollbar(body, command=self.help_text.yview)
        self.help_text.configure(yscrollcommand=scroll.set)
        scroll.pack(side="right", fill="y")
        self.help_text.pack(side="left", fill="both", expand=True)
        self.help_text.tag_configure("H1", font=(FONT, 16, "bold"), foreground=TEXT, spacing3=8)
        self.help_text.tag_configure(
            "H2", font=(FONT, 11, "bold"), foreground=ACCENT_DARK, spacing1=10, spacing3=4
        )
        self.help_text.tag_configure(
            "BODY", font=(FONT, 9), foreground="#374151", lmargin1=2, lmargin2=2
        )
        self.help_text.tag_configure(
            "BULLET", font=(FONT, 9), foreground="#374151", lmargin1=18, lmargin2=18
        )
        return page

    def _build_license(self) -> tk.Frame:
        page = tk.Frame(self.page_host, bg=BG)
        card = self._card(page)
        card.pack(fill="both", expand=True)
        body = tk.Frame(card, bg=CARD)
        body.pack(fill="both", expand=True, padx=20, pady=18)
        self.license_text = tk.Text(
            body,
            bg=CARD,
            fg="#374151",
            relief="flat",
            bd=0,
            wrap="word",
            padx=4,
            pady=2,
            font=(FONT, 9),
            state="disabled",
            spacing1=2,
            spacing3=3,
        )
        scroll = ttk.Scrollbar(body, command=self.license_text.yview)
        self.license_text.configure(yscrollcommand=scroll.set)
        scroll.pack(side="right", fill="y")
        self.license_text.pack(side="left", fill="both", expand=True)
        self.license_text.tag_configure(
            "H1", font=(FONT, 15, "bold"), foreground=TEXT, spacing3=8
        )
        self.license_text.tag_configure(
            "H2", font=(FONT, 10, "bold"), foreground=ACCENT_DARK, spacing1=10, spacing3=3
        )
        return page

    # ------------------------------------------------------------------ pages
    def show_page(self, key: str) -> None:
        for page in self.pages.values():
            page.grid_remove()
        self.pages[key].grid()
        self.current_page = key
        for name, button in self.nav_buttons.items():
            if name == key:
                button.configure(bg=ACCENT_SOFT, fg=ACCENT_DARK, font=(FONT, 10, "bold"))
            else:
                button.configure(bg=SIDEBAR, fg=TEXT, font=(FONT, 10))
        if key == "help" and not self._help_filled:
            self._fill_help()
        if key == "license" and not self._license_filled:
            self._fill_license()

    def _fill_help(self) -> None:
        self._help_filled = True
        t = self.help_text
        t.configure(state="normal")
        t.delete("1.0", "end")

        def h(text: str, tag: str) -> None:
            t.insert("end", text + "\n", tag)

        h("快速开始", "H1")
        h("1. 电脑连接到该路由器的 LAN 口或 WiFi。", "BODY")
        h("2. 打开工具，管理地址默认 192.168.1.1。", "BODY")
        h("3. 输入路由器背面的普通账号和密码（默认 useradmin / ni7tk）。", "BODY")
        h("4. 点击“开始检测”，等待 5–15 秒。", "BODY")
        h("5. 在右侧查看宽带账号、宽带密码和超管默认口令状态。", "BODY")

        h("本版能做什么", "H2")
        h("• 识别设备型号、序列号、固件版本、MAC 和 WAN IP。", "BULLET")
        h("• 普通用户登录 LuCI，读取宽带账号。", "BULLET")
        h("• 检测默认或自定义超管口令。", "BULLET")
        h("• 登录 8080 装维后台，读取 WAN 配置并解出宽带密码。", "BULLET")
        h("• 逐项复制账号/密码，输出日志和 JSON/加密报告。", "BULLET")
        h("• 记住上次目标和端口，启动时自动预检。", "BULLET")

        h("本版不做什么", "H2")
        h("• 不保存/修改 WAN，不重启，不恢复出厂。", "BULLET")
        h("• 不爆破超管口令，不开启 telnet，不写路由器文件。", "BULLET")
        h("• 不包含 M2.1 的超密改动恢复和 RCE 模块。", "BULLET")

        h("常见问题", "H2")
        h("提示 8080 锁定：这是 3 次失败后的临时限制，等待约 60 秒再试。", "BODY")
        h("超管检测失败：设备可能改过默认口令，本版不会继续爆破。", "BODY")
        h("读不到密码：确认 WAN 是 PPPoE，且 8080 页面可访问。", "BODY")
        h(
            "杀毒软件拦截：PyInstaller 单文件程序可能被误报，可改用源码运行或自行构建。",
            "BODY",
        )
        t.configure(state="disabled")

    def _fill_license(self) -> None:
        self._license_filled = True
        t = self.license_text
        t.configure(state="normal")
        t.delete("1.0", "end")
        t.insert("end", LICENSE_TITLE + "\n\n", "H1")
        t.insert("end", LICENSE_SUMMARY + "\n\n", "BODY")
        t.insert("end", "完整协议\n", "H2")
        t.insert("end", LICENSE_TEXT, "BODY")
        t.configure(state="disabled")

    # ------------------------------------------------------------------ logging
    def append_log(self, level: str, message: str) -> None:
        stamp = datetime.now().strftime("%H:%M:%S")
        line = f"[{stamp}] [{level}] {message}\n"
        try:
            with open(self.logfile, "a", encoding="utf-8") as handle:
                handle.write(line)
        except OSError:
            pass
        if not hasattr(self, "log_text"):
            return
        self.log_text.configure(state="normal")
        self.log_text.insert(
            "end",
            line,
            level if level in ("INFO", "STEP", "OK", "WARN", "ERROR") else "INFO",
        )
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    def clear_log(self) -> None:
        self.log_text.configure(state="normal")
        self.log_text.delete("1.0", "end")
        self.log_text.configure(state="disabled")

    def open_log_folder(self) -> None:
        folder = os.path.dirname(self.logfile)
        try:
            os.startfile(folder)  # type: ignore[attr-defined]
        except Exception:
            try:
                subprocess.Popen(["explorer", folder])
            except Exception as exc:  # noqa: BLE001
                self.append_log("ERROR", f"无法打开日志文件夹：{exc}")

    # ------------------------------------------------------------------ actions
    def set_status(self, text: str, bg: str, fg: str) -> None:
        self.status_pill.configure(text=text, bg=bg, fg=fg)

    def set_running(self, running: bool) -> None:
        if running:
            self.start_btn.configure(state="disabled", bg="#9CA3AF")
            self.stop_btn.configure(state="normal")
            self.progress.start(12)
            self.set_status("检测中", AMBER_SOFT, AMBER)
        else:
            self.start_btn.configure(state="normal", bg=ACCENT)
            self.stop_btn.configure(state="disabled")
            self.progress.stop()
        self.start_btn.update_idletasks()

    def start_audit(self) -> None:
        if self.worker and self.worker.is_alive():
            return
        host = self.host_var.get().strip()
        username = self.user_var.get().strip()
        password = self.pass_var.get()
        ta_password = self.ta_var.get()
        if not host:
            messagebox.showinfo("提示", "请填写管理地址")
            return
        if not username or not password:
            messagebox.showinfo("提示", "请填写普通用户名和密码")
            return
        try:
            admin_port = int(self.admin_port_var.get().strip() or "8080")
            if not 1 <= admin_port <= 65535:
                raise ValueError
        except ValueError:
            messagebox.showinfo("提示", "8080 端口必须是 1–65535 的数字")
            return
        target = Target(
            host=host,
            username=username,
            password=password,
            ta_password=ta_password,
            timeout=8.0,
            admin_port=admin_port,
        )
        save_config(
            {
                "host": target.normalized_host(),
                "username": username,
                "admin_port": admin_port,
            }
        )
        self.stop_event.clear()
        self.current_result = None
        for key in self.vars:
            self.vars[key].set("—")
        self.reset_checklist()
        self.pwd_entry.configure(state="normal")
        self.pwd_entry.delete(0, "end")
        self.pwd_entry.configure(state="readonly")
        self.res_state.configure(text="检测中…", fg=AMBER)
        self.result_hint.configure(text="正在登录并读取配置，请稍候…")
        self.set_running(True)
        self.append_log(
            "STEP",
            f"开始检测 {target.normalized_host()}（装维端口 {admin_port}）",
        )
        self.worker = threading.Thread(target=self._worker, args=(target,), daemon=True)
        self.worker.start()

    def stop_audit(self) -> None:
        if self.worker and self.worker.is_alive():
            self.stop_event.set()
            self.append_log("WARN", "已请求停止；等待当前请求返回。")

    def _worker(self, target: Target) -> None:
        def log(level: str, message: str) -> None:
            self.queue.put(("log", level, message))

        def progress(key: str, status: str, message: str) -> None:
            self.queue.put(("progress", key, status, message))

        try:
            result = run_audit(target, log, self.stop_event, progress)
        except AuditCancelled:
            self.queue.put(("cancelled", None))
            return
        except Exception as exc:  # noqa: BLE001
            self.queue.put(("fatal", str(exc)))
            return
        self.queue.put(("done", result))

    def _poll(self) -> None:
        try:
            while True:
                item = self.queue.get_nowait()
                kind = item[0]
                if kind == "log":
                    self.append_log(item[1], item[2])
                elif kind == "progress":
                    self.update_check(item[1], item[2], item[3])
                elif kind == "done":
                    self.apply_result(item[1])
                    self.set_running(False)
                elif kind == "cancelled":
                    self.set_running(False)
                    self.set_status("已停止", "#E5E7EB", MUTED)
                    self.res_state.configure(text="已停止", fg=MUTED)
                    self.append_log("WARN", "检测已停止")
                elif kind == "fatal":
                    self.set_running(False)
                    self.set_status("失败", RED_SOFT, RED)
                    self.res_state.configure(text="检测失败", fg=RED)
                    self.append_log("ERROR", item[1])
        except queue.Empty:
            pass
        self.root.after(100, self._poll)

    def reset_checklist(self) -> None:
        for key, var in self.check_vars.items():
            var.set("等待")
            self.check_labels[key].configure(fg="#CBD5E1")

    def update_check(self, key: str, status: str, message: str) -> None:
        if key not in self.check_vars:
            return
        colors = {
            "wait": "#CBD5E1",
            "run": BLUE,
            "ok": GREEN,
            "warn": AMBER,
            "skip": "#9CA3AF",
            "err": RED,
        }
        self.check_labels[key].configure(fg=colors.get(status, MUTED))
        self.check_vars[key].set(message or status)

    def apply_result(self, result: AuditResult) -> None:
        self.current_result = result
        if result.checks:
            for key, payload in result.checks.items():
                self.update_check(
                    key,
                    str(payload.get("status", "")),
                    str(payload.get("message", "")),
                )
        self.vars["model"].set(result.model or "—")
        self.vars["serial"].set(result.serial or "—")
        self.vars["firmware"].set(result.firmware or "—")
        self.vars["mac"].set(result.mac or "—")
        self.vars["wan_ip"].set(result.wan_ip or "—")
        self.vars["account"].set(result.broadband_account or "—")
        pwd = result.broadband_password
        self.vars["password"].set(pwd or "—")
        self.vars["elapsed"].set(f"{result.elapsed:.2f}s" if result.elapsed else "—")
        if result.superadmin_is_default:
            self.vars["ta"].set(
                f"{result.superadmin_user} / {result.superadmin_password}（默认口令）"
            )
        elif result.superadmin_password:
            self.vars["ta"].set(
                f"{result.superadmin_user} / {result.superadmin_password}（自定义口令）"
            )
        else:
            self.vars["ta"].set("默认口令不可用")

        if result.error:
            self.set_status("失败", RED_SOFT, RED)
            self.res_state.configure(text="检测失败", fg=RED)
            self.result_hint.configure(text=result.error)
            self.append_log("ERROR", f"检测结束：{result.error}")
        elif result.broadband_password:
            self.set_status("完成", GREEN_SOFT, GREEN)
            self.res_state.configure(text="检测完成", fg=GREEN)
            self.result_hint.configure(
                text="已获取宽带凭据。密码已直接显示；保存报告会写入明文，请妥善保管。"
            )
            self.append_log("OK", "检测完成")
        else:
            self.set_status("部分完成", AMBER_SOFT, AMBER)
            self.res_state.configure(text="部分完成", fg=AMBER)
            self.result_hint.configure(text="已获取账号，但密码未获取；请查看日志。")
            self.append_log("WARN", "检测完成，但宽带密码为空")

    def copy_value(self, key: str) -> None:
        value = self.vars.get(key)
        text = value.get() if value else ""
        if not text or text == "—":
            messagebox.showinfo("提示", "该项还没有结果")
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        labels = {"account": "宽带账号", "password": "宽带密码", "serial": "序列号"}
        self.append_log("OK", f"已复制{labels.get(key, key)}到剪贴板")

    def copy_result(self) -> None:
        if not self.current_result:
            messagebox.showinfo("提示", "还没有检测结果")
            return
        text = self.current_result.summary_text(redact=False)
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self.append_log("OK", "结果已复制到剪贴板（包含明文密码，请注意保管）")

    def save_report(self) -> None:
        if not self.current_result:
            messagebox.showinfo("提示", "还没有检测结果")
            return
        default_name = f"tgct526g-{datetime.now():%Y%m%d-%H%M%S}.json"
        path = filedialog.asksaveasfilename(
            parent=self.root,
            title="保存检测报告",
            defaultextension=".json",
            initialfile=default_name,
            filetypes=[
                ("JSON 报告", "*.json"),
                ("文本报告", "*.txt"),
                ("加密报告", "*.tgct"),
            ],
        )
        if not path:
            return
        try:
            if path.lower().endswith(".tgct"):
                password = simpledialog.askstring(
                    "加密报告",
                    "设置报告密码（打开时需要）：",
                    show="*",
                    parent=self.root,
                )
                if not password:
                    return
                payload = json.dumps(
                    self.current_result.to_dict(redact=False),
                    ensure_ascii=False,
                    indent=2,
                ).encode("utf-8")
                with open(path, "wb") as handle:
                    handle.write(encrypt_bytes(payload, password))
                self.append_log("OK", f"加密报告已保存：{path}")
                return
            if path.lower().endswith(".txt"):
                content = self.current_result.summary_text(redact=False)
            else:
                content = json.dumps(
                    self.current_result.to_dict(redact=False),
                    ensure_ascii=False,
                    indent=2,
                )
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(content)
            self.append_log("OK", f"报告已保存：{path}")
        except CryptoUnavailable as exc:
            self.append_log("ERROR", str(exc))
            messagebox.showerror("加密不可用", str(exc))
        except OSError as exc:
            self.append_log("ERROR", f"保存失败：{exc}")
            messagebox.showerror("保存失败", str(exc))
        except Exception as exc:  # noqa: BLE001
            self.append_log("ERROR", f"保存失败：{exc}")
            messagebox.showerror("保存失败", str(exc))

    def load_demo(self) -> None:
        demo = AuditResult(
            target="192.168.1.1",
            model="TGCT-526G",
            serial="F01628-XXXXXXXXXXXX",
            firmware="V1.0.526G1V1",
            mac="F0:16:28:XX:XX:XX",
            wan_ip="172.20.x.x",
            broadband_account="0755****@163.gd",
            broadband_password="Demo#2026",
            superadmin_is_default=True,
            superadmin_password="nE7jA%5m",
            wan_service="3_INTERNET_R_VID_41",
            vlan="41",
            mtu="1492",
            ifname="ppp1.3",
            elapsed=4.21,
            checks={
                "login": {"status": "ok", "message": "useradmin 登录成功"},
                "device": {"status": "ok", "message": "TGCT-526G"},
                "account": {"status": "ok", "message": "0755****@163.gd"},
                "ta": {"status": "ok", "message": "默认口令可用"},
                "wan": {"status": "ok", "message": "密码 8 位"},
            },
        )
        self.apply_result(demo)
        self.set_status("演示数据", "#DBEAFE", BLUE)
        self.append_log("INFO", "已载入演示数据，仅用于界面预览。")

    def _report_callback_exception(self, exc, value, tb) -> None:
        path = _write_crash_log(exc, value, tb)
        try:
            self.append_log("ERROR", f"界面异常已写入 {path}")
        except Exception:
            pass
        messagebox.showerror(
            "界面异常",
            f"操作出错：{value}\n\n崩溃日志：{path}",
        )

    def on_close(self) -> None:
        self.stop_event.set()
        self.root.destroy()

    # ------------------------------------------------------------------ CLI
    @staticmethod
    def run_cli(args: argparse.Namespace) -> int:
        target = Target(
            host=args.host,
            username=args.user,
            password=args.password,
            ta_password=args.ta_password,
            timeout=args.timeout,
            admin_port=args.admin_port,
        )

        def log(level: str, message: str) -> None:
            print(f"[{level}] {message}", file=sys.stderr)

        result = run_audit(target, log)
        if args.out:
            with open(args.out, "w", encoding="utf-8") as handle:
                json.dump(result.to_dict(redact=False), handle, ensure_ascii=False, indent=2)
            print(f"[INFO] 报告已写入 {args.out}", file=sys.stderr)
        print(result.summary_text(redact=not args.show_secrets))
        return 0 if result.broadband_account and not result.error else 1


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
        except Exception:
            pass
    parser = argparse.ArgumentParser(
        prog="tgct526g",
        description="电信天翼TGCT526G宽带账号及超密获取软件（M1.2 稳定版）",
    )
    parser.add_argument("--cli", action="store_true", help="命令行模式，不启动 GUI")
    parser.add_argument("--host", default="192.168.1.1", help="路由器管理地址")
    parser.add_argument("--user", default="useradmin", help="普通用户名")
    parser.add_argument("--password", default="ni7tk", help="普通用户密码")
    parser.add_argument("--ta-password", default="nE7jA%5m", help="超管口令")
    parser.add_argument("--admin-port", type=int, default=8080, help="8080 装维端口")
    parser.add_argument("--timeout", type=float, default=8.0, help="HTTP 超时秒数")
    parser.add_argument("--out", help="将 JSON 报告写入文件")
    parser.add_argument("--show-secrets", action="store_true", help="在终端输出明文密码")
    parser.add_argument("--demo", action="store_true", help="GUI 演示数据")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = parser.parse_args(argv)

    if args.cli:
        return App.run_cli(args)

    _install_crash_hooks()
    _enable_dpi_awareness()
    root = tk.Tk()
    app = App(root)
    if args.demo:
        root.after(350, app.load_demo)
    root.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
