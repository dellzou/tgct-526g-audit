"""Small HTTP client for the two management planes of the TGCT-526G.

* port 80  : LuCI / uhttpd, cookie session ``sysauth``
* port 8080: ty_httpd, IP-authorised installer session, plaintext ``psd`` login
"""

from __future__ import annotations

import gzip
import http.cookiejar as cookiejar
import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any

from .models import Target

USER_AGENT = "TGCT526G-Audit/0.1 (Windows; read-only)"


class AuditError(RuntimeError):
    """Base error for an audit step."""


class AuthError(AuditError):
    """Login was rejected."""


class RateLimitError(AuditError):
    """The 8080 installer login is temporarily locked."""


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


@dataclass
class HttpResponse:
    status: int
    headers: dict[str, str]
    body: bytes
    url: str

    @property
    def text(self) -> str:
        raw = self.body
        if self.headers.get("content-encoding", "").lower() == "gzip":
            try:
                raw = gzip.decompress(raw)
            except OSError:
                pass
        charset = "utf-8"
        ctype = self.headers.get("content-type", "")
        match = re.search(r"charset=([A-Za-z0-9._-]+)", ctype, re.I)
        if match:
            charset = match.group(1)
        for encoding in (charset, "utf-8", "gb18030", "latin-1"):
            try:
                return raw.decode(encoding)
            except (UnicodeDecodeError, LookupError):
                continue
        return raw.decode("utf-8", errors="replace")

    def header(self, name: str, default: str = "") -> str:
        return self.headers.get(name.lower(), default)


class Session:
    """Cookie-aware HTTP session with redirects disabled."""

    def __init__(self, target: Target):
        self.target = target
        self.jar = cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.jar),
            NoRedirect(),
        )

    def _url(self, path: str) -> str:
        if path.lower().startswith(("http://", "https://")):
            return path
        return self.target.origin + path

    def request(
        self,
        method: str,
        path: str,
        data: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
    ) -> HttpResponse:
        url = self._url(path)
        body = None
        merged = {
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/json,*/*",
        }
        if headers:
            merged.update(headers)
        if data is not None:
            body = urllib.parse.urlencode(data).encode("utf-8")
            merged.setdefault("Content-Type", "application/x-www-form-urlencoded")
        request = urllib.request.Request(url, data=body, method=method, headers=merged)
        try:
            response = self.opener.open(request, timeout=self.target.timeout)
            status = getattr(response, "status", 200)
            raw_headers = response.headers
            payload = response.read()
        except urllib.error.HTTPError as exc:
            status = exc.code
            raw_headers = exc.headers
            payload = exc.read()
        except urllib.error.URLError as exc:
            raise AuditError(f"无法连接 {url}: {exc.reason}") from exc
        except TimeoutError as exc:
            raise AuditError(f"连接 {url} 超时") from exc

        parsed_headers = {k.lower(): v for k, v in raw_headers.items()}
        return HttpResponse(status=status, headers=parsed_headers, body=payload, url=url)

    def get(self, path: str, headers: dict[str, str] | None = None) -> HttpResponse:
        return self.request("GET", path, headers=headers)

    def post(
        self,
        path: str,
        data: dict[str, str],
        headers: dict[str, str] | None = None,
    ) -> HttpResponse:
        return self.request("POST", path, data=data, headers=headers)

    def has_cookie(self, name: str) -> bool:
        return any(cookie.name == name for cookie in self.jar)

    def cookie(self, name: str) -> str:
        for cookie in self.jar:
            if cookie.name == name:
                return cookie.value
        return ""

    # ------------------------------------------------------------------ LuCI
    def login_luci(self) -> None:
        # Prime the cookie jar / login page.
        self.get("/cgi-bin/luci")
        response = self.post(
            "/cgi-bin/luci",
            {"username": self.target.username, "psd": self.target.password},
        )
        if not self.has_cookie("sysauth"):
            hint = "用户名或密码错误" if "密码错误" in response.text else "未获得 sysauth 会话"
            raise AuthError(f"LuCI 登录失败：{hint}")
        # Verify the session can actually read an authenticated page.
        check = self.get("/cgi-bin/luci/")
        if check.status != 200 or "login_form" in check.text:
            raise AuthError("LuCI 登录后仍回到登录页")

    def get_gwinfo(self) -> dict[str, Any]:
        response = self.get("/cgi-bin/luci/admin/settings/gwinfo?get=all")
        if response.status != 200:
            raise AuditError(f"读取网关信息失败（HTTP {response.status}）")
        try:
            data = json.loads(response.text)
        except json.JSONDecodeError as exc:
            raise AuditError("网关信息不是合法 JSON（会话可能已失效）") from exc
        if not isinstance(data, dict):
            raise AuditError("网关信息格式异常")
        return data

    # ------------------------------------------------------------------ 8080
    def check_ta_default(self, ta_password: str) -> tuple[bool, str]:
        """Check the default TA password without touching port 8080."""
        session = Session(self.target)
        session.get("/cgi-bin/luci")
        response = session.post(
            "/cgi-bin/luci",
            {"username": "telecomadmin", "psd": ta_password},
        )
        body = response.text
        match = re.search(r'getElementById\("psd"\)\.value\s*=\s*"([^"]*)"', body)
        if "8080/login.cgi" in body and match and match.group(1) == ta_password:
            return True, body
        return False, body

    def login_8080(self, ta_password: str) -> str:
        """Log into the installer plane and return the NN_WAN.html source."""
        target = self.target.with_port(8080)
        session = Session(target)
        session.get("/login.html")
        response = session.post(
            "/login.cgi",
            {"username": "telecomadmin", "psd": ta_password},
            headers={"Referer": target.origin + "/login.html"},
        )
        body = response.text
        if "禁止登录" in body or "超过三次" in body:
            raise RateLimitError("8080 装维登录被临时锁定，请等待约 60 秒后重试；M1 不会继续尝试")
        if "main.html" not in body:
            raise AuthError("8080 装维登录失败：默认超管口令不可用或页面结构已变化")
        # The installer session is IP-authorised; cookies are not required.
        page = session.get("/NN_WAN.html")
        if page.status != 200:
            raise AuditError(f"读取 WAN 页面失败（HTTP {page.status}）")
        if "WanConnStr" not in page.text:
            raise AuditError("WAN 页面中没有 WanConnStr（可能未授权或固件已变更）")
        return page.text


def polite_pause(seconds: float = 0.35) -> None:
    """Keep request bursts gentle; the installer plane locks after 3 failures."""
    time.sleep(seconds)
