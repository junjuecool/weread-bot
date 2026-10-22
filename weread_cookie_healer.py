#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WeRead 凭证自愈模块（fork 定制）

职责：
1. 把运行期内刷新到的新 Cookie 重新写回到抓包用的 CURL 文本里；
2. （可选）在 GitHub Actions 环境下把更新后的 CURL 自动回写到仓库 Secret，
   让定时运行在下次启动时就用上"新"凭证，尽量延长免手动抓包的时间；
3. 提供凭证失效时的恢复指引文案（用于飞书等通知）。

说明：
- 本模块只依赖标准库 + PyNaCl（GitHub Secret 加密需要），未启用同步时无副作用；
- 所有日志输出均经过脱敏处理，绝不打印完整 Cookie / Token。
"""

from __future__ import annotations

import base64
import json
import logging
import os
import re
import urllib.error
import urllib.request
from typing import Dict, Optional, Tuple

__version__ = "1.0.0"

# 环境变量名（与仓库 README《Secrets 表》保持一致）
ENV_SYNC_ENABLED = "WEREAD_COOKIE_SYNC_ENABLED"
ENV_SECRET_NAME = "WEREAD_COOKIE_SYNC_SECRET_NAME"
ENV_SYNC_TOKEN = "WEREAD_SECRET_SYNC_TOKEN"   # 可选：PAT 覆盖 GITHUB_TOKEN
ENV_REPO = "GITHUB_REPOSITORY"                # Actions 自动提供 owner/repo
ENV_API_URL = "GITHUB_API_URL"                # 默认 https://api.github.com

DEFAULT_SECRET_NAME = "WEREAD_CURL_STRING"


def _truthy(value: Optional[str]) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def _mask_cookie_line(cookie_string: str) -> str:
    """日志脱敏：只展示 cookie 名，不展示取值。"""
    names = [part.split("=", 1)[0].strip() for part in cookie_string.split(";") if part.strip()]
    return f"{len(names)} 项({', '.join(names)})"


def build_curl_with_cookies(curl_text: str, cookies: Dict[str, str]) -> Optional[str]:
    """用最新 cookies 重建一条抓包 CURL。

    支持 DevTools 复制的两种常见写法：
        curl ... -H 'Cookie: a=1; b=2' ...
        curl ... -b 'a=1; b=2' ...

    返回 None 表示无法安全改写（例如新 cookie 与引号风格冲突），
    调用方应放弃本次回写，不影响主流程。
    """
    if not curl_text or not cookies:
        return None

    new_cookie_string = "; ".join(f"{k}={v}" for k, v in cookies.items() if v)

    # 形式一：-H 'Cookie: ...' / -H "Cookie: ..."
    def _replace_header_cookie(match: "re.Match") -> str:
        prefix, quote, label, _old, quote_close = match.groups()
        if quote == "'" and "'" in new_cookie_string:
            raise ValueError("单引号风格的 Cookie 与新值冲突")
        if quote == '"' and '"' in new_cookie_string:
            raise ValueError("双引号风格的 Cookie 与新值冲突")
        return f"{prefix}{quote}{label}{new_cookie_string}{quote_close}"

    header_pattern = re.compile(
        r"(-H\s+)(['\"])(Cookie\s*:\s*)([^'\"]*)(\2)",
        re.IGNORECASE,
    )
    # 形式二：-b 'xxx' / -b "xxx"
    def _replace_b(match: "re.Match") -> str:
        flag, quote, _old, quote_close = match.groups()
        if quote == "'" and "'" in new_cookie_string:
            raise ValueError("单引号风格的 -b 与新值冲突")
        if quote == '"' and '"' in new_cookie_string:
            raise ValueError("双引号风格的 -b 与新值冲突")
        return f"{flag}{quote}{new_cookie_string}{quote_close}"

    b_pattern = re.compile(r"(-b\s+)(['\"])([^'\"]*)(\2)")

    try:
        result = b_pattern.sub(_replace_b, curl_text)
        result = header_pattern.sub(_replace_header_cookie, result)
    except ValueError as exc:
        logging.warning("⚠️ CURL 改写失败（%s），本次跳过回写", exc)
        return None

    return result


class GitHubSecretClient:
    """GitHub Actions Secrets API 客户端（仓库级 Secret）。

    凭据优先级：WEREAD_SECRET_SYNC_TOKEN > GITHUB_TOKEN。
    需要 PyNaCl 完成 Secret 加密。
    """

    def __init__(self, token: str, repo: str, api_url: str = "https://api.github.com"):
        if not token:
            raise ValueError("缺少 GitHub Token（GITHUB_TOKEN 或 WEREAD_SECRET_SYNC_TOKEN）")
        if not repo or "/" not in repo:
            raise ValueError(f"GITHUB_REPOSITORY 无效: {repo!r}")
        try:
            from nacl.public import PublicKey, SealedBox  # noqa: F401
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError(
                "缺少依赖 PyNaCl，无法加密 Secret；请确认已按 requirements.txt 安装"
            ) from exc
        self._nacl_public = __import__("nacl.public", fromlist=["PublicKey", "SealedBox"])
        self.token = token
        self.repo = repo
        self.api_url = (api_url or "https://api.github.com").rstrip("/")

    def _request(self, method: str, path: str, body: Optional[dict] = None) -> dict:
        url = f"{self.api_url}{path}"
        data = json.dumps(body).encode("utf-8") if body is not None else None
        request = urllib.request.Request(url, data=data, method=method)
        request.add_header("Accept", "application/vnd.github+json")
        request.add_header("Authorization", f"Bearer {self.token}")
        request.add_header("X-GitHub-Api-Version", "2022-11-28")
        request.add_header("Content-Type", "application/json")
        request.add_header("User-Agent", "weread-cookie-healer")
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                payload = response.read().decode("utf-8")
                return json.loads(payload) if payload else {}
        except urllib.error.HTTPError as exc:
            raise RuntimeError(
                f"GitHub API {method} {path} -> HTTP {exc.code}"
            ) from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(f"GitHub API 网络错误: {exc.reason}") from exc

    def get_public_key(self) -> Tuple[str, str]:
        data = self._request(
            "GET", f"/repos/{self.repo}/actions/secrets/public-key"
        )
        key = data.get("key")
        key_id = data.get("key_id")
        if not key or not key_id:
            raise RuntimeError("GitHub 返回的 Secret 公钥不完整")
        return key, key_id

    def update_secret(self, secret_name: str, plaintext: str) -> None:
        """加密并更新仓库 Secret（不打印任何明文）。"""
        nacl_public = self._nacl_public
        key, key_id = self.get_public_key()
        public_key = nacl_public.PublicKey(base64.b64decode(key))
        sealed_box = nacl_public.SealedBox(public_key)
        encrypted = base64.b64encode(
            sealed_box.encrypt(plaintext.encode("utf-8"))
        ).decode("ascii")
        self._request(
            "PUT",
            f"/repos/{self.repo}/actions/secrets/{secret_name}",
            body={"encrypted_value": encrypted, "key_id": key_id},
        )


class CookieHealer:
    """凭证自愈门面：供 weread-bot.py 调用。"""

    def __init__(
        self,
        enabled: Optional[bool] = None,
        secret_name: Optional[str] = None,
        token: Optional[str] = None,
        repo: Optional[str] = None,
        api_url: Optional[str] = None,
    ):
        env = os.environ
        self.enabled = _truthy(env.get(ENV_SYNC_ENABLED, "")) if enabled is None else bool(enabled)
        self.secret_name = secret_name or env.get(ENV_SECRET_NAME) or DEFAULT_SECRET_NAME
        self.token = token or env.get(ENV_SYNC_TOKEN) or env.get("GITHUB_TOKEN") or ""
        self.repo = repo or env.get(ENV_REPO) or ""
        self.api_url = api_url or env.get(ENV_API_URL) or "https://api.github.com"

    # ---- 对上层暴露的能力 -------------------------------------------------

    @staticmethod
    def repair_guide_text() -> str:
        """凭证失效恢复指引（写入通知）。"""
        return (
            "🔧 凭证可能已失效，请按以下步骤恢复（约 1 分钟）：\n"
            "1. 浏览器打开 https://weread.qq.com 并登录；\n"
            "2. 打开任意一本书并翻页；\n"
            "3. F12 → 网络(Network) → 找到 read 请求；\n"
            "4. 右键 Copy as cURL；\n"
            "5. 仓库 Settings → Secrets → Actions 更新 "
            "WEREAD_CURL_STRING。"
        )

    @classmethod
    def sync_from_session(cls, session_manager) -> str:
        """从会话管理器导出刷新后的 CURL 并尝试回写，返回状态字符串。"""
        healer = cls()
        curl_text = None
        try:
            curl_text = session_manager.export_refreshed_curl()
        except Exception as exc:  # 防御：导出自带异常不应影响主流程
            logging.warning("⚠️ 导出刷新后凭证失败: %s", exc)
            return "failed:export"
        if not curl_text:
            return "skipped:no_changes"
        return healer.sync_curl_text(curl_text)

    def sync_curl_text(self, curl_text: str) -> str:
        """把刷新后的 CURL 回写到 GitHub Secret。"""
        if not self.enabled:
            return "skipped:disabled"
        if not curl_text or not curl_text.strip():
            return "skipped:empty"
        if not self.token or not self.repo:
            logging.info(
                "ℹ️ 非 GitHub Actions 环境（或缺 GITHUB_TOKEN/GITHUB_REPOSITORY），"
                "凭证回写仅在 Actions 中生效"
            )
            return "skipped:not_in_actions"
        try:
            client = GitHubSecretClient(self.token, self.repo, self.api_url)
            client.update_secret(self.secret_name, curl_text.strip())
        except Exception as exc:
            logging.warning(
                "⚠️ 凭证回写 GitHub Secret '%s' 失败: %s（不影响本次运行；"
                "如需自动回写，请参考 README 配置 WEREAD_SECRET_SYNC_TOKEN）",
                self.secret_name,
                exc,
            )
            return f"failed:{exc}"[:200]
        logging.info(
            "✅ 凭证自愈成功：刷新后的 CURL 已回写 Secret '%s'（%s）",
            self.secret_name,
            _mask_cookie_line(
                extract_cookie_string(curl_text) or ""
            ),
        )
        return "synced"


_CURL_COOKIE_HEADER_RE = re.compile(
    r"-H\s+['\"]Cookie\s*:\s*([^'\"]*)['\"]", re.IGNORECASE
)
_CURL_B_RE = re.compile(r"-b\s+['\"]([^'\"]*)['\"]")


def extract_cookie_string(curl_text: str) -> Optional[str]:
    """从 CURL 文本中提取 Cookie 字符串（仅用于脱敏展示/调试）。"""
    if not curl_text:
        return None
    match = _CURL_COOKIE_HEADER_RE.search(curl_text)
    if not match:
        match = _CURL_B_RE.search(curl_text)
    return match.group(1) if match else None
