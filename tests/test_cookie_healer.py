"""fork 定制：凭证自愈模块测试。"""

import base64
import unittest
from unittest.mock import MagicMock, patch

from tests.helpers import load_weread_bot

import weread_cookie_healer as healer


class BuildCurlTests(unittest.TestCase):
    def test_replace_cookie_header_single_quotes(self):
        curl = (
            "curl 'https://weread.qq.com/web/book/read' "
            "-H 'Cookie: wr_vid=1; wr_skey=old' "
            "--data-raw '{\"b\":\"book\"}'"
        )
        result = healer.build_curl_with_cookies(
            curl, {"wr_vid": "1", "wr_skey": "new"}
        )
        self.assertIn("-H 'Cookie: wr_vid=1; wr_skey=new'", result)
        self.assertIn("--data-raw", result)

    def test_replace_dash_b_form(self):
        curl = 'curl "https://weread.qq.com/web/book/read" -b "wr_skey=old"'
        result = healer.build_curl_with_cookies(curl, {"wr_skey": "new"})
        self.assertEqual(result, 'curl "https://weread.qq.com/web/book/read" -b "wr_skey=new"')

    def test_returns_none_when_quote_conflicts(self):
        curl = "curl 'https://x' -H 'Cookie: wr_skey=old'"
        result = healer.build_curl_with_cookies(curl, {"wr_skey": "a'b"})
        self.assertIsNone(result)

    def test_multiline_curl_from_devtools(self):
        curl = (
            "curl 'https://weread.qq.com/web/book/read' \\\n"
            "  -H 'Cookie: wr_vid=1; wr_skey=old' \\\n"
            "  --data-raw '{}'"
        )
        result = healer.build_curl_with_cookies(curl, {"wr_vid": "1", "wr_skey": "new"})
        self.assertIn("-H 'Cookie: wr_vid=1; wr_skey=new'", result)
        self.assertIn("\\\n  --data-raw", result)


class GitHubSecretClientTests(unittest.TestCase):
    def setUp(self):
        from nacl.public import PrivateKey

        self.private_key = PrivateKey.generate()
        self.client = healer.GitHubSecretClient(
            token="t", repo="owner/repo"
        )
        self.public_key_b64 = base64.b64encode(
            bytes(self.private_key.public_key)
        ).decode()

    def _patch_request(self, recorder):
        def _fake_request(method, path, body=None):
            recorder.append((method, path, body))
            if path.endswith("public-key"):
                return {"key": self.public_key_b64, "key_id": "key-1"}
            return {}

        return patch.object(self.client, "_request", side_effect=_fake_request)

    def test_update_secret_encrypts_roundtrip(self):
        recorder = []
        with self._patch_request(recorder):
            self.client.update_secret("WEREAD_CURL_STRING", "curl-secret-value")

        methods = [(m, p) for m, p, _ in recorder]
        self.assertIn(("GET", "/repos/owner/repo/actions/secrets/public-key"), methods)
        self.assertIn(
            ("PUT", "/repos/owner/repo/actions/secrets/WEREAD_CURL_STRING"),
            methods,
        )
        put_body = next(b for m, _, b in recorder if m == "PUT")
        self.assertEqual(put_body["key_id"], "key-1")

        from nacl.public import SealedBox

        box = SealedBox(self.private_key)
        plaintext = box.decrypt(base64.b64decode(put_body["encrypted_value"]))
        self.assertEqual(plaintext, b"curl-secret-value")

    def test_http_error_raises_runtime_error(self):
        import urllib.error

        with patch.object(
            self.client,
            "_request",
            side_effect=RuntimeError("GitHub API PUT -> HTTP 403"),
        ):
            with self.assertRaises(RuntimeError):
                self.client.update_secret("X", "y")


class CookieHealerTests(unittest.TestCase):
    def test_disabled_by_default(self):
        with patch.dict("os.environ", {}, clear=True):
            healer_obj = healer.CookieHealer()
        self.assertFalse(healer_obj.enabled)
        self.assertEqual(healer_obj.sync_curl_text("curl ..."), "skipped:disabled")

    def test_missing_token_or_repo_skips(self):
        with patch.dict(
            "os.environ",
            {"WEREAD_COOKIE_SYNC_ENABLED": "1", "WEREAD_COOKIE_SYNC_SECRET_NAME": "S"},
            clear=True,
        ):
            healer_obj = healer.CookieHealer()
        self.assertTrue(healer_obj.enabled)
        self.assertEqual(healer_obj.secret_name, "S")
        self.assertEqual(healer_obj.sync_curl_text("curl ..."), "skipped:not_in_actions")

    def test_sync_success(self):
        with patch.dict(
            "os.environ",
            {
                "WEREAD_COOKIE_SYNC_ENABLED": "true",
                "GITHUB_TOKEN": "gh-token",
                "GITHUB_REPOSITORY": "me/wxread",
            },
            clear=True,
        ):
            healer_obj = healer.CookieHealer()
            with patch.object(healer.GitHubSecretClient, "update_secret") as mock:
                status = healer_obj.sync_curl_text("curl 'x' -H 'Cookie: a=1'")
        self.assertEqual(status, "synced")
        mock.assert_called_once()
        self.assertEqual(mock.call_args[0][0], "WEREAD_CURL_STRING")

    def test_sync_failure_returns_failed(self):
        with patch.dict(
            "os.environ",
            {
                "WEREAD_COOKIE_SYNC_ENABLED": "true",
                "GITHUB_TOKEN": "gh-token",
                "GITHUB_REPOSITORY": "me/wxread",
            },
            clear=True,
        ):
            healer_obj = healer.CookieHealer()
            with patch.object(
                healer.GitHubSecretClient,
                "update_secret",
                side_effect=RuntimeError("boom"),
            ):
                status = healer_obj.sync_curl_text("curl 'x'")
        self.assertTrue(status.startswith("failed:"))

    def test_sync_from_session_uses_manager_export(self):
        manager = MagicMock()
        manager.export_refreshed_curl.return_value = "curl 'x' -H 'Cookie: a=1'"
        with patch.object(healer.CookieHealer, "sync_curl_text", return_value="synced") as mock:
            status = healer.CookieHealer.sync_from_session(manager)
        self.assertEqual(status, "synced")
        mock.assert_called_once()

    def test_sync_from_session_without_changes(self):
        manager = MagicMock()
        manager.export_refreshed_curl.return_value = None
        self.assertEqual(
            healer.CookieHealer.sync_from_session(manager), "skipped:no_changes"
        )

    def test_repair_guide_mentions_secret(self):
        self.assertIn("WEREAD_CURL_STRING", healer.CookieHealer.repair_guide_text())


class SessionCookieCaptureTests(unittest.TestCase):
    """会话侧：Cookie 捕获与导出。"""

    def setUp(self):
        self.bot = load_weread_bot()

    def _session(self, template="curl 'https://weread.qq.com/web/book/read' -H 'Cookie: wr_skey=old'"):
        session = object.__new__(self.bot.WeReadSessionManager)
        session.cookies = {"wr_skey": "old"}
        session.headers = {}
        session._curl_template = template
        return session

    def test_capture_merges_response_cookies(self):
        session = self._session()
        response = MagicMock()
        response.cookies = {"wr_vid": "42"}
        response.headers.get.return_value = "wr_skey=fresh; Path=/"
        session._capture_cookies_from_response(response)
        self.assertEqual(session.cookies["wr_vid"], "42")
        self.assertEqual(session.cookies["wr_skey"], "fresh")
        self.assertTrue(session.cookie_dirty)

    def test_capture_without_change_keeps_clean(self):
        session = self._session()
        response = MagicMock()
        response.cookies = {}
        response.headers.get.return_value = ""
        session._capture_cookies_from_response(response)
        self.assertFalse(session.cookie_dirty)

    def test_export_requires_successful_renewal(self):
        session = self._session()
        self.assertIsNone(session.export_refreshed_curl())
        session.cookie_dirty = True
        session.cookie_renewals = 1
        exported = session.export_refreshed_curl()
        self.assertIn("-H 'Cookie: wr_skey=old'", exported)

    def test_export_applies_newest_cookie(self):
        session = self._session()
        session.cookies = {"wr_skey": "refreshed-key"}
        session.cookie_dirty = True
        session.cookie_renewals = 2
        exported = session.export_refreshed_curl()
        self.assertIn("-H 'Cookie: wr_skey=refreshed-key'", exported)
        self.assertNotIn("old", exported)


class CookieRenewalDirtyTests(unittest.IsolatedAsyncioTestCase):
    """续期只轮换 wr_skey 时，也必须标记 dirty 以便回写。"""

    def _session(self, bot):
        session = object.__new__(bot.WeReadSessionManager)
        session.cookies = {"wr_skey": "old-sk ey", "wr_vid": "1"}
        session.headers = {}
        session.user_name = "default"
        session.cookie_dirty = False
        session.cookie_renewals = 0
        session._curl_template = (
            "curl 'https://weread.qq.com/web/book/read' "
            "-H 'Cookie: wr_skey=old-sk ey'"
        )
        return session

    async def test_renewal_marks_dirty_with_only_skey_rotation(self):
        bot = load_weread_bot()
        session = self._session(bot)

        class _Headers:
            def get(self, key, default=""):
                if key == "set-cookie":
                    return "wr_skey=new-sk ey123; Path=/; HttpOnly"
                return default

        class _Response:
            cookies = {}
            headers = _Headers()

        class _HttpClient:
            async def post_raw(self, *args, **kwargs):
                return _Response(), 0.1

        session.http_client = _HttpClient()
        session._build_cookie_refresh_payloads = lambda: [{"ql": True}]

        refreshed = await session._refresh_cookie()

        self.assertTrue(refreshed)
        self.assertEqual(session.cookies["wr_skey"], "new-sk ey123")
        self.assertTrue(session.cookie_dirty)
        exported = session.export_refreshed_curl()
        self.assertIn("wr_skey=new-sk ey123", exported)
        self.assertNotIn("old-sk ey'", exported)



if __name__ == "__main__":
    unittest.main()
