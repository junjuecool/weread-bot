import unittest

from tests.helpers import load_weread_bot


class PlaceholderWebhookTests(unittest.TestCase):
    def setUp(self):
        self.bot = load_weread_bot()

    def test_is_placeholder_webhook_detects_common_placeholders(self):
        check = self.bot.is_placeholder_webhook

        self.assertTrue(check("", "飞书"))
        self.assertTrue(check(
            "https://open.feishu.cn/open-apis/bot/v2/hook/请替换为真实token",
            "飞书",
        ))
        self.assertTrue(check(
            "https://open.feishu.cn/open-apis/bot/v2/hook/your_webhook_here",
            "飞书",
        ))
        self.assertTrue(check(
            "https://open.feishu.cn/open-apis/bot/v2/hook/xxxxxxxx",
            "飞书",
        ))
        # 非飞书域名的地址一律视为非法
        self.assertTrue(check("https://example.com/hook", "飞书"))
        self.assertTrue(check(
            "http://open.feishu.cn/open-apis/bot/v2/hook/abc123",
            "飞书",
        ))

    def test_is_placeholder_webhook_accepts_real_address(self):
        check = self.bot.is_placeholder_webhook

        self.assertFalse(check(
            "https://open.feishu.cn/open-apis/bot/v2/hook/"
            "0d4b8e2c-1f3a-4c2b-9d8e-abcdef123456",
            "飞书",
        ))

    def test_send_feishu_rejects_placeholder_webhook_without_request(self):
        service = object.__new__(self.bot.NotificationService)

        result = service._send_feishu(
            "测试消息",
            {"webhook_url": "https://open.feishu.cn/open-apis/bot/v2/hook/请替换"},
        )

        self.assertFalse(result)
