"""
req_rewrite.py —— mitmproxy 请求拦截与响应体重写 addon

三个功能:
    1. 按正则拦截广告 / 跟踪域名, 直接返回 204
    2. 剔除请求 URL 里的营销追踪参数
    3. 递归删除 JSON 响应里的广告字段

用法:
    mitmproxy -s mitmproxy/req_rewrite.py -p 8080
    mitmdump  -s mitmproxy/req_rewrite.py --set flow_detail=1
"""

from __future__ import annotations

import json
import re
from typing import Any

from mitmproxy import http

BLOCK_PATTERNS = [
    r"(^|\.)ads?\.",
    r"(^|\.)adservice\.",
    r"(^|\.)advert",
    r"(^|\.)doubleclick\.",
    r"(^|\.)track(ing|er)?\.",
    r"(^|\.)analytics\.",
    r"(^|\.)metrics\.",
    r"(^|\.)beacon\.",
    r"(^|\.)umeng\.",
    r"(^|\.)gdt\.qq\.com$",
]
BLOCK_RE = re.compile("|".join(BLOCK_PATTERNS), re.IGNORECASE)

AD_KEY_RE = re.compile(
    r"^(ad|ads|adv|advert|adinfo|ad_list|adlist|promotion|promo|banner|splash_ad|feed_ad)\w*$",
    re.IGNORECASE,
)

STRIP_PARAMS = [
    "utm_source",
    "utm_medium",
    "utm_campaign",
    "utm_term",
    "utm_content",
    "spm",
    "track_id",
    "from_source",
]

MAX_DEPTH = 8


class Rewriter:
    def __init__(self) -> None:
        self.blocked = 0
        self.rewritten = 0

    def request(self, flow: http.HTTPFlow) -> None:
        host = flow.request.pretty_host
        if BLOCK_RE.search(host):
            self.blocked += 1
            flow.response = http.Response.make(
                204,
                b"",
                {"Content-Type": "text/plain", "X-Blocked-By": "req_rewrite"},
            )
            return

        for name in STRIP_PARAMS:
            if name in flow.request.query:
                del flow.request.query[name]

    def response(self, flow: http.HTTPFlow) -> None:
        response = flow.response
        if response is None:
            return
        content_type = response.headers.get("content-type", "")
        if "json" not in content_type.lower():
            return
        try:
            payload = json.loads(response.get_text(strict=False))
        except (ValueError, UnicodeDecodeError):
            return

        if _strip_ad_keys(payload, 0):
            response.set_text(
                json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
            )
            self.rewritten += 1

    def done(self) -> None:
        print(
            "[req_rewrite] 拦截域名 {0} 次, 重写响应 {1} 次".format(
                self.blocked, self.rewritten
            )
        )


def _strip_ad_keys(node: Any, depth: int) -> int:
    """递归删除广告类字段, 返回删除数量。"""
    if depth > MAX_DEPTH:
        return 0
    removed = 0
    if isinstance(node, dict):
        for key in list(node.keys()):
            if AD_KEY_RE.match(str(key)):
                del node[key]
                removed += 1
                continue
            removed += _strip_ad_keys(node[key], depth + 1)
    elif isinstance(node, list):
        for item in node:
            removed += _strip_ad_keys(item, depth + 1)
    return removed


addons = [Rewriter()]
