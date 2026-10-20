"""Send alerts to Discord/Slack webhook (optional)."""

from __future__ import annotations
import json
import urllib.request
from typing import List, Optional
from detection.engine import Alert


def send_webhook(url: str, alerts: List[Alert]) -> bool:
    if not url or not alerts:
        return False
    lines = []
    for a in alerts[:10]:
        lines.append(f"**[{a.severity}]** {a.rule_name}\nIP `{a.source_ip}` — {a.detail}")
    payload = {
        "content": None,
        "embeds": [{
            "title": "AttackWatch Alert",
            "color": 15158332,
            "description": "\n\n".join(lines),
            "footer": {"text": "AttackWatch"},
        }],
    }
    try:
        data = json.dumps(payload).encode()
        req = urllib.request.Request(
            url, data=data,
            headers={"Content-Type": "application/json", "User-Agent": "AttackWatch/0.3"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            return 200 <= resp.status < 300
    except Exception as e:
        print(f"  [Webhook] failed: {e}")
        return False
