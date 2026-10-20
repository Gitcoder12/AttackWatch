"""Optional GeoIP lookup via ip-api.com (free, no key, rate-limited)."""

from __future__ import annotations
import time
from typing import Dict, Optional
import urllib.request
import json

_cache: Dict[str, dict] = {}
_last_call = 0.0


def lookup(ip: str) -> Optional[dict]:
    """Return {country, city, isp, org} or None. Skips private IPs."""
    global _last_call
    if not ip or ip.startswith(("10.", "192.168.", "127.", "172.")):
        return {"country": "Private", "city": "-", "isp": "LAN", "org": "-"}
    if ip in _cache:
        return _cache[ip]
    # Be polite: max ~1 req / 1.5s
    elapsed = time.time() - _last_call
    if elapsed < 1.5:
        time.sleep(1.5 - elapsed)
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,country,city,isp,org,query"
        with urllib.request.urlopen(url, timeout=5) as resp:
            data = json.loads(resp.read().decode())
        _last_call = time.time()
        if data.get("status") == "success":
            result = {
                "country": data.get("country", "?"),
                "city": data.get("city", "?"),
                "isp": data.get("isp", "?"),
                "org": data.get("org", "?"),
            }
            _cache[ip] = result
            return result
    except Exception as e:
        print(f"  [GeoIP] {ip} failed: {e}")
    return None
