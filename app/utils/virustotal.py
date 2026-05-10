import base64
from typing import Optional

import httpx
from app.config import settings

_VT_BASE = "https://www.virustotal.com/api/v3"


def _headers() -> dict:
    return {"x-apikey": settings.VIRUS_TOTAL_KEY}


def _malicious_count(response_json: dict) -> int:
    stats = response_json.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    return stats.get("malicious", 0)


async def check_hash(file_hash: str) -> Optional[dict]:
    if not settings.VIRUS_TOTAL_KEY:
        return None
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.get(f"{_VT_BASE}/files/{file_hash}", headers=_headers())
    if resp.status_code != 200:
        return None
    detections = _malicious_count(resp.json())
    return {"item": file_hash, "type": "hash", "malicious": detections > 0, "detections": detections}


async def check_url(url: str) -> Optional[dict]:
    if not settings.VIRUS_TOTAL_KEY:
        return None
    url_id = base64.urlsafe_b64encode(url.encode()).rstrip(b"=").decode()
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.get(f"{_VT_BASE}/urls/{url_id}", headers=_headers())
    if resp.status_code != 200:
        return None
    detections = _malicious_count(resp.json())
    return {"item": url, "type": "url", "malicious": detections > 0, "detections": detections}
