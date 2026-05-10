import asyncio
import base64
import hashlib
import json
import re

import anthropic
from app.config import settings
from app.utils.email_parser import get_header, parse_raw_email
from app.utils.security_signals import extract_auth_headers, parse_dmarc, parse_dkim, parse_spf
from app.utils import virustotal

_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_URL_RE = re.compile(r"https?://[^\s<>\"']+")


def _extract_iocs(text: str) -> dict:
    return {
        "ips": list(set(_IP_RE.findall(text))),
        "urls": list(set(_URL_RE.findall(text))),
    }


def _hash_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


async def _classify_with_claude(body: str) -> tuple[str, str]:
    if not settings.CLAUDE_API_KEY:
        # Keyword fallback when no API key is configured
        lower = body.lower()
        if any(k in lower for k in ("malware", "trojan", "ransomware", "virus", "payload")):
            return "Malware", "Keyword-based fallback: malware terms detected."
        if any(k in lower for k in ("credential", "password", "login", "verify your account", "reset your password")):
            return "Credential Stealing", "Keyword-based fallback: credential-harvesting terms detected."
        return "Commercial", "Keyword-based fallback: no threat indicators found."

    client = anthropic.AsyncAnthropic(api_key=settings.CLAUDE_API_KEY)
    prompt = (
        "Classify this email body as exactly one of: Commercial, Credential Stealing, or Malware.\n"
        "Return only a JSON object with keys 'classification' and 'reasoning'.\n\n"
        f"Email body:\n{body[:4000]}"
    )
    message = await client.messages.create(
        model=settings.CLAUDE_MODEL,
        max_tokens=256,
        messages=[{"role": "user", "content": prompt}],
    )
    raw = message.content[0].text.strip()
    # Strip markdown code fences if Claude wrapped the JSON
    cleaned = re.sub(r"^```(?:json)?\s*|\s*```$", "", raw, flags=re.DOTALL).strip()
    try:
        result = json.loads(cleaned)
        return result["classification"], result["reasoning"]
    except Exception:
        lower = cleaned.lower()
        if "malware" in lower:
            return "Malware", cleaned
        if "credential" in lower:
            return "Credential Stealing", cleaned
        return "Commercial", cleaned


def _score(dmarc: str, spf: str, dkim: str, classification: str, vt_hits: list) -> int:
    score = 0
    if dmarc == "fail":
        score += 25
    if spf == "fail":
        score += 15
    if dkim == "none":
        score += 10
    if classification == "Malware":
        score += 35
    elif classification == "Credential Stealing":
        score += 25
    malicious_hits = sum(1 for h in vt_hits if h.get("malicious"))
    score += min(malicious_hits * 15, 30)
    return min(score, 100)


def _risk_label(score: int) -> str:
    if score < 30:
        return "low"
    if score < 70:
        return "medium"
    return "high"


async def process_email(data: dict) -> dict:
    raw_content: str = data.get("raw_content", "")
    body: str = data.get("body", "")
    attachments: list = data.get("attachments", [])

    message = parse_raw_email(raw_content) if raw_content else None

    # Prefer body extracted from raw email; fall back to the field sent directly
    if message and not body:
        body_part = message.get_body(preferencelist=("plain",))
        if body_part:
            body = body_part.get_content()

    # Auth header signals
    auth_headers = extract_auth_headers(message) if message else {}
    dmarc = parse_dmarc(auth_headers.get("authentication_results", ""))
    spf = parse_spf(auth_headers.get("received_spf", ""))
    dkim = parse_dkim(auth_headers.get("dkim_signature", ""))

    # AI classification (async, non-blocking)
    classification, reasoning = await _classify_with_claude(body)

    # IOC extraction across both raw and plain body
    iocs = _extract_iocs((raw_content + " " + body).strip())

    # Hash actual attachment bytes (skip entries with no content)
    attachment_hashes: list[str] = []
    for att in attachments:
        content_b64 = att.get("content_b64") if isinstance(att, dict) else getattr(att, "content_b64", None)
        if content_b64:
            try:
                attachment_hashes.append(_hash_bytes(base64.b64decode(content_b64)))
            except Exception:
                pass

    # VirusTotal checks — run concurrently, cap at 5 URLs + all hashes
    vt_tasks = [virustotal.check_url(url) for url in iocs["urls"][:5]]
    vt_tasks += [virustotal.check_hash(h) for h in attachment_hashes]
    vt_results = await asyncio.gather(*vt_tasks, return_exceptions=True)
    vt_hits = [r for r in vt_results if isinstance(r, dict)]

    score = _score(dmarc, spf, dkim, classification, vt_hits)

    return {
        "score": score,
        "risk_level": _risk_label(score),
        "dmarc_status": dmarc,
        "spf_status": spf,
        "dkim_status": dkim,
        "ai_classification": classification,
        "ai_reasoning": reasoning,
        "iocs": iocs,
        "virustotal_hits": vt_hits,
        "attachment_hashes": attachment_hashes,
    }
