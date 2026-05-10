import email
from email import policy
from email.message import EmailMessage
from typing import Optional


def parse_raw_email(raw_content: str) -> Optional[EmailMessage]:
    try:
        return email.message_from_string(raw_content, policy=policy.default)
    except Exception:
        return None


def get_header(message: EmailMessage, name: str, default: str = "") -> str:
    value = message.get(name)
    return str(value) if value else default
