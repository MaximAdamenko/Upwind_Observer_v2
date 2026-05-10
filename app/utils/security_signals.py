from email.message import EmailMessage
from app.utils.email_parser import get_header


def extract_auth_headers(message: EmailMessage) -> dict:
    return {
        "authentication_results": get_header(message, "Authentication-Results"),
        "received_spf": get_header(message, "Received-SPF"),
        "dkim_signature": get_header(message, "DKIM-Signature"),
    }


def parse_dmarc(auth_results: str) -> str:
    if not auth_results:
        return "none"
    return "pass" if "dmarc=pass" in auth_results.lower() else "fail"


def parse_spf(spf_header: str) -> str:
    if not spf_header:
        return "none"
    return "pass" if "pass" in spf_header.lower() else "fail"


def parse_dkim(dkim_signature: str) -> str:
    return "pass" if dkim_signature else "none"
