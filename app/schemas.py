from typing import Any, Optional
from pydantic import BaseModel, Field


class Attachment(BaseModel):
    filename: str
    content_b64: Optional[str] = None  # base64-encoded file bytes


class ScanRequest(BaseModel):
    raw_content: str = ""           # RFC2822 raw email (preferred source)
    body: str = ""                  # plain-text body (fallback)
    attachments: list[Attachment] = Field(default_factory=list)


class ScanResponse(BaseModel):
    job_id: str


class ResultResponse(BaseModel):
    status: str
    report: Optional[dict[str, Any]] = None
    error: Optional[str] = None
