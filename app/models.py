from datetime import datetime, timezone


def job_doc(job_id: str) -> dict:
    now = datetime.now(timezone.utc)
    return {
        "_id": job_id,
        "status": "pending",
        "report": None,
        "error": None,
        "created_at": now,
        "updated_at": now,
    }
