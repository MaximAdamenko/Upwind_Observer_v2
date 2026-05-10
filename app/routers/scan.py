import logging
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, BackgroundTasks, Depends
from motor.motor_asyncio import AsyncIOMotorCollection

from app.auth import verify_api_key
from app.database import get_jobs_collection
from app.models import job_doc
from app.schemas import ScanRequest, ScanResponse
from app.tasks import process_email

logger = logging.getLogger(__name__)
router = APIRouter()


async def _run_job(job_id: str, data: dict) -> None:
    col = get_jobs_collection()
    try:
        report = await process_email(data)
        await col.update_one(
            {"_id": job_id},
            {"$set": {"status": "completed", "report": report, "updated_at": datetime.now(timezone.utc)}},
        )
    except Exception as exc:
        logger.exception("Job %s failed", job_id)
        await col.update_one(
            {"_id": job_id},
            {"$set": {"status": "failed", "error": str(exc), "updated_at": datetime.now(timezone.utc)}},
        )


@router.post("/scan", response_model=ScanResponse)
async def submit_scan(
    request: ScanRequest,
    background_tasks: BackgroundTasks,
    col: AsyncIOMotorCollection = Depends(get_jobs_collection),
    _: str = Depends(verify_api_key),
) -> ScanResponse:
    job_id = str(uuid.uuid4())
    await col.insert_one(job_doc(job_id))
    background_tasks.add_task(_run_job, job_id, request.model_dump())
    return ScanResponse(job_id=job_id)
