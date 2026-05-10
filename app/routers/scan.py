import logging
import uuid

from fastapi import APIRouter, BackgroundTasks, Depends
from sqlalchemy.orm import Session

from app.auth import verify_api_key
from app.database import SessionLocal, get_db
from app.models import Job
from app.schemas import ScanRequest, ScanResponse
from app.tasks import process_email

logger = logging.getLogger(__name__)
router = APIRouter()


async def _run_job(job_id: str, data: dict) -> None:
    db: Session = SessionLocal()
    try:
        job = db.query(Job).filter(Job.id == job_id).first()
        report = await process_email(data)
        job.status = "completed"
        job.report = report
        db.commit()
    except Exception as exc:
        logger.exception("Job %s failed", job_id)
        try:
            job.status = "failed"
            job.error = str(exc)
            db.commit()
        except Exception:
            pass
    finally:
        db.close()


@router.post("/scan", response_model=ScanResponse)
async def submit_scan(
    request: ScanRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    _: str = Depends(verify_api_key),
) -> ScanResponse:
    job_id = str(uuid.uuid4())
    db.add(Job(id=job_id, status="pending"))
    db.commit()
    background_tasks.add_task(_run_job, job_id, request.model_dump())
    return ScanResponse(job_id=job_id)
