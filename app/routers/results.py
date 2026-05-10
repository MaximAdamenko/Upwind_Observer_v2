from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.auth import verify_api_key
from app.database import get_db
from app.models import Job
from app.schemas import ResultResponse

router = APIRouter()


@router.get("/results/{job_id}", response_model=ResultResponse)
def get_result(
    job_id: str,
    db: Session = Depends(get_db),
    _: str = Depends(verify_api_key),
) -> ResultResponse:
    job = db.query(Job).filter(Job.id == job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return ResultResponse(status=job.status, report=job.report, error=job.error)
