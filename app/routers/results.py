from fastapi import APIRouter, Depends, HTTPException
from motor.motor_asyncio import AsyncIOMotorCollection

from app.auth import verify_api_key
from app.database import get_jobs_collection
from app.schemas import ResultResponse

router = APIRouter()


@router.get("/results/{job_id}", response_model=ResultResponse)
async def get_result(
    job_id: str,
    col: AsyncIOMotorCollection = Depends(get_jobs_collection),
    _: str = Depends(verify_api_key),
) -> ResultResponse:
    job = await col.find_one({"_id": job_id})
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return ResultResponse(status=job["status"], report=job.get("report"), error=job.get("error"))
