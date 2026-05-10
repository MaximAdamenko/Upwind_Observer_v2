from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorCollection
from app.config import settings

_client: AsyncIOMotorClient | None = None


def get_client() -> AsyncIOMotorClient:
    global _client
    if _client is None:
        _client = AsyncIOMotorClient(settings.MONGODB_URI)
    return _client


def get_jobs_collection() -> AsyncIOMotorCollection:
    return get_client()[settings.MONGODB_DB]["jobs"]
