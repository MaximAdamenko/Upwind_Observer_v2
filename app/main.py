from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.database import Base, engine
from app.routers import results, scan

Base.metadata.create_all(bind=engine)

app = FastAPI(title="Upwind Observer", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type"],
)

app.include_router(scan.router, prefix="/v1")
app.include_router(results.router, prefix="/v1")


@app.get("/")
def health() -> dict:
    return {"status": "ok", "service": "Upwind Observer"}
