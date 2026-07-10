import os
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api.routers.scans import router as scans_router
from database import init_db

DEFAULT_CORS_ORIGINS = "http://localhost:3000,http://localhost:5173,http://127.0.0.1:3000,http://127.0.0.1:5173"


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None]:
    init_db()
    yield


app = FastAPI(
    title="SecuritScanner API",
    description=(
        "REST API for SecuritScanner - a from-scratch Python web security scanner "
        "(crawler + passive header analysis + 14 active vulnerability scanners). "
        "Every scan runs the same pipeline as `python main.py`; see CLAUDE.md for "
        "the underlying architecture."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

cors_origins = [origin.strip() for origin in os.environ.get("CORS_ORIGINS", DEFAULT_CORS_ORIGINS).split(",") if origin.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(scans_router)


@app.get("/health", tags=["meta"], summary="Liveness check")
def health() -> dict[str, str]:
    return {"status": "ok"}
