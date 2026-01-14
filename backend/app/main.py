from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import logging

from .database import init_db, close_db
from .routes import scan_router, report_router

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@asynccontextmanager
async def lifespan(app: FastAPI):
    # 시작 시 실행
    logger.info("FastAPI 서버 시작 중...")
    await init_db()
    yield
    # 종료 시 실행
    logger.info("FastAPI 서버 종료 중...")
    await close_db()

app = FastAPI(
    title="DeepGuard Security Scanner API",
    version="1.0.0",
    description="포트 스캔 및 보안 분석 API",
    lifespan=lifespan
)

# CORS 설정
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # 프로덕션에서는 특정 도메인만 허용
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 라우터 등록
app.include_router(scan_router.router, prefix="/api/v1/scan", tags=["Scan"])
app.include_router(report_router.router, prefix="/api/v1/report", tags=["Report"])

@app.get("/")
async def root():
    return {
        "service": "DeepGuard Scanner API",
        "version": "1.0.0",
        "status": "running"
    }

@app.get("/health")
async def health_check():
    return {"status": "healthy"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
