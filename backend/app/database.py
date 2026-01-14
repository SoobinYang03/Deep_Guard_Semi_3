from motor.motor_asyncio import AsyncIOMotorClient
from beanie import init_beanie
import logging
import os
from pathlib import Path
from dotenv import load_dotenv

from .models import ScanResult, PortReport

# backend/.env 파일 경로 지정
env_path = Path(__file__).parent.parent / '.env'
load_dotenv(dotenv_path=env_path)

logger = logging.getLogger(__name__)

# MongoDB 클라이언트
client: AsyncIOMotorClient = None

async def init_db():
    """MongoDB 연결 초기화"""
    global client
    
    mongodb_url = os.getenv("MONGODB_URL", "mongodb://localhost:27017")
    db_name = os.getenv("DB_NAME", "deepguard")
    
    try:
        logger.info(f"MongoDB 연결 시도: {mongodb_url}")
        client = AsyncIOMotorClient(mongodb_url)
        
        # Beanie 초기화
        await init_beanie(
            database=client[db_name],
            document_models=[ScanResult, PortReport]
        )
        
        logger.info("MongoDB 연결 성공")
    except Exception as e:
        logger.error(f"MongoDB 연결 실패: {e}")
        raise

async def close_db():
    """MongoDB 연결 종료"""
    global client
    if client:
        client.close()
        logger.info("MongoDB 연결 종료")

def get_database():
    """데이터베이스 인스턴스 반환"""
    return client[os.getenv("DB_NAME", "deepguard")]
