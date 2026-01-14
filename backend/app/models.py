from beanie import Document
from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime
from enum import Enum

class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"

class RiskLevel(str, Enum):
    SAFE = "안전"
    WARNING = "경고"
    DANGER = "위험"

# 요청 모델
class ScanRequest(BaseModel):
    target_ip: str
    port_range: Optional[List[int]] = None
    description: Optional[str] = None

# 취약점 정보 :cve_list
class VulnerabilityInfo(BaseModel):
    id: str
    severity: str
    description: str
    name: Optional[str] = None
    reference: Optional[List[str]] = None
    epss: Optional[float] = 0.0

# 평판 정보 : reputation_data
class ReputationData(BaseModel):
    reputation: str
    malicious_hits: int
    total_engines: Optional[int] = 0

# Shodan 정보 : shodan_data
class ShodanData(BaseModel):
    shodan_exposed: bool
    org: Optional[str] = None
    os: Optional[str] = None
    tags: Optional[List[str]] = None
    is_vpn: Optional[bool] = None
    error: Optional[str] = None

# 증거 정보 : evidence
class EvidenceData(BaseModel):
    is_web: bool
    screenshot_path: Optional[str] = None
    raw_log: Optional[str] = None

# 포트 스캔 결과 (MongoDB 문서)
class ScanResult(Document):
    scan_id: str = Field(..., unique=True, index=True)
    target_ip: str = Field(..., index=True)
    status: ScanStatus = ScanStatus.PENDING
    created_at: datetime = Field(default_factory=datetime.now)
    completed_at: Optional[datetime] = None
    description: Optional[str] = None
    
    # 스캔 메타데이터
    scan_mode: Optional[str] = None
    total_ports: int = 0
    open_ports: int = 0
    
    # 전체 리포트 (JSON)
    reports: Optional[List[dict]] = []
    
    # 에러 정보
    error_message: Optional[str] = None
    
    class Settings:
        name = "scan_results"
        indexes = [
            "scan_id",
            "target_ip",
            "status",
            "created_at"
        ]

# 개별 포트 리포트 (MongoDB 문서)
class PortReport(Document):
    scan_id: str = Field(..., index=True)
    target_ip: str
    port: int
    protocol: str = "TCP"
    
    # 서비스 정보
    service_name: str
    service_version: Optional[str] = None
    
    # 위험도
    risk_score: float = 0.0
    risk_level: str = RiskLevel.SAFE
    
    # 상세 정보
    vulnerabilities: List[VulnerabilityInfo] = []
    shodan_data: Optional[ShodanData] = None
    reputation_data: Optional[ReputationData] = None
    evidence: Optional[EvidenceData] = None
    
    # 메타
    scanned_at: datetime = Field(default_factory=datetime.now)
    
    class Settings:
        name = "port_reports"
        indexes = [
            "scan_id",
            "target_ip",
            "port",
            "risk_score"
        ]

# 응답 모델
class ScanResponse(BaseModel):
    scan_id: str
    message: str
    target_ip: str
    status: ScanStatus
