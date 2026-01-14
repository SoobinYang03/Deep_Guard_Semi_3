from fastapi import APIRouter, HTTPException, Query
from typing import List, Optional
from datetime import datetime, timedelta

from ..models import ScanResult, PortReport, ScanStatus

router = APIRouter()

@router.get("/list")
async def list_scans(
    status: Optional[ScanStatus] = None,
    target_ip: Optional[str] = None,
    limit: int = Query(50, le=100),
    skip: int = 0
):
    """
    스캔 결과 목록 조회
    """
    query = {}
    
    if status:
        query['status'] = status
    if target_ip:
        query['target_ip'] = target_ip
    
    scans = await ScanResult.find(query).sort("-created_at").skip(skip).limit(limit).to_list()
    
    return {
        "total": len(scans),
        "scans": [
            {
                "scan_id": scan.scan_id,
                "target_ip": scan.target_ip,
                "status": scan.status,
                "created_at": scan.created_at,
                "completed_at": scan.completed_at,
                "total_ports": scan.total_ports,
                "open_ports": scan.open_ports
            }
            for scan in scans
        ]
    }

@router.get("/{scan_id}/port/{port}")
async def get_port_details(scan_id: str, port: int):
    """
    특정 포트의 상세 정보 조회
    """
    port_report = await PortReport.find_one(
        PortReport.scan_id == scan_id,
        PortReport.port == port
    )
    
    if not port_report:
        raise HTTPException(status_code=404, detail="포트 리포트를 찾을 수 없습니다.")
    
    return port_report.dict()

@router.get("/statistics/summary")
async def get_statistics(days: int = Query(7, le=30)):
    """
    통계 정보 조회
    """
    start_date = datetime.now() - timedelta(days=days)
    
    total_scans = await ScanResult.find(
        ScanResult.created_at >= start_date
    ).count()
    
    completed_scans = await ScanResult.find(
        ScanResult.created_at >= start_date,
        ScanResult.status == ScanStatus.COMPLETED
    ).count()
    
    # 위험한 포트 TOP 10
    pipeline = [
        {"$match": {"scanned_at": {"$gte": start_date}}},
        {"$group": {
            "_id": "$port",
            "count": {"$sum": 1},
            "avg_risk": {"$avg": "$risk_score"}
        }},
        {"$sort": {"avg_risk": -1}},
        {"$limit": 10}
    ]
    
    # PyMongo 컬렉션 직접 사용
    collection = PortReport.get_pymongo_collection()
    cursor = collection.aggregate(pipeline)
    risky_ports = await cursor.to_list(length=None)
    
    return {
        "period_days": days,
        "total_scans": total_scans,
        "completed_scans": completed_scans,
        "success_rate": round(completed_scans / total_scans * 100, 2) if total_scans > 0 else 0,
        "risky_ports": [
            {
                "port": item["_id"],
                "scan_count": item["count"],
                "avg_risk_score": round(item["avg_risk"], 2)
            }
            for item in risky_ports
        ]
    }

@router.get("/export/{scan_id}")
async def export_scan_report(scan_id: str):
    """
    스캔 결과 전체 내보내기 (JSON)
    """
    scan_result = await ScanResult.find_one(ScanResult.scan_id == scan_id)
    
    if not scan_result:
        raise HTTPException(status_code=404, detail="스캔 ID를 찾을 수 없습니다.")
    
    return {
        "scan_id": scan_result.scan_id,
        "target_ip": scan_result.target_ip,
        "created_at": scan_result.created_at,
        "reports": scan_result.reports
    }
