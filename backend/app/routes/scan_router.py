from fastapi import APIRouter, HTTPException, BackgroundTasks
from typing import List
import asyncio
import uuid
import sys
import os

# deepguard_portscanner.py 임포트를 위한 경로 설정
# backend/app/routes/ -> backend/ -> 프로젝트 루트
root_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..'))
if root_path not in sys.path:
    sys.path.insert(0, root_path)

from deepguard_portscanner import DeepguardController, logger as scan_logger
from ..models import (
    ScanRequest, 
    ScanResponse, 
    ScanStatus,
    ScanResult,
    PortReport,
    VulnerabilityInfo,
    ReputationData,
    ShodanData,
    EvidenceData
)

router = APIRouter()

@router.post("/start", response_model=ScanResponse)
async def start_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    """
    비동기 포트 스캔 시작
    """
    try:
        # 고유 스캔 ID 생성
        scan_id = str(uuid.uuid4())
        
        # DB에 스캔 레코드 생성
        scan_result = ScanResult(
            scan_id=scan_id,
            target_ip=request.target_ip,
            status=ScanStatus.PENDING,
            description=request.description
        )
        await scan_result.insert()
        
        # 백그라운드 작업으로 스캔 실행
        background_tasks.add_task(
            run_background_scan,
            scan_id,
            request.target_ip,
            request.port_range
        )
        
        return ScanResponse(
            scan_id=scan_id,
            message="스캔이 시작되었습니다.",
            target_ip=request.target_ip,
            status=ScanStatus.PENDING
        )
    
    except Exception as e:
        scan_logger.error(f"스캔 시작 실패: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/{scan_id}")
async def get_scan_status(scan_id: str):
    """
    스캔 상태 조회
    """
    scan_result = await ScanResult.find_one(ScanResult.scan_id == scan_id)
    
    if not scan_result:
        raise HTTPException(status_code=404, detail="스캔 ID를 찾을 수 없습니다.")
    
    return {
        "scan_id": scan_result.scan_id,
        "target_ip": scan_result.target_ip,
        "status": scan_result.status,
        "created_at": scan_result.created_at,
        "completed_at": scan_result.completed_at,
        "total_ports": scan_result.total_ports,
        "open_ports": scan_result.open_ports,
        "error_message": scan_result.error_message
    }

@router.delete("/{scan_id}")
async def delete_scan(scan_id: str):
    """
    스캔 결과 삭제
    """
    scan_result = await ScanResult.find_one(ScanResult.scan_id == scan_id)
    
    if not scan_result:
        raise HTTPException(status_code=404, detail="스캔 ID를 찾을 수 없습니다.")
    
    # 관련 포트 리포트도 삭제
    await PortReport.find(PortReport.scan_id == scan_id).delete()
    await scan_result.delete()
    
    return {"message": "스캔 결과가 삭제되었습니다.", "scan_id": scan_id}

async def run_background_scan(scan_id: str, target_ip: str, port_range: List[int] = None):
    """
    백그라운드에서 스캔 실행
    """
    scan_result = await ScanResult.find_one(ScanResult.scan_id == scan_id)
    
    try:
        # 스캔 상태 업데이트
        scan_result.status = ScanStatus.RUNNING
        await scan_result.save()
        
        # DeepGuard 스캐너 실행
        controller = DeepguardController()
        results = await controller.main_controller(target_ip, port_range)
        
        # 결과 저장
        open_ports = 0
        port_reports = []
        
        for report in results:
            if report:
                open_ports += 1
                
                # 안전하게 데이터 추출
                try:
                    # 개별 포트 리포트 생성
                    port_report = PortReport(
                        scan_id=scan_id,
                        target_ip=target_ip,
                        port=report.get('summary', {}).get('port', 0),
                        protocol=report.get('summary', {}).get('protocol', 'TCP'),
                        service_name=report.get('summary', {}).get('service_name', 'unknown'),
                        service_version=report.get('details', {}).get('service_version', ''),
                        risk_score=report.get('summary', {}).get('risk_score', 0.0),
                        risk_level=report.get('summary', {}).get('risk_level', '안전'),
                        vulnerabilities=[
                            VulnerabilityInfo(**v) 
                            for v in report.get('details', {}).get('cve_list', [])
                        ],
                        shodan_data=ShodanData(
                            **report.get('details', {}).get('shodan_data', {
                                'shodan_exposed': False
                            })
                        ),
                        reputation_data=ReputationData(
                            **report.get('details', {}).get('reputation_data', {
                                'reputation': 'unknown',
                                'malicious_hits': 0
                            })
                        ),
                        evidence=EvidenceData(
                            **report.get('evidence', {
                                'is_web': False,
                                'screenshot_path': None
                            })
                        )
                    )
                    await port_report.insert()
                    port_reports.append(report)
                    
                except Exception as e:
                    scan_logger.error(f"포트 리포트 저장 실패 (port {report.get('summary', {}).get('port', '?')}): {e}")
                    continue
        
        # 스캔 결과 업데이트
        from datetime import datetime
        scan_result.status = ScanStatus.COMPLETED
        scan_result.completed_at = datetime.now()
        scan_result.scan_mode = "SYN_SCAN"
        scan_result.total_ports = len(results)
        scan_result.open_ports = open_ports
        scan_result.reports = port_reports  # 성공적으로 저장된 리포트만 저장
        await scan_result.save()
        
        scan_logger.info(f"스캔 완료: {scan_id} (총 {len(results)}개 포트, {open_ports}개 열림)")
    
    except Exception as e:
        scan_logger.error(f"백그라운드 스캔 실패 ({scan_id}): {e}")
        
        from datetime import datetime
        scan_result.status = ScanStatus.FAILED
        scan_result.completed_at = datetime.now()
        scan_result.error_message = str(e)
        await scan_result.save()
