import socket
import json
from concurrent.futures import ThreadPoolExecutor
import nmap
import os
import shodan
import asyncio
import aiohttp
import logging
from Wappalyzer import Wappalyzer, WebPage
from scapy.all import AsyncSniffer, wrpcap
from webdriver_manager.chrome import ChromeDriverManager
from datetime import datetime

#로그 남기기
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler("deepguard.log", encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

#스캔 클래스
class PortScanner:
    def __init__(self):
        try:
            self.nm = nmap.PortScanner()
        except Exception:
            logger.error("nmap 에러. 환경 변수를 확인하세요.")
            self.nm = None

    #스캔설정. 비동기로 연결하여 작업속도를 높임.
    async def scan_port_setting(self, target_ip, port):
        try:
            conn = asyncio.open_connection(target_ip, port)
            _, writer = await asyncio.wait_for(conn, timeout=1.0)
            writer.close()
            await writer.wait_closed()
            return port, "open", "syn-ack"
        except:
            return port, "closed", "timeout/rst"

    #메인스캔방식. Nmap활용 SYN스캔
    def scan_syn(self, target_ip, port):
        if not self.nm: return "error"

        try:
            self.nm.scan(target_ip, str(port), arguments='-sS -Pn --host-timeout 2s')
            if target_ip in self.nm.all_hosts():
                return self.nm[target_ip]['tcp'][port]['state']
            return "error"

        except Exception:
            return "error"

    #보조스캔방식. 소켓활용 TCP Connect스캔
    async def scan_tcp_connect(self, target_ip, port):

        try:
            conn = asyncio.open_connection(target_ip, port)
            _, writer = await asyncio.wait_for(conn, timeout=1.0)
            writer.close()
            await writer.wait_closed()
            return "open"
        except:
            return "closed"

#식별 클래스
class ServiceIdentifier:
    def __init__(self):
        self.nm = nmap.PortScanner()

    #식별API1. Nmap기반. 서비스 및 OS 식별
    def port_identification(self, target_ip, port):

        try:
            self.nm.scan(target_ip, str(port), arguments = '-sV')
            if target_ip not in self.nm.all_hosts() or 'tcp' not in self.nm[target_ip]:
                return {"version": "unknown", "product": "unknown", "banner": ""}

            service_info = self.nm[target_ip]['tcp'][port]
            return {
                "version": service_info.get('version', 'unknown'),
                "product": service_info.get('product', 'unknown'),
                "banner": service_info.get('extrainfo', '')
            }
        except Exception as e:
            logger.warning(f"Nmap 식별 실패 ({port}): {e}")
            return {"version": "식별 실패", "product": "unknown"}

#분석 클래스
class SecurityAnalyzer:
    SHODAN_API_KEY="ey5rlzjZfdldErPb61eux6tcQNWt46GI"
    VT_API_KEY="7ee00e4cace9e08500d05eada843603a1afd05636c11de9dabe0c950270a8e7b"

    def __init__(self):
        os.environ['WDM_LOG_LEVEL'] = '0'
        logger.info("6조 Deepguard 세미프로젝트 3차.")
        self.driver_path = ChromeDriverManager().install()

    #분석API1. Nuclei도구를 사용, CVE데이터 매칭
    async def port_vulnerability(self, target_ip, port, product):

        vulnerabilities = []
        cmd = [
            "nuclei",
            "-target", target_ip,
            "-p", str(port),
            "-tags", "cve",
            "-silent",
            "-jsonl",
            "-ni"
        ]

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()

            if stdout:
                for line in stdout.decode().strip().split('\n'):
                    if not line: continue
                    data = json.loads(line)

                    vulnerabilities.append({
                        "id": data.get("template-id", "Unknown"),
                        "severity": data.get("info", {}).get("severity", "info").capitalize(),
                        "description": data.get("info", {}).get("description", "설명 없음"),
                        "name": data.get("info", {}).get("name", ""),
                        "reference": data.get("info", {}).get("reference", [])
                    })

            if not vulnerabilities and product != "unknown":
                vulnerabilities.append({
                    "id": "info-service",
                    "severity": "info",
                    "description": f"nuclei 탐지 결과 없음 ({product} 서비스 작동 중)"
                })

        except FileNotFoundError:
            logger.error("nuclei가 시스템에 설치되어 있지 않습니다. 환경변수 확인 필요")
        except Exception as e:
            logger.error(f"nuclei 실행 중 오류 발생: {e}")

        return vulnerabilities

    #분석API2. shodan OSINT데이터 활용. 외부에 노출된 적이 있나 확인
    def match_shodan(self, target_ip):
        try:
            api = shodan.Shodan(SecurityAnalyzer.SHODAN_API_KEY)
            host = api.host(target_ip)

            return {
                "shodan_exposed": True,
                "org": host.get('org', 'N/A'),
                "os": host.get('os', 'N/A'),
                "tags": host.get('tags', []),
                "is_vpn": "vpn" in str(host.get('tags', [])).lower()
            }

        except shodan.APIError as e:
            return {"shodan_exposed": False, "error": str(e)}

    #분석API3. EPSS API를 통해서 실제로 공격이 발생할 확률을 조회
    @staticmethod
    async def get_epss_score(session, cve_id):
        try:
            #first.org 의 공식 API를 호출해서 조회
            url = f"https://api.first.org/data/v1/epss?cve={cve_id}"
            async with session.get(url, timeout=5) as response:
                if response.status == 200:
                    data = await response.json()
                    if data.get('data'):
                        return float(data['data'][0].get('epss', 0.0))
                return 0.0
        except Exception as e:
            logger.error(f"EPSS 조회 에러 ({cve_id}): {e}")
            return 0.0

    #분석API4. VirusTotal 사용. IP평판 및 히스토리 분석
    async def match_virustotal(self, session, target_ip):
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{target_ip}"
        headers = {"x-apikey": SecurityAnalyzer.VT_API_KEY}

        try:
            async with session.get(url, headers=headers) as response:
                if response.status == 200:
                    data = await response.json()
                    stats = data['data']['attributes']['last_analysis_stats']
                    malicious_count = stats.get('malicious', 0)

                    return {
                        "reputation": "Malicious" if malicious_count > 0 else "Clean",
                        "malicious_hits": malicious_count,
                        "total_engines": sum(stats.values()),
                    }
            return {"reputation": "no data", "malicious_hits": 0}
        except Exception as e:
            logger.error(f"바이러스토탈 조회 실패: {e}")
            return {"reputation": "error", "malicious_hits": 0}

#증거 클래스
class EvidenceCollector:
    def __init__(self):
        # Wappalyzer 엔진 초기화 (최신 기술 정의 로드)
        try:
            self.wappalyzer = Wappalyzer.latest()
            logger.info("Wappalyzer 엔진 로드 완료")
        except Exception as e:
            logger.error(f"Wappalyzer 초기화 실패: {e}")
            self.wappalyzer = None

        self.sniffer_dict = {}  # 포트별 스니퍼 관리를 위한 딕셔너리
    #증거 저장 위치
    def save_evidence_dir(self, port):
        path = os.path.join("evidence", str(port))
        if not os.path.exists(path):
            os.makedirs(path)
        return path
    #웹서비스일경우, 메타데이터 수집
    def collect_web_metadata(self, target_ip, port):
        save_dir = self.save_evidence_dir(port)
        url = f"http://{target_ip}:{port}"

        try:
            webpage = WebPage.new_from_url(url, timeout=5)
            tech_data = self.wappalyzer.analyze_with_versions(webpage)

            file_path = os.path.join(save_dir, "tech_stack.json")
            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(tech_data, f, indent=4, ensure_ascii=False)

            logger.info(f"웹 메타데이터 저장 완료: {file_path}")
            return tech_data
        except Exception as e:
            logger.warning(f"웹 메타데이터 수집 실패 ({port}): {e}")
            return None
    #웹서비스가 아닐 경우, 우선 TCP캡쳐
    def start_packet_capture(self, target_ip, port):
        try:
            filter_str = f"host {target_ip} and port {port}"
            sniffer = AsyncSniffer(filter=filter_str)
            sniffer.start()
            self.sniffer_dict[port] = sniffer
            logger.info(f"포트 {port} 패킷 캡처 시작")
        except Exception as e:
            logger.error(f"패킷 캡처 시작 실패: {e}")

    def stop_packet_capture(self, port):
        sniffer = self.sniffer_dict.get(port)
        if not sniffer:
            return None

        try:
            sniffer.stop()
            packets = sniffer.results
            if packets:
                save_dir = self.save_evidence_dir(port)
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                file_path = os.path.join(save_dir, f"traffic_{timestamp}.pcap")
                wrpcap(file_path, packets)
                logger.info(f"PCAP 저장 완료: {file_path}")
                return file_path
        except Exception as e:
            logger.error(f"PCAP 저장 실패: {e}")
        finally:
            if port in self.sniffer_dict:
                del self.sniffer_dict[port]
        return None
    #TCP캡쳐에서 배너 로그를 추출
    def save_banner_log(self, port, identified_data):
        save_dir = self.save_evidence_dir(port)
        file_path = os.path.join(save_dir, "banner_info.txt")

        try:
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(f"Timestamp: {datetime.now()}\n")
                f.write(f"Port: {port}\n")
                f.write(f"Product: {identified_data.get('product', 'unknown')}\n")
                f.write(f"Version: {identified_data.get('version', 'unknown')}\n")
                f.write(f"Raw Banner: {identified_data.get('banner', '')}\n")
            return file_path
        except Exception as e:
            logger.error(f"배너 로그 저장 실패: {e}")
            return None


#스키마 클래스
class ReportSchema:
    @staticmethod
    async def json_result(session, target_ip, scan_mode, port, identified_data, vulns, intel, reputation, evidence):

        if vulns:
            tasks = [SecurityAnalyzer.get_epss_score(session, v['id']) for v in vulns]
            epss_scores = await asyncio.gather(*tasks)

            for v, score in zip(vulns, epss_scores):
                v['epss'] = score

            max_epss = max(epss_scores) if epss_scores else 0.0
        else:
            max_epss = 0.0

        cvss_base = 7.5 if vulns else 0.0
        final_score = (cvss_base * 0.6) + (max_epss * 10 * 0.4)

        return {
            "scan_metadata": {
                "target_ip": target_ip,
                "scan_mode": scan_mode,
                "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            },
            "summary": {
                "port": port,
                "protocol": "TCP",
                "service_name": identified_data.get('product', 'unknown'),
                "risk_score": round(final_score, 2),
                "risk_level": "위험" if final_score > 6.0 else "안전"
            },
            "details": {
                "service_version": f"{identified_data['product']}{identified_data['version']}",
                "os_fingerprint": "식별중.",
                "cve_list": vulns,
                "shodan_data": intel,
                "reputation_data": reputation,
                "remediation": "최신 보안패치 적용을 권장합니다."
            },
            "evidence": {
                "is_web": evidence.get('is_web', False),
                "tech_stack": evidence.get('tech_stack'),
                "pcap_path": evidence.get('pcap_path'),
                "raw_log": identified_data.get('banner', f"Port {port} active")
            }
        }

#조작 클래스
class DeepguardController:
    def __init__(self):
        self.scanner = PortScanner()
        self.identifier = ServiceIdentifier()
        self.analyzer = SecurityAnalyzer()
        self.evidence = EvidenceCollector()
        self.executor = ThreadPoolExecutor(max_workers=10)
        self.shodan_api = shodan.Shodan(self.analyzer.SHODAN_API_KEY)
        self.browser_semaphore = asyncio.Semaphore(2)


    async def process_target_port(self, target_ip, port):

        loop = asyncio.get_event_loop()

        status = await loop.run_in_executor(self.executor, self.scanner.scan_syn, target_ip, port)

        if status == "error":
            logger.info(f"{port} SYN스캔 에러. TCP Connect스캔으로 전환.")
            status = await self.scanner.scan_tcp_connect(target_ip, port)

        if status == "open":
            logger.info(f"발견한 포트 번호{port} 분석 시작")

            await loop.run_in_executor(None, self.evidence.start_packet_capture, target_ip, port)

            async with aiohttp.ClientSession() as session:
                # 식별클래스 호출
                identified_data = await loop.run_in_executor(None, self.identifier.port_identification, target_ip, port)
                # 분석클래스 호출
                # 내부 취약점
                vulns = await self.analyzer.port_vulnerability(target_ip, port, identified_data['product'])
                # 외부 OSINT
                try:
                    intel = await loop.run_in_executor(None, self.shodan_api.host, target_ip)
                except:
                    intel = {"shodan_exposed": False}
                # 히스토리 및 평판
                reputation = await self.analyzer.match_virustotal(session, target_ip)
                # 동적 웹서비스 판별, 증거수집
                is_web = "http" in identified_data['product'].lower() or port in [80, 443]
                tech_stack = None

                if is_web:
                    # 웹 서비스일 경우 Wappalyzer 메타데이터 수집
                    tech_stack = await loop.run_in_executor(None, self.evidence.collect_web_metadata, target_ip, port)
                else:
                    # 웹이 아닐 경우 배너 로그 별도 저장
                    await loop.run_in_executor(None, self.evidence.save_banner_log, port, identified_data)

                # 분석 종료 후 패킷 캡처 중지 및 PCAP 저장
                pcap_path = await loop.run_in_executor(None, self.evidence.stop_packet_capture, port)

                #증거데이터 1차 정리
                evidence = {
                    "is_web": is_web,
                    "tech_stack": tech_stack,
                    "pcap_path": pcap_path
                }

                # 스키마클래스 호출
                report = await ReportSchema.json_result(session, target_ip, "SYN_SCAN", port, identified_data, vulns, intel, reputation, evidence)
                return report
        return None

    async def main_controller(self, target_ip, port_range=None):

        loop = asyncio.get_event_loop()

        if port_range is None:
            logger.info(f"{target_ip} 에 대한 열린 포트 자동 탐색")
            try:
                await loop.run_in_executor(
                    self.executor,
                    lambda: self.scanner.nm.scan(target_ip, arguments='--top-ports 65535 -F')
                )

                discovered_ports = []
                if target_ip in self.scanner.nm.all_hosts():
                    for proto in self.scanner.nm[target_ip].all_protocols():
                        lport = self.scanner.nm[target_ip][proto].keys()
                        for port in lport:
                            if self.scanner.nm[target_ip][proto][port]['state'] == 'open':
                                discovered_ports.append(port)

                port_range = discovered_ports
                if not port_range:
                    logger.info("열린 포트를 미발견")
                    return []

                logger.info(f"자동 탐색 결과 발견된 포트: {port_range}")

            except Exception as e:
                logger.error(f"자동 탐색 중 오류 발생. 기본 포트 탐지. {e}")

                port_range = [80, 443, 3306, 3389, 8080]

        logger.info(f"Target {target_ip} 에 대해 {len(port_range)}개 포트 상세 분석 시작...")

        tasks = [self.process_target_port(target_ip, p) for p in port_range]
        results = await asyncio.gather(*tasks)

        final_reports = [r for r in results if r]
        final_reports.sort(key=lambda x: x['summary']['risk_score'], reverse=True)

        return final_reports





if __name__ == "__main__":
    controller = DeepguardController()
    final_output = asyncio.run(controller.main_controller("127.0.0.1"))
    formatted_output = json.dumps(final_output, indent=4, ensure_ascii=False)
    print(f"최종 리포트 요약.\n{formatted_output}\n")

