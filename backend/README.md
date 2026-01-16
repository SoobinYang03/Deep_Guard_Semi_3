# 🛡️ DeepGuard Backend API

DeepGuard 포트 스캐너를 위한 FastAPI + MongoDB 백엔드

> 비동기 포트 스캔, 취약점 분석, OSINT 정보 수집 및 리포트 생성을 제공하는 REST API

## 📋 목차

- [프로젝트 구조](#-프로젝트-구조)
- [기술 스택](#-기술-스택)
- [시작하기](#-시작하기)
- [API 엔드포인트](#-api-엔드포인트)
- [데이터 모델](#-데이터-모델)
- [사용 예시](#-사용-예시)
- [주의사항](#-주의사항)

## 📁 프로젝트 구조

```
backend/
├── app/
│   ├── __init__.py
│   ├── main.py              # FastAPI 앱 초기화, 라이프사이클 관리
│   ├── models.py            # Pydantic/Beanie 데이터 모델
│   ├── database.py          # MongoDB 연결 및 초기화
│   └── routes/
│       ├── __init__.py
│       ├── scan_router.py   # 포트 스캔 API (비동기/동기)
│       └── report_router.py # 리포트 조회 및 통계 API
├── .env                     # 환경 변수 (MongoDB URL, 보안 키 등)
├── docker-compose.yml       # MongoDB + Mongo Express
├── requirements.txt         # Python 패키지 의존성
└── README.md
```

## 🔧 기술 스택

| 구분 | 기술 |
|------|------|
| **웹 프레임워크** | FastAPI |
| **ASGI 서버** | Uvicorn |
| **데이터베이스** | MongoDB |
| **ODM** | Beanie (비동기 MongoDB ODM) |
| **검증/직렬화** | Pydantic |
| **스캔 엔진** | DeepGuard Scanner (Nmap, Nuclei, Shodan, VirusTotal) |
| **컨테이너** | Docker Compose |

## 🚀 시작하기

### 1️⃣ 사전 요구사항

- Python 3.10+
- Docker & Docker Compose
- nmap 설치 및 PATH 등록
- Nuclei 설치 및 PATH 등록
- etc...

### 2️⃣ 가상환경 설정 (프로젝트 루트에서)

```powershell
# 가상환경 생성
python -m venv venv

# 활성화
.\.venv\Scripts\Activate.ps1

# 패키지 설치
pip install -r requirements.txt
```

### 3️⃣ MongoDB 실행

```bash
cd backend
docker-compose up -d
```

**접속 정보:**
- MongoDB: `mongodb://localhost:27017`
- Mongo Express (웹 UI): http://localhost:8081
  - ID: `admin` / PW: `admin`

### 4️⃣ 환경 변수 설정

`backend/.env.example` 파일을 참고하여 `backend/.env` 파일을 생성하세요:

```powershell
cd backend
cp .env.example .env
# 또는 Windows에서
copy .env.example .env
```

생성된 `.env` 파일에서 필요한 값을 수정하세요.

### 5️⃣ FastAPI 서버 실행 (프로젝트 루트에서)

```powershell
# 개발 모드 (자동 리로드)
.\.venv\Scripts\python.exe -m uvicorn backend.app.main:app --reload --host 0.0.0.0 --port 8000
```

**접속:**
- API 서버: http://localhost:8000
- Swagger 문서: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc

## 📡 API 엔드포인트

### 🔍 스캔 API (`/api/v1/scan`)

| Method | Endpoint | 설명 |
|--------|----------|------|
| POST | `/start` | 비동기 스캔 시작 (즉시 scan_id 반환) |
| GET | `/{scan_id}` | 스캔 상태 및 진행상황 조회 |
| DELETE | `/{scan_id}` | 스캔 결과 삭제 |

### 📊 리포트 API (`/api/v1/report`)

| Method | Endpoint | 설명 |
|--------|----------|------|
| GET | `/list` | 스캔 목록 조회 (필터링, 페이징) |
| GET | `/{scan_id}/port/{port}` | 특정 포트 상세 정보 |
| GET | `/statistics/summary` | 통계 정보 (위험 포트 TOP 10 등) |
| GET | `/export/{scan_id}` | JSON 형식 결과 내보내기 |

## 💡 사용 예시

### 1️⃣ 스캔 시작

```bash
curl -X POST "http://localhost:8000/api/v1/scan/start" \
  -H "Content-Type: application/json" \
  -d '{
    "target_ip": "192.168.1.1",
    "port_range": [80, 443, 22, 3306],
    "description": "웹 서버 보안 점검"
  }'
```

**응답:**
```json
{
  "scan_id": "14e225dc-2112-40ef-b162-af96daa34612",
  "message": "스캔이 시작되었습니다.",
  "target_ip": "192.168.1.1",
  "status": "pending"
}
```

### 2️⃣ 스캔 상태 확인

```bash
curl "http://localhost:8000/api/v1/scan/14e225dc-2112-40ef-b162-af96daa34612"
```

**응답 (진행중):**
```json
{
  "scan_id": "14e225dc-2112-40ef-b162-af96daa34612",
  "status": "running",
  "target_ip": "192.168.1.1",
  "created_at": "2026-01-14T12:00:00",
  "total_ports": 4,
  "open_ports": 2
}
```

## ⚙️ 주요 기능

### ✅ 비동기 스캔 처리
- FastAPI BackgroundTasks로 장시간 스캔 비동기 실행
- 즉시 응답 후 백그라운드 처리
- 실시간 상태 조회 가능

### ✅ 통합 보안 분석
- **Nmap**: 포트 스캔 및 서비스 식별
- **Nuclei**: CVE 취약점 탐지
- **Shodan**: OSINT 정보 수집
- **VirusTotal**: IP 평판 분석
- **EPSS**: 실제 공격 확률 조회

### ✅ MongoDB 저장
- Beanie ODM으로 비동기 DB 작업
- 스캔 메타데이터 + 포트별 상세 정보 분리 저장
- 인덱스 최적화로 빠른 조회

### ✅ 데이터 검증
- Pydantic으로 타입 안전성 보장
- 자동 검증 및 직렬화
- API 문서 자동 생성

## ⚠️ 주의사항

### 1. nmap 설치 및 권한
```powershell
# nmap 설치 확인
nmap --version
```

### 2. API 키 설정
`deepguard_portscanner.py`에서 본인의 API 키로 변경:
```python
SHODAN_API_KEY = "your-shodan-key"
VT_API_KEY = "your-virustotal-key"
```

### 3. Nuclei 설치
```bash
# Go 설치 후
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest

# 또는 바이너리 다운로드
# https://github.com/projectdiscovery/nuclei/releases
```

### 4. 프로덕션 배포 시
- `.env`의 `SECRET_KEY` 변경
- CORS 설정 수정 (특정 도메인만 허용)
- MongoDB 인증 강화
- HTTPS 사용
- Rate Limiting 추가

## 🗄️ 데이터베이스 스키마

### Collections

**scan_results**: 스캔 메타데이터
- Indexes: `scan_id`, `target_ip`, `status`, `created_at`

**port_reports**: 포트별 상세 정보
- Indexes: `scan_id`, `target_ip`, `port`, `risk_score`

### Mongo Express로 확인
http://localhost:8081 접속 → `deepguard` 데이터베이스 선택