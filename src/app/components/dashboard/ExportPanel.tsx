import { Card, CardContent, CardHeader, CardTitle } from "../ui/card";
import { Button } from "../ui/button";
import { Download, FileJson, FileSpreadsheet, FileCode } from "lucide-react";
import { PortDetail } from "./PortToggleCard";

interface ExportPanelProps {
  results: PortDetail[];
  scanConfig: {
    targetIp: string;
    startPort: number;
    endPort: number;
    scanType: string;
    timestamp: string;
  };
}

export function ExportPanel({ results, scanConfig }: ExportPanelProps) {
  // JSON 내보내기
  const exportToJSON = () => {
    const data = {
      scanConfig,
      timestamp: new Date().toISOString(),
      totalPorts: results.length,
      vulnerablePorts: results.filter(r => r.vulnerabilityCount > 0).length,
      results: results,
    };

    const jsonContent = JSON.stringify(data, null, 2);
    const blob = new Blob([jsonContent], { type: "application/json" });
    const link = document.createElement("a");
    const url = URL.createObjectURL(blob);
    link.setAttribute("href", url);
    link.setAttribute("download", `port_scan_detailed_${Date.now()}.json`);
    link.style.visibility = "hidden";
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  // CSV 내보내기
  const exportToCSV = () => {
    const headers = [
      "포트",
      "프로토콜",
      "서비스",
      "상태",
      "취약점 개수",
      "위험도",
      "버전",
      "OS",
      "CVE",
    ];

    const csvContent = [
      headers.join(","),
      ...results.map(r =>
        [
          r.port,
          r.protocol,
          r.service,
          r.status,
          r.vulnerabilityCount,
          r.riskLevel,
          r.version || "N/A",
          r.osFingerprint || "N/A",
          r.cveList?.join(";") || "N/A",
        ].join(",")
      ),
    ].join("\n");

    const blob = new Blob(["\uFEFF" + csvContent], { type: "text/csv;charset=utf-8;" });
    const link = document.createElement("a");
    const url = URL.createObjectURL(blob);
    link.setAttribute("href", url);
    link.setAttribute("download", `port_scan_detailed_${Date.now()}.csv`);
    link.style.visibility = "hidden";
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  // HTML 보고서 생성
  const exportToHTML = () => {
    const htmlContent = `
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>포트 스캔 보고서</title>
  <style>
    body { font-family: Arial, sans-serif; padding: 20px; max-width: 1200px; margin: 0 auto; }
    h1 { color: #1f2937; }
    .header { background: #f3f4f6; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
    .stat { display: inline-block; margin-right: 30px; }
    table { width: 100%; border-collapse: collapse; margin-top: 20px; }
    th, td { border: 1px solid #e5e7eb; padding: 12px; text-align: left; }
    th { background: #3b82f6; color: white; }
    .critical { background: #fee2e2; }
    .high { background: #fed7aa; }
    .medium { background: #fef3c7; }
    .low { background: #dbeafe; }
    .timestamp { color: #6b7280; font-size: 14px; }
  </style>
</head>
<body>
  <h1>포트 스캔 보고서</h1>
  
  <div class="header">
    <div class="stat"><strong>타겟 IP:</strong> ${scanConfig.targetIp}</div>
    <div class="stat"><strong>포트 범위:</strong> ${scanConfig.startPort}-${scanConfig.endPort}</div>
    <div class="stat"><strong>스캔 방식:</strong> ${scanConfig.scanType.toUpperCase()}</div>
    <br/>
    <div class="timestamp">생성일시: ${new Date().toLocaleString('ko-KR')}</div>
  </div>

  <h2>요약</h2>
  <div class="stat"><strong>총 포트:</strong> ${results.length}</div>
  <div class="stat"><strong>취약 포트:</strong> ${results.filter(r => r.vulnerabilityCount > 0).length}</div>
  <div class="stat"><strong>Critical:</strong> ${results.filter(r => r.riskLevel === 'critical').length}</div>
  <div class="stat"><strong>High:</strong> ${results.filter(r => r.riskLevel === 'high').length}</div>
  <div class="stat"><strong>Medium:</strong> ${results.filter(r => r.riskLevel === 'medium').length}</div>
  <div class="stat"><strong>Low:</strong> ${results.filter(r => r.riskLevel === 'low').length}</div>

  <h2>상세 결과</h2>
  <table>
    <thead>
      <tr>
        <th>포트</th>
        <th>프로토콜</th>
        <th>서비스</th>
        <th>상태</th>
        <th>취약점</th>
        <th>위험도</th>
        <th>CVE</th>
        <th>대응 방안</th>
      </tr>
    </thead>
    <tbody>
      ${results.map(r => `
        <tr class="${r.riskLevel}">
          <td>${r.port}</td>
          <td>${r.protocol}</td>
          <td>${r.service}</td>
          <td>${r.status}</td>
          <td>${r.vulnerabilityCount}</td>
          <td>${r.riskLevel.toUpperCase()}</td>
          <td>${r.cveList?.join(', ') || 'N/A'}</td>
          <td>${r.mitigation || 'N/A'}</td>
        </tr>
      `).join('')}
    </tbody>
  </table>

  <div style="margin-top: 40px; padding-top: 20px; border-top: 1px solid #e5e7eb; color: #6b7280; font-size: 12px;">
    <p>이 보고서는 자동으로 생성되었습니다. 실제 환경에서는 전문가의 검증이 필요합니다.</p>
  </div>
</body>
</html>
    `;

    const blob = new Blob([htmlContent], { type: "text/html" });
    const link = document.createElement("a");
    const url = URL.createObjectURL(blob);
    link.setAttribute("href", url);
    link.setAttribute("download", `port_scan_report_${Date.now()}.html`);
    link.style.visibility = "hidden";
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle>결과 내보내기</CardTitle>
      </CardHeader>
      <CardContent className="space-y-3">
        <p className="text-sm text-gray-600 mb-4">
          스캔 결과를 다양한 형식으로 내보낼 수 있습니다.
        </p>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          <Button onClick={exportToJSON} variant="outline" className="w-full">
            <FileJson className="mr-2 h-4 w-4" />
            JSON
          </Button>
          <Button onClick={exportToCSV} variant="outline" className="w-full">
            <FileSpreadsheet className="mr-2 h-4 w-4" />
            CSV
          </Button>
          <Button onClick={exportToHTML} variant="outline" className="w-full">
            <FileCode className="mr-2 h-4 w-4" />
            HTML 보고서
          </Button>
        </div>
        <div className="text-xs text-gray-500 mt-4 p-3 bg-gray-50 rounded-lg">
          <p><strong>포함 항목:</strong></p>
          <ul className="list-disc list-inside mt-1 space-y-1">
            <li>스캔 설정 정보</li>
            <li>포트별 상세 정보</li>
            <li>취약점 및 CVE 리스트</li>
            <li>위험도 평가</li>
            <li>대응 가이드</li>
          </ul>
        </div>
      </CardContent>
    </Card>
  );
}
