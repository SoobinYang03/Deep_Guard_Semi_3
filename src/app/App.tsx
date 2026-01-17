import api from '../lib/api';
import { useState, useEffect } from "react";
import { ScanConfig } from "./components/ScanForm";
import { ScanResult } from "./components/ScanResults";
import { PortDetail } from "./components/dashboard/PortToggleCard";
import { UnifiedScanner } from "./components/UnifiedScanner";
import { Shield } from "lucide-react";

// 1. ScanResult를 디자인 컴포넌트용 PortDetail로 변환하는 함수 추가
const convertToPortDetail = (result: ScanResult): PortDetail => {
  return {
    port: result.port,
    protocol: result.protocol,
    service: result.service || "unknown",
    status: result.status,
    vulnerabilityCount: 0, // 초기값
    riskLevel: "low",      // 초기값
    scanMethod: result.protocol.toUpperCase(),
  };
};

export default function App() {
  const [isScanning, setIsScanning] = useState(false);
  const [progress, setProgress] = useState(0);
  const [results, setResults] = useState<ScanResult[]>([]);
  const [scanConfig, setScanConfig] = useState<ScanConfig | null>(null);
  const [scanId, setScanId] = useState<string | null>(null);

  useEffect(() => {
    let timer: any;
    if (isScanning && scanId) {
      timer = setInterval(async () => {
        try {
          const response = await api.get(`/scan/${scanId}`);
          if (response.data.status === "completed") {
            setIsScanning(false);
            setProgress(100);
            clearInterval(timer);
            fetchFinalReport(scanId);
          } else {
            setProgress((prev) => (prev < 90 ? prev + 5 : prev));
          }
        } catch (error) {
          console.error("상태 확인 실패:", error);
        }
      }, 3000);
    }
    return () => { if (timer) clearInterval(timer); };
  }, [isScanning, scanId]);

  const fetchFinalReport = async (id: string) => {
    try {
      const response = await api.get(`/report/export/${id}`);
      setResults(response.data.results || []);
    } catch (error) {
      console.error("리포트 조회 실패:", error);
    }
  };

  const handleStartScan = async (config: any) => {
    setScanConfig(config);
    setIsScanning(true);
    setProgress(5);
    setResults([]);

    try {
      const response = await api.post('/scan/start', {
        target_ip: config.target || config.ip || "127.0.0.1",
        port_range: [config.startPort || 1, config.endPort || 1000],
        description: "DeepGuard UI Scan"
      });
      setScanId(response.data.scan_id);
    } catch (error) {
      alert("백엔드 서버 연결 실패!");
      setIsScanning(false);
    }
  };

  // 2. 오류 지점 수정: results를 PortDetail 형식으로 변환하여 전달
  const dashboardData: PortDetail[] = results.map(convertToPortDetail);

  return (
    <div className="min-h-screen bg-[#0f1419] text-white">
      <header className="bg-[#1a1f2e] border-b border-gray-800 p-4">
        <div className="container mx-auto flex items-center gap-3">
          <Shield className="text-cyan-400" />
          <h1 className="text-xl font-bold">DEEPGUARD</h1>
        </div>
      </header>

      <main className="container mx-auto py-8 px-6">
        <UnifiedScanner
          onStartScan={handleStartScan}
          isScanning={isScanning}
          progress={progress}
          currentPort={0}
          totalPorts={scanConfig ? (scanConfig.endPort - scanConfig.startPort + 1) : 0}
          openPorts={results.filter(r => r.status === "open").length}
          closedPorts={results.filter(r => r.status === "closed").length}
          results={dashboardData} // 변환된 데이터를 넣어서 오류 해결!
          scanConfig={scanConfig}
        />
      </main>
    </div>
  );
}