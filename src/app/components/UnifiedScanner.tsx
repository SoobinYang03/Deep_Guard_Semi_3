import { useState } from "react";
import { Input } from "./ui/input";
import { Button } from "./ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "./ui/select";
import { PortDetail, PortToggleCard } from "./dashboard/PortToggleCard";
import { ScanConfig } from "./ScanForm";
import { Progress } from "./ui/progress";
import { Activity, AlertCircle, CheckCircle2, Filter } from "lucide-react";
import { RadioGroup, RadioGroupItem } from "./ui/radio-group";
import { Label } from "./ui/label";

interface UnifiedScannerProps {
  onStartScan: (config: ScanConfig) => void;
  isScanning: boolean;
  progress: number;
  currentPort: number;
  totalPorts: number;
  openPorts: number;
  closedPorts: number;
  results: PortDetail[];
  scanConfig: ScanConfig | null;
}

export function UnifiedScanner({
  onStartScan,
  isScanning,
  progress,
  currentPort,
  totalPorts,
  openPorts,
  closedPorts,
  results,
  scanConfig,
}: UnifiedScannerProps) {
  const [targetIp, setTargetIp] = useState("220.112.55.123");
  const [startPort, setStartPort] = useState("1");
  const [endPort, setEndPort] = useState("1000");
  const [scanType, setScanType] = useState("tcp");
  const [scanSpeed, setScanSpeed] = useState("medium");
  
  // 필터 상태
  const [riskFilter, setRiskFilter] = useState<"all" | "critical" | "high" | "medium" | "low">("all");
  const [scanMethodFilter, setScanMethodFilter] = useState<"all" | "tcp" | "syn" | "udp" | "ack">("all");

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();

    const speedMap: Record<string, number> = {
      fast: 5,
      medium: 20,
      slow: 50,
    };

    onStartScan({
      targetIp,
      startPort: parseInt(startPort),
      endPort: parseInt(endPort),
      scanType,
      scanSpeed: speedMap[scanSpeed],
    });
  };

  // 필터링된 결과
  const filteredResults = results.filter(r => {
    const matchesRisk = riskFilter === "all" || r.riskLevel === riskFilter;
    const matchesMethod = scanMethodFilter === "all" || r.protocol.toLowerCase() === scanMethodFilter;
    return matchesRisk && matchesMethod && r.status === "open";
  });

  return (
    <div className="space-y-6">
      {/* Title */}
      <div>
        <h2 className="text-3xl font-semibold text-white mb-2">포트 스캐너 (Port Scanner)</h2>
        <p className="text-gray-400 text-sm">대상 IP/도메인 포트 개방 상태 확인</p>
        <p className="text-gray-500 text-xs mt-1">대상 서버의 열린 포트를 탐지하여 잠재적인 취약점을 파악합니다.</p>
      </div>

      {/* Scan Form */}
      <div className="bg-[#1a1f2e] rounded-lg p-6 border border-gray-800">
        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="flex gap-4">
            <div className="flex-1">
              <Input
                placeholder="220.112.55.123"
                value={targetIp}
                onChange={(e) => setTargetIp(e.target.value)}
                className="bg-[#0f1419] border-gray-700 text-white placeholder:text-gray-500 h-12 text-lg"
                disabled={isScanning}
                required
              />
            </div>
            <Button
              type="submit"
              disabled={isScanning}
              className="bg-cyan-500 hover:bg-cyan-600 text-white px-8 h-12 text-base font-medium"
            >
              {isScanning ? "스캔 중..." : "스캔 시작"}
            </Button>
          </div>

          <div className="grid grid-cols-4 gap-4">
            <div>
              <label className="text-xs text-gray-400 mb-1.5 block">시작 포트</label>
              <Input
                type="number"
                min="1"
                max="65535"
                value={startPort}
                onChange={(e) => setStartPort(e.target.value)}
                className="bg-[#0f1419] border-gray-700 text-white h-10"
                disabled={isScanning}
                required
              />
            </div>
            <div>
              <label className="text-xs text-gray-400 mb-1.5 block">종료 포트</label>
              <Input
                type="number"
                min="1"
                max="65535"
                value={endPort}
                onChange={(e) => setEndPort(e.target.value)}
                className="bg-[#0f1419] border-gray-700 text-white h-10"
                disabled={isScanning}
                required
              />
            </div>
            <div>
              <label className="text-xs text-gray-400 mb-1.5 block">스캔 방식</label>
              <Select value={scanType} onValueChange={setScanType} disabled={isScanning}>
                <SelectTrigger className="bg-[#0f1419] border-gray-700 text-white h-10">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent className="bg-[#1a1f2e] border-gray-700">
                  <SelectItem value="tcp" className="text-white">TCP</SelectItem>
                  <SelectItem value="syn" className="text-white">SYN</SelectItem>
                  <SelectItem value="udp" className="text-white">UDP</SelectItem>
                  <SelectItem value="ack" className="text-white">ACK</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div>
              <label className="text-xs text-gray-400 mb-1.5 block">스캔 속도</label>
              <Select value={scanSpeed} onValueChange={setScanSpeed} disabled={isScanning}>
                <SelectTrigger className="bg-[#0f1419] border-gray-700 text-white h-10">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent className="bg-[#1a1f2e] border-gray-700">
                  <SelectItem value="fast" className="text-white">빠름</SelectItem>
                  <SelectItem value="medium" className="text-white">보통</SelectItem>
                  <SelectItem value="slow" className="text-white">느림</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
        </form>

        {/* Progress Bar */}
        {isScanning && (
          <div className="mt-4 space-y-2">
            <div className="flex items-center justify-between text-sm">
              <span className="text-gray-400">스캔 진행중...</span>
              <span className="text-cyan-400">{Math.round(progress)}%</span>
            </div>
            <Progress value={progress} className="h-2 bg-gray-800" />
            <div className="flex items-center gap-4 text-xs text-gray-500">
              <span>포트: {currentPort} / {totalPorts}</span>
              <span>열림: {openPorts}</span>
              <span>닫힘: {closedPorts}</span>
            </div>
          </div>
        )}
      </div>

      {/* Results Section */}
      {results.length > 0 && (
        <div className="space-y-4">
          {/* Stats Cards */}
          <div className="grid grid-cols-4 gap-4">
            <div className="bg-[#1a1f2e] rounded-lg p-4 border border-gray-800">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-xs text-gray-400 mb-1">Total</p>
                  <p className="text-2xl font-semibold text-white">{results.length}</p>
                </div>
                <Activity className="h-8 w-8 text-cyan-400" />
              </div>
            </div>

            <div className="bg-[#1a1f2e] rounded-lg p-4 border border-red-900/30">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-xs text-gray-400 mb-1">Critical</p>
                  <p className="text-2xl font-semibold text-red-400">
                    {results.filter(r => r.riskLevel === "critical").length}
                  </p>
                </div>
                <AlertCircle className="h-8 w-8 text-red-400" />
              </div>
            </div>

            <div className="bg-[#1a1f2e] rounded-lg p-4 border border-orange-900/30">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-xs text-gray-400 mb-1">High</p>
                  <p className="text-2xl font-semibold text-orange-400">
                    {results.filter(r => r.riskLevel === "high").length}
                  </p>
                </div>
                <AlertCircle className="h-8 w-8 text-orange-400" />
              </div>
            </div>

            <div className="bg-[#1a1f2e] rounded-lg p-4 border border-green-900/30">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-xs text-gray-400 mb-1">Safe</p>
                  <p className="text-2xl font-semibold text-green-400">
                    {results.filter(r => r.riskLevel === "low").length}
                  </p>
                </div>
                <CheckCircle2 className="h-8 w-8 text-green-400" />
              </div>
            </div>
          </div>

          {/* Filter Section */}
          <div className="bg-[#1a1f2e] rounded-lg p-4 border border-gray-800">
            <div className="flex items-center justify-between">
              {/* Left: Risk Level Filter */}
              <div className="flex items-center gap-4">
                <div className="flex items-center gap-2 text-sm text-gray-400">
                  <Filter className="h-4 w-4" />
                  <span className="font-medium">탐지 필터:</span>
                </div>
                <RadioGroup 
                  value={riskFilter} 
                  onValueChange={(value: any) => setRiskFilter(value)}
                  className="flex items-center gap-4"
                >
                  <div className="flex items-center space-x-2">
                    <RadioGroupItem value="all" id="all" className="border-gray-600 text-cyan-500" />
                    <Label htmlFor="all" className="text-sm text-gray-300 cursor-pointer">전체</Label>
                  </div>
                  <div className="flex items-center space-x-2">
                    <RadioGroupItem value="critical" id="critical" className="border-gray-600 text-red-500" />
                    <Label htmlFor="critical" className="text-sm text-red-400 cursor-pointer">Critical</Label>
                  </div>
                  <div className="flex items-center space-x-2">
                    <RadioGroupItem value="high" id="high" className="border-gray-600 text-orange-500" />
                    <Label htmlFor="high" className="text-sm text-orange-400 cursor-pointer">High</Label>
                  </div>
                  <div className="flex items-center space-x-2">
                    <RadioGroupItem value="medium" id="medium" className="border-gray-600 text-yellow-500" />
                    <Label htmlFor="medium" className="text-sm text-yellow-400 cursor-pointer">Medium</Label>
                  </div>
                  <div className="flex items-center space-x-2">
                    <RadioGroupItem value="low" id="low" className="border-gray-600 text-blue-500" />
                    <Label htmlFor="low" className="text-sm text-blue-400 cursor-pointer">Low</Label>
                  </div>
                </RadioGroup>
              </div>

              {/* Right: Scan Method Filter */}
              <div className="flex items-center gap-3">
                <span className="text-sm text-gray-400 font-medium">스캔 방식:</span>
                <Select value={scanMethodFilter} onValueChange={(value: any) => setScanMethodFilter(value)}>
                  <SelectTrigger className="w-[140px] bg-[#0f1419] border-gray-700 text-white h-9">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent className="bg-[#1a1f2e] border-gray-700">
                    <SelectItem value="all" className="text-white">전체</SelectItem>
                    <SelectItem value="tcp" className="text-white">TCP</SelectItem>
                    <SelectItem value="syn" className="text-white">SYN</SelectItem>
                    <SelectItem value="udp" className="text-white">UDP</SelectItem>
                    <SelectItem value="ack" className="text-white">ACK</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>
          </div>

          {/* Active Ports Toggle List */}
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-xl font-semibold text-white">활성화 중인 포트 목록</h3>
                <p className="text-gray-500 text-sm mt-1">
                  {filteredResults.length}개의 열린 포트 발견
                  {(riskFilter !== "all" || scanMethodFilter !== "all") && (
                    <span className="text-cyan-400 ml-2">(필터 적용됨)</span>
                  )}
                </p>
              </div>
              <div className="text-sm text-gray-400">
                클릭하여 상세 정보 확인
              </div>
            </div>

            {filteredResults.length > 0 ? (
              filteredResults.map((result) => (
                <div key={result.port} className="[&>div]:bg-[#1a1f2e] [&>div]:border-gray-800">
                  <PortToggleCard data={result} />
                </div>
              ))
            ) : (
              <div className="bg-[#1a1f2e] rounded-lg p-12 border border-gray-800 text-center">
                <p className="text-gray-400">선택한 필터 조건에 맞는 포트가 없습니다.</p>
                <p className="text-gray-600 text-sm mt-2">필터를 변경하거나 새로운 스캔을 시작해보세요.</p>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Initial State */}
      {results.length === 0 && !isScanning && (
        <div className="bg-[#1a1f2e] rounded-lg p-12 border border-gray-800 text-center">
          <Activity className="h-16 w-16 text-gray-600 mx-auto mb-4" />
          <h3 className="text-xl font-semibold text-white mb-2">스캔을 시작하세요</h3>
          <p className="text-gray-400">위에서 타겟 IP와 포트 범위를 설정하고 '스캔 시작' 버튼을 클릭하세요.</p>
        </div>
      )}
    </div>
  );
}