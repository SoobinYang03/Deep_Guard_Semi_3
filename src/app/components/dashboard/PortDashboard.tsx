import { useState, useEffect } from "react";
import { PortToggleCard, PortDetail } from "./PortToggleCard";
import { NetworkDiagram } from "./NetworkDiagram";
import { ExportPanel } from "./ExportPanel";
import { Card, CardContent, CardHeader, CardTitle } from "../ui/card";
import { Badge } from "../ui/badge";
import { Activity, AlertTriangle, Shield, CheckCircle2 } from "lucide-react";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "../ui/select";
import { Input } from "../ui/input";
import { Label } from "../ui/label";

interface PortDashboardProps {
  scanResults: PortDetail[];
  scanConfig: {
    targetIp: string;
    startPort: number;
    endPort: number;
    scanType: string;
  };
}

export function PortDashboard({ scanResults, scanConfig }: PortDashboardProps) {
  const [filter, setFilter] = useState<"all" | "critical" | "high" | "medium" | "low">("all");
  const [searchTerm, setSearchTerm] = useState("");
  const [filteredResults, setFilteredResults] = useState(scanResults);

  useEffect(() => {
    let results = scanResults;

    // 위험도 필터
    if (filter !== "all") {
      results = results.filter(r => r.riskLevel === filter);
    }

    // 검색 필터
    if (searchTerm) {
      results = results.filter(r =>
        r.port.toString().includes(searchTerm) ||
        r.service.toLowerCase().includes(searchTerm.toLowerCase()) ||
        r.protocol.toLowerCase().includes(searchTerm.toLowerCase())
      );
    }

    setFilteredResults(results);
  }, [filter, searchTerm, scanResults]);

  const stats = {
    total: scanResults.length,
    critical: scanResults.filter(r => r.riskLevel === "critical").length,
    high: scanResults.filter(r => r.riskLevel === "high").length,
    medium: scanResults.filter(r => r.riskLevel === "medium").length,
    low: scanResults.filter(r => r.riskLevel === "low").length,
    vulnerable: scanResults.filter(r => r.vulnerabilityCount > 0).length,
  };

  const openPorts = scanResults
    .filter(r => r.status === "open")
    .map(r => r.port);

  return (
    <div className="space-y-6">
      {/* 통계 카드 */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <Card>
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-600">총 포트</p>
                <p className="text-2xl font-semibold mt-1">{stats.total}</p>
              </div>
              <Activity className="h-8 w-8 text-blue-600" />
            </div>
          </CardContent>
        </Card>

        <Card className="border-red-200">
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-600">Critical</p>
                <p className="text-2xl font-semibold mt-1 text-red-600">{stats.critical}</p>
              </div>
              <AlertTriangle className="h-8 w-8 text-red-600" />
            </div>
          </CardContent>
        </Card>

        <Card className="border-orange-200">
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-600">High</p>
                <p className="text-2xl font-semibold mt-1 text-orange-600">{stats.high}</p>
              </div>
              <Shield className="h-8 w-8 text-orange-600" />
            </div>
          </CardContent>
        </Card>

        <Card className="border-yellow-200">
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-600">Medium/Low</p>
                <p className="text-2xl font-semibold mt-1 text-yellow-600">{stats.medium + stats.low}</p>
              </div>
              <CheckCircle2 className="h-8 w-8 text-yellow-600" />
            </div>
          </CardContent>
        </Card>
      </div>

      {/* 네트워크 다이어그램 & 내보내기 패널 */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2">
          <NetworkDiagram targetIp={scanConfig.targetIp} openPorts={openPorts} />
        </div>
        <div>
          <ExportPanel
            results={scanResults}
            scanConfig={{
              ...scanConfig,
              timestamp: new Date().toISOString(),
            }}
          />
        </div>
      </div>

      {/* 필터 및 검색 */}
      <Card>
        <CardHeader>
          <CardTitle>포트 상세 정보</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
            <div className="space-y-2">
              <Label htmlFor="riskFilter">위험도 필터</Label>
              <Select value={filter} onValueChange={(value: any) => setFilter(value)}>
                <SelectTrigger id="riskFilter">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">전체</SelectItem>
                  <SelectItem value="critical">Critical</SelectItem>
                  <SelectItem value="high">High</SelectItem>
                  <SelectItem value="medium">Medium</SelectItem>
                  <SelectItem value="low">Low</SelectItem>
                </SelectContent>
              </Select>
            </div>

            <div className="space-y-2">
              <Label htmlFor="search">검색</Label>
              <Input
                id="search"
                placeholder="포트, 서비스, 프로토콜 검색..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
              />
            </div>
          </div>

          <div className="mb-4 flex items-center gap-2">
            <Badge variant="outline">
              총 {filteredResults.length}개 결과
            </Badge>
            {filter !== "all" && (
              <Badge>
                {filter.toUpperCase()} 필터 적용됨
              </Badge>
            )}
          </div>

          {/* 토글 카드 리스트 */}
          <div className="space-y-3">
            {filteredResults.length > 0 ? (
              filteredResults.map((result) => (
                <PortToggleCard key={result.port} data={result} />
              ))
            ) : (
              <div className="text-center py-12 text-gray-500">
                <p>필터 조건에 맞는 결과가 없습니다.</p>
              </div>
            )}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
