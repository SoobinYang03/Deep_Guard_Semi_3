import { useState } from "react";
import { Card } from "../ui/card";
import { Badge } from "../ui/badge";
import { ChevronDown, ChevronUp, AlertTriangle, Shield, CheckCircle } from "lucide-react";
import { Button } from "../ui/button";

export interface PortDetail {
  port: number;
  protocol: string;
  service: string;
  status: "open" | "closed" | "filtered";
  vulnerabilityCount: number;
  riskLevel: "critical" | "high" | "medium" | "low";
  version?: string;
  osFingerprint?: string;
  scanMethod?: string;
  cveList?: string[];
  shodanData?: {
    country: string;
    organization: string;
    lastSeen: string;
  };
  screenshot?: string;
  nucleiLogs?: string[];
  mitigation?: string;
}

interface PortToggleCardProps {
  data: PortDetail;
}

const riskColors = {
  critical: "border-red-600 bg-red-950/30",
  high: "border-orange-500 bg-orange-950/30",
  medium: "border-yellow-500 bg-yellow-950/30",
  low: "border-blue-500 bg-blue-950/30",
};

const riskTextColors = {
  critical: "text-red-400",
  high: "text-orange-400",
  medium: "text-yellow-400",
  low: "text-blue-400",
};

export function PortToggleCard({ data }: PortToggleCardProps) {
  const [isExpanded, setIsExpanded] = useState(false);

  const getRiskIcon = () => {
    switch (data.riskLevel) {
      case "critical":
      case "high":
        return <AlertTriangle className="h-5 w-5 text-red-600" />;
      case "medium":
        return <Shield className="h-5 w-5 text-yellow-600" />;
      case "low":
        return <CheckCircle className="h-5 w-5 text-blue-600" />;
    }
  };

  return (
    <Card className={`border-2 ${riskColors[data.riskLevel]} transition-all duration-200 bg-[#1a1f2e]`}>
      <div
        className="p-4 cursor-pointer"
        onClick={() => setIsExpanded(!isExpanded)}
      >
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-4">
            {getRiskIcon()}
            <div>
              <div className="flex items-center gap-2">
                <span className="text-xl font-semibold text-white">{data.port}</span>
                <Badge variant="outline" className="uppercase text-xs border-gray-600 text-gray-300">
                  {data.protocol}
                </Badge>
              </div>
              <p className="text-sm text-gray-400 mt-1">{data.service}</p>
            </div>
          </div>

          <div className="flex items-center gap-4">
            <div className="text-right">
              <p className={`text-sm font-semibold ${riskTextColors[data.riskLevel]}`}>
                {data.riskLevel.toUpperCase()}
              </p>
              <p className="text-xs text-gray-500">
                {data.vulnerabilityCount} 취약점
              </p>
            </div>
            <Button variant="ghost" size="icon" className="text-gray-400 hover:text-white">
              {isExpanded ? (
                <ChevronUp className="h-5 w-5" />
              ) : (
                <ChevronDown className="h-5 w-5" />
              )}
            </Button>
          </div>
        </div>
      </div>

      {isExpanded && (
        <div className="border-t border-gray-800 px-4 py-4 space-y-4 bg-[#0f1419]">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* 버전 정보 */}
            {data.version && (
              <div>
                <h4 className="text-sm font-semibold mb-1 text-white">버전 정보</h4>
                <p className="text-sm text-gray-400">{data.version}</p>
              </div>
            )}

            {/* OS 핑거프린팅 */}
            {data.osFingerprint && (
              <div>
                <h4 className="text-sm font-semibold mb-1 text-white">OS 핑거프린팅</h4>
                <p className="text-sm text-gray-400">{data.osFingerprint}</p>
              </div>
            )}

            {/* 스캔 방식 */}
            {data.scanMethod && (
              <div>
                <h4 className="text-sm font-semibold mb-1 text-white">스캔 방식</h4>
                <p className="text-sm text-gray-400">{data.scanMethod}</p>
              </div>
            )}

            {/* Shodan 데이터 */}
            {data.shodanData && (
              <div>
                <h4 className="text-sm font-semibold mb-1 text-white">Shodan 데이터</h4>
                <div className="text-sm text-gray-400 space-y-1">
                  <p>국가: {data.shodanData.country}</p>
                  <p>조직: {data.shodanData.organization}</p>
                  <p>마지막 확인: {data.shodanData.lastSeen}</p>
                </div>
              </div>
            )}
          </div>

          {/* CVE 리스트 */}
          {data.cveList && data.cveList.length > 0 && (
            <div>
              <h4 className="text-sm font-semibold mb-2 text-white">CVE 리스트</h4>
              <div className="flex flex-wrap gap-2">
                {data.cveList.map((cve) => (
                  <Badge key={cve} variant="destructive" className="text-xs bg-red-900/40 text-red-400 border-red-800">
                    {cve}
                  </Badge>
                ))}
              </div>
            </div>
          )}

          {/* Screenshot */}
          {data.screenshot && (
            <div>
              <h4 className="text-sm font-semibold mb-2 text-white">스크린샷</h4>
              <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
                <img
                  src={data.screenshot}
                  alt="Service screenshot"
                  className="rounded max-w-full"
                />
              </div>
            </div>
          )}

          {/* Nuclei 로그 */}
          {data.nucleiLogs && data.nucleiLogs.length > 0 && (
            <div>
              <h4 className="text-sm font-semibold mb-2 text-white">Nuclei 스캔 로그</h4>
              <div className="bg-black text-green-400 p-3 rounded-lg font-mono text-xs max-h-40 overflow-y-auto border border-gray-800">
                {data.nucleiLogs.map((log, index) => (
                  <div key={index}>{log}</div>
                ))}
              </div>
            </div>
          )}

          {/* 대응 가이드 */}
          {data.mitigation && (
            <div className="bg-blue-950/30 border border-blue-800 rounded-lg p-4">
              <h4 className="text-sm font-semibold mb-2 flex items-center gap-2 text-blue-400">
                <Shield className="h-4 w-4 text-blue-400" />
                대응 가이드
              </h4>
              <p className="text-sm text-gray-300 whitespace-pre-line">
                {data.mitigation}
              </p>
            </div>
          )}
        </div>
      )}
    </Card>
  );
}