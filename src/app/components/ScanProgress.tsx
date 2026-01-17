import { Card, CardContent, CardHeader, CardTitle } from "./ui/card";
import { Progress } from "./ui/progress";
import { Activity, CheckCircle, AlertCircle } from "lucide-react";

interface ScanProgressProps {
  isScanning: boolean;
  progress: number;
  currentPort: number;
  totalPorts: number;
  openPorts: number;
  closedPorts: number;
}

export function ScanProgress({
  isScanning,
  progress,
  currentPort,
  totalPorts,
  openPorts,
  closedPorts,
}: ScanProgressProps) {
  if (!isScanning && progress === 0) {
    return null;
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Activity className={`h-5 w-5 ${isScanning ? "animate-pulse text-blue-600" : "text-green-600"}`} />
          스캔 진행 상태
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <div>
          <div className="flex items-center justify-between mb-2">
            <span className="text-sm">진행률</span>
            <span className="text-sm font-semibold">{Math.round(progress)}%</span>
          </div>
          <Progress value={progress} className="h-2" />
          <p className="text-sm text-gray-500 mt-2">
            {currentPort} / {totalPorts} 포트 스캔됨
          </p>
        </div>

        <div className="grid grid-cols-2 gap-4 pt-2">
          <div className="flex items-center gap-2 p-3 bg-green-50 rounded-lg">
            <CheckCircle className="h-5 w-5 text-green-600" />
            <div>
              <p className="text-sm text-gray-600">열린 포트</p>
              <p className="text-xl font-semibold text-green-600">{openPorts}</p>
            </div>
          </div>
          <div className="flex items-center gap-2 p-3 bg-red-50 rounded-lg">
            <AlertCircle className="h-5 w-5 text-red-600" />
            <div>
              <p className="text-sm text-gray-600">닫힌 포트</p>
              <p className="text-xl font-semibold text-red-600">{closedPorts}</p>
            </div>
          </div>
        </div>

        {!isScanning && progress === 100 && (
          <div className="p-3 bg-blue-50 rounded-lg border border-blue-200">
            <p className="text-sm text-blue-800">✓ 스캔이 완료되었습니다!</p>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
