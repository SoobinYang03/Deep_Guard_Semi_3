import { useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "./ui/card";
import { Input } from "./ui/input";
import { Label } from "./ui/label";
import { Button } from "./ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "./ui/select";
import { Search } from "lucide-react";

interface ScanFormProps {
  onStartScan: (config: ScanConfig) => void;
  isScanning: boolean;
}

export interface ScanConfig {
  targetIp: string;
  startPort: number;
  endPort: number;
  scanType: string;
  scanSpeed: number;
}

export function ScanForm({ onStartScan, isScanning }: ScanFormProps) {
  const [targetIp, setTargetIp] = useState("192.168.1.1");
  const [startPort, setStartPort] = useState("1");
  const [endPort, setEndPort] = useState("1000");
  const [scanType, setScanType] = useState("tcp");
  const [scanSpeed, setScanSpeed] = useState("medium");

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    
    // 스캔 속도를 밀리초로 변환
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

  return (
    <Card>
      <CardHeader>
        <CardTitle>스캔 설정</CardTitle>
      </CardHeader>
      <CardContent>
        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="targetIp">타겟 IP 주소</Label>
            <Input
              id="targetIp"
              placeholder="예: 192.168.1.1"
              value={targetIp}
              onChange={(e) => setTargetIp(e.target.value)}
              required
              disabled={isScanning}
            />
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div className="space-y-2">
              <Label htmlFor="startPort">시작 포트</Label>
              <Input
                id="startPort"
                type="number"
                min="1"
                max="65535"
                value={startPort}
                onChange={(e) => setStartPort(e.target.value)}
                required
                disabled={isScanning}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="endPort">종료 포트</Label>
              <Input
                id="endPort"
                type="number"
                min="1"
                max="65535"
                value={endPort}
                onChange={(e) => setEndPort(e.target.value)}
                required
                disabled={isScanning}
              />
            </div>
          </div>

          <div className="space-y-2">
            <Label htmlFor="scanType">스캔 방식</Label>
            <Select value={scanType} onValueChange={setScanType} disabled={isScanning}>
              <SelectTrigger id="scanType">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="tcp">TCP Connect</SelectItem>
                <SelectItem value="syn">SYN Scan</SelectItem>
                <SelectItem value="udp">UDP Scan</SelectItem>
                <SelectItem value="ack">ACK Scan</SelectItem>
              </SelectContent>
            </Select>
          </div>

          <div className="space-y-2">
            <Label htmlFor="scanSpeed">스캔 속도</Label>
            <Select value={scanSpeed} onValueChange={setScanSpeed} disabled={isScanning}>
              <SelectTrigger id="scanSpeed">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="fast">빠름 (5ms)</SelectItem>
                <SelectItem value="medium">보통 (20ms)</SelectItem>
                <SelectItem value="slow">느림 (50ms)</SelectItem>
              </SelectContent>
            </Select>
          </div>

          <Button type="submit" className="w-full" disabled={isScanning}>
            <Search className="mr-2 h-4 w-4" />
            {isScanning ? "스캔 중..." : "스캔 시작"}
          </Button>
        </form>
      </CardContent>
    </Card>
  );
}