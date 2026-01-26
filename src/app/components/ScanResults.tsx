import { Card, CardContent, CardHeader, CardTitle } from "./ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "./ui/table";
import { Badge } from "./ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "./ui/tabs";
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, PieChart, Pie, Cell } from "recharts";
import { Button } from "./ui/button";
import { Download, Filter } from "lucide-react";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "./ui/select";
import { useState } from "react";
import { Input } from "./ui/input";
import { Label } from "./ui/label";

export interface ScanResult {
  port: number;
  status: "open" | "closed" | "filtered";
  service: string;
  protocol: string;
}

interface ScanResultsProps {
  results: ScanResult[];
}

const COLORS = {
  open: "#10b981",
  closed: "#ef4444",
  filtered: "#f59e0b",
};

export function ScanResults({ results }: ScanResultsProps) {
  const [statusFilter, setStatusFilter] = useState<string>("all");
  const [portSearch, setPortSearch] = useState("");

  if (results.length === 0) {
    return null;
  }

  // 필터링 로직
  const filteredResults = results.filter((result) => {
    const matchesStatus = statusFilter === "all" || result.status === statusFilter;
    const matchesPort = portSearch === "" || result.port.toString().includes(portSearch);
    return matchesStatus && matchesPort;
  });

  // CSV 내보내기 함수
  const exportToCSV = () => {
    const headers = ["포트", "상태", "서비스", "프로토콜"];
    const csvContent = [
      headers.join(","),
      ...filteredResults.map(r => 
        `${r.port},${r.status},${r.service},${r.protocol}`
      )
    ].join("\n");

    const blob = new Blob(["\uFEFF" + csvContent], { type: "text/csv;charset=utf-8;" });
    const link = document.createElement("a");
    const url = URL.createObjectURL(blob);
    link.setAttribute("href", url);
    link.setAttribute("download", `port_scan_results_${new Date().getTime()}.csv`);
    link.style.visibility = "hidden";
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  // JSON 내보내기 함수
  const exportToJSON = () => {
    const jsonContent = JSON.stringify(filteredResults, null, 2);
    const blob = new Blob([jsonContent], { type: "application/json" });
    const link = document.createElement("a");
    const url = URL.createObjectURL(blob);
    link.setAttribute("href", url);
    link.setAttribute("download", `port_scan_results_${new Date().getTime()}.json`);
    link.style.visibility = "hidden";
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  // 상태별 통계
  const statusStats = {
    open: filteredResults.filter(r => r.status === "open").length,
    closed: filteredResults.filter(r => r.status === "closed").length,
    filtered: filteredResults.filter(r => r.status === "filtered").length,
  };

  const pieData = [
    { name: "열림", value: statusStats.open },
    { name: "닫힘", value: statusStats.closed },
    { name: "필터됨", value: statusStats.filtered },
  ];

  // 포트 범위별 통계 (100개씩 묶음)
  const rangeStats = results.reduce((acc, result) => {
    const range = Math.floor(result.port / 100) * 100;
    const key = `${range}-${range + 99}`;
    if (!acc[key]) {
      acc[key] = { range: key, open: 0, closed: 0 };
    }
    if (result.status === "open") {
      acc[key].open++;
    } else {
      acc[key].closed++;
    }
    return acc;
  }, {} as Record<string, { range: string; open: number; closed: number }>);

  const barData = Object.values(rangeStats).slice(0, 10);

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <CardTitle>스캔 결과</CardTitle>
          <div className="flex gap-2">
            <Button onClick={exportToCSV} variant="outline" size="sm">
              <Download className="h-4 w-4 mr-2" />
              CSV
            </Button>
            <Button onClick={exportToJSON} variant="outline" size="sm">
              <Download className="h-4 w-4 mr-2" />
              JSON
            </Button>
          </div>
        </div>
      </CardHeader>
      <CardContent>
        {/* 필터 섹션 */}
        <div className="mb-4 p-4 bg-gray-50 rounded-lg border space-y-3">
          <div className="flex items-center gap-2 mb-2">
            <Filter className="h-4 w-4 text-gray-600" />
            <span className="text-sm font-semibold">필터</span>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            <div className="space-y-1">
              <Label htmlFor="statusFilter" className="text-xs">상태</Label>
              <Select value={statusFilter} onValueChange={setStatusFilter}>
                <SelectTrigger id="statusFilter">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">전체</SelectItem>
                  <SelectItem value="open">열림</SelectItem>
                  <SelectItem value="closed">닫힘</SelectItem>
                  <SelectItem value="filtered">필터됨</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1">
              <Label htmlFor="portSearch" className="text-xs">포트 번호</Label>
              <Input
                id="portSearch"
                placeholder="포트 검색..."
                value={portSearch}
                onChange={(e) => setPortSearch(e.target.value)}
              />
            </div>
          </div>
          <p className="text-xs text-gray-500">
            총 {results.length}개 중 {filteredResults.length}개 표시
          </p>
        </div>

        <Tabs defaultValue="table">
          <TabsList className="grid w-full grid-cols-3">
            <TabsTrigger value="table">테이블</TabsTrigger>
            <TabsTrigger value="bar">막대 그래프</TabsTrigger>
            <TabsTrigger value="pie">원형 그래프</TabsTrigger>
          </TabsList>

          <TabsContent value="table" className="mt-4">
            <div className="max-h-[500px] overflow-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>포트</TableHead>
                    <TableHead>상태</TableHead>
                    <TableHead>서비스</TableHead>
                    <TableHead>프로토콜</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filteredResults.map((result) => (
                    <TableRow key={result.port}>
                      <TableCell className="font-semibold">{result.port}</TableCell>
                      <TableCell>
                        <Badge
                          variant={
                            result.status === "open" ? "default" :
                            result.status === "closed" ? "destructive" : "secondary"
                          }
                        >
                          {result.status === "open" ? "열림" : result.status === "closed" ? "닫힘" : "필터됨"}
                        </Badge>
                      </TableCell>
                      <TableCell>{result.service}</TableCell>
                      <TableCell className="uppercase">{result.protocol}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          </TabsContent>

          <TabsContent value="bar" className="mt-4">
            <div className="h-[400px]">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={barData}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="range" angle={-45} textAnchor="end" height={80} />
                  <YAxis />
                  <Tooltip />
                  <Bar dataKey="open" fill="#10b981" name="열린 포트" />
                  <Bar dataKey="closed" fill="#ef4444" name="닫힌 포트" />
                </BarChart>
              </ResponsiveContainer>
            </div>
            <p className="text-sm text-gray-500 text-center mt-2">포트 범위별 상태 분포</p>
          </TabsContent>

          <TabsContent value="pie" className="mt-4">
            <div className="h-[400px]">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={pieData}
                    cx="50%"
                    cy="50%"
                    labelLine={false}
                    label={({ name, value, percent }) => `${name}: ${value} (${(percent * 100).toFixed(0)}%)`}
                    outerRadius={120}
                    fill="#8884d8"
                    dataKey="value"
                  >
                    {pieData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={Object.values(COLORS)[index]} />
                    ))}
                  </Pie>
                  <Tooltip />
                </PieChart>
              </ResponsiveContainer>
            </div>
            <div className="flex justify-center gap-6 mt-4">
              <div className="flex items-center gap-2">
                <div className="w-4 h-4 bg-green-500 rounded"></div>
                <span className="text-sm">열림: {statusStats.open}</span>
              </div>
              <div className="flex items-center gap-2">
                <div className="w-4 h-4 bg-red-500 rounded"></div>
                <span className="text-sm">닫힌: {statusStats.closed}</span>
              </div>
              <div className="flex items-center gap-2">
                <div className="w-4 h-4 bg-amber-500 rounded"></div>
                <span className="text-sm">필터됨: {statusStats.filtered}</span>
              </div>
            </div>
          </TabsContent>
        </Tabs>
      </CardContent>
    </Card>
  );
}