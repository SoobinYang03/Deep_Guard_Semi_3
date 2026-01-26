import { Card, CardContent } from "./ui/card";
import { LucideIcon } from "lucide-react";

interface MetricCardProps {
  title: string;
  value: string;
  change: string;
  changeType: "increase" | "decrease";
  icon: LucideIcon;
}

export function MetricCard({ title, value, change, changeType, icon: Icon }: MetricCardProps) {
  return (
    <Card>
      <CardContent className="p-6">
        <div className="flex items-center justify-between">
          <div className="flex-1">
            <p className="text-sm text-gray-600">{title}</p>
            <p className="text-3xl font-semibold mt-2">{value}</p>
            <div className="flex items-center gap-1 mt-2">
              <span className={`text-sm ${changeType === "increase" ? "text-green-600" : "text-red-600"}`}>
                {change}
              </span>
              <span className="text-sm text-gray-500">vs last month</span>
            </div>
          </div>
          <div className={`p-3 rounded-lg ${changeType === "increase" ? "bg-green-100" : "bg-blue-100"}`}>
            <Icon className={`h-6 w-6 ${changeType === "increase" ? "text-green-600" : "text-blue-600"}`} />
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
