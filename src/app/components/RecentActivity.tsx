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

const activities = [
  { id: "1", user: "John Doe", action: "Created new project", status: "Completed", time: "2 hours ago" },
  { id: "2", user: "Jane Smith", action: "Updated dashboard", status: "In Progress", time: "4 hours ago" },
  { id: "3", user: "Mike Johnson", action: "Submitted report", status: "Completed", time: "6 hours ago" },
  { id: "4", user: "Sarah Williams", action: "Reviewed documents", status: "Completed", time: "8 hours ago" },
  { id: "5", user: "Tom Brown", action: "Added new users", status: "Pending", time: "10 hours ago" },
];

export function RecentActivity() {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Recent Activity</CardTitle>
      </CardHeader>
      <CardContent>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>User</TableHead>
              <TableHead>Action</TableHead>
              <TableHead>Status</TableHead>
              <TableHead className="text-right">Time</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {activities.map((activity) => (
              <TableRow key={activity.id}>
                <TableCell className="font-medium">{activity.user}</TableCell>
                <TableCell>{activity.action}</TableCell>
                <TableCell>
                  <Badge 
                    variant={
                      activity.status === "Completed" ? "default" :
                      activity.status === "In Progress" ? "secondary" : "outline"
                    }
                  >
                    {activity.status}
                  </Badge>
                </TableCell>
                <TableCell className="text-right text-gray-500">{activity.time}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </CardContent>
    </Card>
  );
}
