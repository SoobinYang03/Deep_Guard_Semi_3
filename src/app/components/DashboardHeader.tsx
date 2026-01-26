import { Bell, Search, User } from "lucide-react";
import { Input } from "./ui/input";
import { Button } from "./ui/button";

export function DashboardHeader() {
  return (
    <header className="border-b bg-white px-6 py-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-8">
          <h1 className="text-2xl font-semibold">Dashboard</h1>
          <nav className="hidden md:flex gap-6">
            <a href="#" className="text-sm text-gray-600 hover:text-gray-900">Overview</a>
            <a href="#" className="text-sm text-gray-600 hover:text-gray-900">Analytics</a>
            <a href="#" className="text-sm text-gray-600 hover:text-gray-900">Reports</a>
            <a href="#" className="text-sm text-gray-600 hover:text-gray-900">Settings</a>
          </nav>
        </div>
        
        <div className="flex items-center gap-4">
          <div className="hidden md:block relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-gray-400" />
            <Input
              type="search"
              placeholder="Search..."
              className="pl-9 w-64"
            />
          </div>
          <Button variant="ghost" size="icon">
            <Bell className="h-5 w-5" />
          </Button>
          <Button variant="ghost" size="icon">
            <User className="h-5 w-5" />
          </Button>
        </div>
      </div>
    </header>
  );
}
