
import { useState, useEffect } from "react";
import { Outlet, Navigate, Link, useLocation } from "react-router-dom";
import { Shield, Bell, Activity, Settings, Menu, X, LogOut, BarChart2 } from "lucide-react";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";

// Mock authentication check - this would be replaced with real auth logic
const isAuthenticated = () => {
  return localStorage.getItem("sentinel-auth") === "true";
};

const DashboardLayout = () => {
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const location = useLocation();
  
  // In a real implementation, we would check with a proper auth system
  // For demo purposes, we'll set the user as authenticated so we can see the dashboard
  useEffect(() => {
    localStorage.setItem("sentinel-auth", "true");
  }, []);

  // For actual implementation, uncomment this to require authentication
  /*
  if (!isAuthenticated()) {
    return <Navigate to="/login" replace />;
  }
  */

  const navigation = [
    { name: "Dashboard", href: "/", icon: Shield, current: location.pathname === "/" },
    { name: "Alerts", href: "/alerts", icon: Bell, current: location.pathname === "/alerts" },
    { name: "Traffic Analysis", href: "/traffic", icon: Activity, current: location.pathname === "/traffic" },
    { name: "Settings", href: "/settings", icon: Settings, current: location.pathname === "/settings" },
  ];

  return (
    <div className="flex h-screen bg-background">
      {/* Sidebar */}
      <div
        className={cn(
          "fixed inset-y-0 z-50 flex w-72 flex-col border-r transition-all duration-300 bg-sentinel-dark border-sentinel-light/10",
          sidebarOpen ? "left-0" : "-left-72"
        )}
      >
        <div className="flex h-16 items-center justify-between px-4 border-b border-sentinel-light/10">
          <Link to="/" className="flex items-center space-x-2">
            <Shield className="h-8 w-8 text-sentinel-accent animate-pulse-glow" />
            <span className="text-lg font-bold text-white tracking-wider">SentinelNet</span>
          </Link>
          <Button
            variant="ghost"
            size="icon"
            onClick={() => setSidebarOpen(false)}
            className="lg:hidden"
          >
            <X className="h-5 w-5" />
          </Button>
        </div>
        <div className="flex-1 overflow-auto p-4">
          <nav className="flex flex-col space-y-1">
            {navigation.map((item) => (
              <Link
                key={item.name}
                to={item.href}
                className={cn(
                  "flex items-center rounded-md px-3 py-2 text-sm font-medium transition-colors",
                  item.current
                    ? "bg-sentinel-accent/10 text-sentinel-accent"
                    : "text-white/70 hover:bg-sentinel-light/10 hover:text-white"
                )}
              >
                <item.icon className="mr-3 h-5 w-5" />
                {item.name}
              </Link>
            ))}
          </nav>
        </div>
        <div className="p-4 border-t border-sentinel-light/10">
          <Button 
            variant="ghost" 
            className="w-full justify-start text-white/70 hover:text-white hover:bg-sentinel-light/10"
            onClick={() => {
              localStorage.removeItem("sentinel-auth");
              window.location.href = "/login";
            }}
          >
            <LogOut className="mr-3 h-5 w-5" />
            Sign out
          </Button>
        </div>
      </div>

      {/* Main content */}
      <div className={cn(
        "flex flex-col flex-1 overflow-x-hidden transition-all duration-300",
        sidebarOpen ? "lg:pl-72" : "lg:pl-0"
      )}>
        {/* Top navigation bar */}
        <header className="sticky top-0 z-40 flex h-16 items-center gap-x-4 border-b bg-background px-4 shadow-sm border-sentinel-light/10">
          <Button
            variant="ghost"
            size="icon"
            onClick={() => setSidebarOpen(!sidebarOpen)}
            className="lg:hidden"
          >
            <Menu className="h-5 w-5" />
          </Button>
          
          {/* Current page title */}
          <div className="flex-1">
            <h1 className="text-lg font-semibold">
              {navigation.find((item) => item.current)?.name || "Dashboard"}
            </h1>
          </div>
          
          {/* Status indicators could go here */}
          <div className="flex items-center gap-4">
            <div className="flex items-center gap-2">
              <span className="h-2 w-2 rounded-full bg-sentinel-success animate-pulse"></span>
              <span className="text-sm text-sentinel-success">System Online</span>
            </div>
          </div>
        </header>

        {/* Page content */}
        <main className="flex-1 overflow-y-auto p-4 md:p-6 bg-gradient-to-b from-background to-sentinel-dark/50">
          <Outlet />
        </main>
      </div>
    </div>
  );
};

export default DashboardLayout;
