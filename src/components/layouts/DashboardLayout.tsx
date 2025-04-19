import { useState, useEffect } from "react";
import { Outlet, Navigate, Link, useLocation } from "react-router-dom";
import { 
  Shield, Bell, Activity, Settings, Menu, X, LogOut, 
  BarChart2, FilterX, Search, AlertTriangle, Eye, 
  Network, Database, FileJson, TerminalSquare, Zap,
  FileText, BookOpen, Clock, Lock, Truck
} from "lucide-react";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { toast } from "sonner";
import { 
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "@/components/ui/collapsible";
import { useAuth } from "@/contexts/AuthContext";

const DashboardLayout = () => {
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const [activeToolTip, setActiveToolTip] = useState("");
  const location = useLocation();
  const { user, isLoading, signOut } = useAuth();
  
  useEffect(() => {
    // Show a welcome toast when the dashboard loads
    if (location.pathname === "/" && user) {
      setTimeout(() => {
        toast.success(`Welcome to SentinelNet, ${user.user_metadata?.name || 'User'}`, {
          description: "Your network is now being monitored in real-time",
        });
      }, 1000);
    }
  }, [location.pathname, user]);

  // Show loading indicator while auth state is being determined
  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-sentinel-dark">
        <div className="animate-pulse text-sentinel-accent">Loading...</div>
      </div>
    );
  }

  // Check authentication
  if (!user) {
    return <Navigate to="/login" replace />;
  }

  const mainNavigation = [
    { name: "Dashboard", href: "/", icon: Shield, current: location.pathname === "/" },
    { name: "Alerts", href: "/alerts", icon: Bell, current: location.pathname === "/alerts" },
    { name: "Traffic Analysis", href: "/traffic", icon: Activity, current: location.pathname === "/traffic" },
    { name: "Settings", href: "/settings", icon: Settings, current: location.pathname === "/settings" },
  ];

  const detectionTools = [
    { name: "Signature Detection", href: "/signature-detection", icon: FileJson, description: "Pattern matching against known threats" },
    { name: "Anomaly Detection", href: "/anomaly-detection", icon: AlertTriangle, description: "ML-based unusual behavior detection" },
    { name: "Protocol Analysis", href: "/protocol-analysis", icon: Network, description: "Stateful inspection of network protocols" },
  ];

  const idpsTools = [
    { name: "Snort", href: "/tools/snort", icon: Eye, description: "Open-source network IDS/IPS" },
    { name: "Suricata", href: "/tools/suricata", icon: Zap, description: "High performance network IDS/IPS" },
    { name: "Security Onion", href: "/tools/security-onion", icon: Shield, description: "Security monitoring platform" },
    { name: "OWASP ZAP", href: "/tools/zap", icon: Lock, description: "Web application security scanner" },
    { name: "RequestShield", href: "/tools/requestshield", icon: FilterX, description: "API security monitoring" },
  ];

  const responseTools = [
    { name: "Traffic Blocking", href: "/response/blocking", icon: FilterX, description: "Automated threat prevention" },
    { name: "Alert Management", href: "/response/alerting", icon: Bell, description: "Notification configuration" },
    { name: "Logging", href: "/response/logging", icon: Clock, description: "Security event logging" },
    { name: "Reporting", href: "/response/reporting", icon: FileText, description: "Generate security reports" },
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
          <nav className="flex flex-col space-y-6">
            {/* User info */}
            <div className="px-3 py-2 text-sm font-medium text-white/70">
              <div className="flex items-center space-x-2">
                <div className="h-8 w-8 rounded-full bg-sentinel-accent/20 flex items-center justify-center">
                  <User className="h-4 w-4 text-sentinel-accent" />
                </div>
                <div className="flex flex-col">
                  <span className="font-medium text-white">{user.user_metadata?.name || 'User'}</span>
                  <span className="text-xs text-white/50">{user.email}</span>
                </div>
              </div>
            </div>

            {/* Main Navigation */}
            <div className="space-y-1">
              <p className="text-xs font-semibold text-gray-400 uppercase tracking-wider px-3 mb-2">
                Main Navigation
              </p>
              {mainNavigation.map((item) => (
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
            </div>

            {/* Detection Methods */}
            <Collapsible className="space-y-1">
              <CollapsibleTrigger className="flex w-full items-center justify-between px-3 py-2 text-sm font-medium text-white/70 hover:bg-sentinel-light/10 hover:text-white rounded-md">
                <div className="flex items-center">
                  <Search className="mr-3 h-5 w-5" />
                  <span>Detection Methods</span>
                </div>
                <svg
                  xmlns="http://www.w3.org/2000/svg"
                  width="24"
                  height="24"
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="2"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  className="h-4 w-4 transition-transform ui-open:rotate-180"
                >
                  <polyline points="6 9 12 15 18 9"></polyline>
                </svg>
              </CollapsibleTrigger>
              <CollapsibleContent className="pl-3 space-y-1">
                {detectionTools.map((tool) => (
                  <TooltipProvider key={tool.name}>
                    <Tooltip>
                      <TooltipTrigger asChild>
                        <Link
                          to={tool.href}
                          className="flex items-center rounded-md px-3 py-2 text-sm font-medium text-white/70 hover:bg-sentinel-light/10 hover:text-white ml-5"
                        >
                          <tool.icon className="mr-3 h-4 w-4" />
                          {tool.name}
                        </Link>
                      </TooltipTrigger>
                      <TooltipContent>
                        <p>{tool.description}</p>
                      </TooltipContent>
                    </Tooltip>
                  </TooltipProvider>
                ))}
              </CollapsibleContent>
            </Collapsible>
            
            {/* Response Tools */}
            <Collapsible className="space-y-1">
              <CollapsibleTrigger className="flex w-full items-center justify-between px-3 py-2 text-sm font-medium text-white/70 hover:bg-sentinel-light/10 hover:text-white rounded-md">
                <div className="flex items-center">
                  <Zap className="mr-3 h-5 w-5" />
                  <span>Response Tools</span>
                </div>
                <svg
                  xmlns="http://www.w3.org/2000/svg"
                  width="24"
                  height="24"
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="2"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  className="h-4 w-4 transition-transform ui-open:rotate-180"
                >
                  <polyline points="6 9 12 15 18 9"></polyline>
                </svg>
              </CollapsibleTrigger>
              <CollapsibleContent className="pl-3 space-y-1">
                {responseTools.map((tool) => (
                  <TooltipProvider key={tool.name}>
                    <Tooltip>
                      <TooltipTrigger asChild>
                        <Link
                          to={tool.href}
                          className="flex items-center rounded-md px-3 py-2 text-sm font-medium text-white/70 hover:bg-sentinel-light/10 hover:text-white ml-5"
                        >
                          <tool.icon className="mr-3 h-4 w-4" />
                          {tool.name}
                        </Link>
                      </TooltipTrigger>
                      <TooltipContent>
                        <p>{tool.description}</p>
                      </TooltipContent>
                    </Tooltip>
                  </TooltipProvider>
                ))}
              </CollapsibleContent>
            </Collapsible>

            {/* IDPS Tools */}
            <Collapsible className="space-y-1">
              <CollapsibleTrigger className="flex w-full items-center justify-between px-3 py-2 text-sm font-medium text-white/70 hover:bg-sentinel-light/10 hover:text-white rounded-md">
                <div className="flex items-center">
                  <TerminalSquare className="mr-3 h-5 w-5" />
                  <span>IDPS Tools</span>
                </div>
                <svg
                  xmlns="http://www.w3.org/2000/svg"
                  width="24"
                  height="24"
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="2"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  className="h-4 w-4 transition-transform ui-open:rotate-180"
                >
                  <polyline points="6 9 12 15 18 9"></polyline>
                </svg>
              </CollapsibleTrigger>
              <CollapsibleContent className="pl-3 space-y-1">
                {idpsTools.map((tool) => (
                  <TooltipProvider key={tool.name}>
                    <Tooltip>
                      <TooltipTrigger asChild>
                        <Link
                          to={tool.href}
                          className="flex items-center rounded-md px-3 py-2 text-sm font-medium text-white/70 hover:bg-sentinel-light/10 hover:text-white ml-5"
                        >
                          <tool.icon className="mr-3 h-4 w-4" />
                          {tool.name}
                        </Link>
                      </TooltipTrigger>
                      <TooltipContent>
                        <p>{tool.description}</p>
                      </TooltipContent>
                    </Tooltip>
                  </TooltipProvider>
                ))}
              </CollapsibleContent>
            </Collapsible>

            {/* Documentation */}
            <div className="space-y-1">
              <p className="text-xs font-semibold text-gray-400 uppercase tracking-wider px-3 mb-2">
                Documentation
              </p>
              <Link
                to="/documentation"
                className="flex items-center rounded-md px-3 py-2 text-sm font-medium text-white/70 hover:bg-sentinel-light/10 hover:text-white"
              >
                <BookOpen className="mr-3 h-5 w-5" />
                User Guide
              </Link>
            </div>
          </nav>
        </div>
        <div className="p-4 border-t border-sentinel-light/10">
          <Button 
            variant="ghost" 
            className="w-full justify-start text-white/70 hover:text-white hover:bg-sentinel-light/10"
            onClick={signOut}
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
              {mainNavigation.find((item) => item.current)?.name || "Dashboard"}
            </h1>
          </div>
          
          {/* Status indicators */}
          <div className="flex items-center gap-4">
            <div className="flex items-center gap-2">
              <span className="h-2 w-2 rounded-full bg-sentinel-success animate-pulse"></span>
              <span className="text-sm text-sentinel-success">System Online</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="h-2 w-2 rounded-full bg-sentinel-warning animate-pulse"></span>
              <span className="text-sm text-sentinel-warning">3 Active Alerts</span>
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
