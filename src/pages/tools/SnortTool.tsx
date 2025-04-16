
import { useState } from "react";
import { 
  AlertTriangle, 
  FileText, 
  Eye, 
  RefreshCw, 
  Upload, 
  ArrowUpDown, 
  Check, 
  X, 
  Filter, 
  Download, 
  Play,
  Pause,
  Settings,
  ChevronDown,
  ChevronRight,
  Clock,
  Code,
  Shield,
  Info
} from "lucide-react";
import { 
  Card, 
  CardContent, 
  CardDescription, 
  CardFooter, 
  CardHeader, 
  CardTitle 
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Badge } from "@/components/ui/badge";
import { Switch } from "@/components/ui/switch";
import { 
  Select, 
  SelectContent, 
  SelectItem, 
  SelectTrigger, 
  SelectValue 
} from "@/components/ui/select";
import { toast } from "sonner";
import { 
  Table, 
  TableBody, 
  TableCaption, 
  TableCell, 
  TableHead, 
  TableHeader, 
  TableRow 
} from "@/components/ui/table";
import { Textarea } from "@/components/ui/textarea";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";

// Mock data for Snort alerts
const snortAlertsMock = [
  {
    id: 1,
    timestamp: "2025-04-16T10:23:45.000Z",
    message: "INDICATOR-SCAN Port Scan",
    classification: "Attempted Information Leak",
    priority: 2,
    protocol: "TCP",
    srcIp: "203.0.113.42",
    srcPort: 43210,
    dstIp: "192.168.1.15",
    dstPort: 80,
    sid: 2000419,
    ruleContent: 'alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"INDICATOR-SCAN Port Scan"; flow:stateless; detection_filter: track by_src, count 30, seconds 5; threshold:type threshold, track by_src, count 1, seconds 60; classtype:attempted-recon; sid:2000419; rev:10;)'
  },
  {
    id: 2,
    timestamp: "2025-04-16T09:18:27.000Z",
    message: "SERVER-WEBAPP SQL injection attempt",
    classification: "Web Application Attack",
    priority: 1,
    protocol: "TCP",
    srcIp: "203.0.113.15",
    srcPort: 52341,
    dstIp: "192.168.1.100",
    dstPort: 443,
    sid: 2102832,
    ruleContent: 'alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"SERVER-WEBAPP SQL injection attempt"; flow:to_server,established; content:"SELECT"; nocase; pcre:"/SELECT\\s+(?:\\w+\\s*,\\s*)*\\*\\s*FROM/i"; classtype:web-application-attack; sid:2102832; rev:5;)'
  },
  {
    id: 3,
    timestamp: "2025-04-16T08:42:13.000Z",
    message: "MALWARE-CNC Possible Emotet infection",
    classification: "Trojan Activity",
    priority: 1,
    protocol: "TCP",
    srcIp: "192.168.1.110",
    srcPort: 49832,
    dstIp: "185.244.31.142",
    dstPort: 8080,
    sid: 2028973,
    ruleContent: 'alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"MALWARE-CNC Possible Emotet infection"; flow:to_server,established; content:"POST"; http_method; content:".php"; http_uri; content:"Mozilla/"; http_header; pcre:"/Content-Length\\s*:\\s*\\d{3,4}$/mH"; classtype:trojan-activity; sid:2028973; rev:2;)'
  },
  {
    id: 4,
    timestamp: "2025-04-16T07:55:02.000Z",
    message: "OS-WINDOWS Microsoft Windows SMB remote code execution attempt",
    classification: "Attempted Administrator Privilege Gain",
    priority: 1,
    protocol: "TCP",
    srcIp: "203.0.113.55",
    srcPort: 38291,
    dstIp: "192.168.1.5",
    dstPort: 445,
    sid: 2024297,
    ruleContent: 'alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"OS-WINDOWS Microsoft Windows SMB remote code execution attempt"; flow:to_server,established; content:"|FF|SMB|33 00|"; depth:6; content:"|01 00 00 00 00|"; within:5; distance:73; content:"|FF FF FF FF FF FF FF FF 00 00 00 00|"; within:12; distance:27; classtype:attempted-admin; sid:2024297; rev:4;)'
  },
  {
    id: 5,
    timestamp: "2025-04-15T23:34:56.000Z",
    message: "PROTOCOL-DNS zone transfer attempt",
    classification: "Potentially Bad Traffic",
    priority: 2,
    protocol: "UDP",
    srcIp: "203.0.113.22",
    srcPort: 53245,
    dstIp: "192.168.1.10",
    dstPort: 53,
    sid: 2100368,
    ruleContent: 'alert udp $EXTERNAL_NET any -> $HOME_NET 53 (msg:"PROTOCOL-DNS zone transfer attempt"; content:"|00 00 FC|"; offset:14; depth:3; reference:cve,1999-0532; classtype:attempted-recon; sid:2100368; rev:12;)'
  }
];

// Mock data for Snort rules
const snortRulesMock = [
  {
    id: 1,
    sid: 1000001,
    name: "SQL Injection Attempt",
    description: "Detects common SQL injection patterns in HTTP requests",
    content: 'alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"SQL Injection Attempt"; flow:to_server,established; content:"SELECT"; nocase; content:"FROM"; distance:0; nocase; content:"WHERE"; distance:0; nocase; classtype:web-application-attack; sid:1000001; rev:1;)',
    enabled: true,
    category: "web-application-attack",
    reference: "CVE-1999-0001",
    updated: "2025-03-15T14:30:00.000Z"
  },
  {
    id: 2,
    sid: 1000002,
    name: "Potential XSS Attack",
    description: "Detects cross-site scripting attempts in URI parameters",
    content: 'alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"Potential XSS Attack"; flow:to_server,established; content:"<script>"; nocase; pcre:"/<script.*?>.*?<\/script>/i"; classtype:web-application-attack; sid:1000002; rev:2;)',
    enabled: true,
    category: "web-application-attack",
    reference: "CVE-2007-5243",
    updated: "2025-03-18T11:20:00.000Z"
  },
  {
    id: 3,
    sid: 1000003,
    name: "Suspicious PowerShell Command",
    description: "Detects obfuscated or suspicious PowerShell commands",
    content: 'alert tcp $HOME_NET any -> $HOME_NET any (msg:"Suspicious PowerShell Command"; content:"powershell"; nocase; content:"-enc"; distance:0; nocase; content:"-exec"; distance:0; nocase; classtype:trojan-activity; sid:1000003; rev:1;)',
    enabled: true,
    category: "trojan-activity",
    reference: "",
    updated: "2025-03-22T09:45:00.000Z"
  },
  {
    id: 4,
    sid: 1000004,
    name: "SMB Remote Code Execution Attempt",
    description: "Detects attempts to exploit SMB vulnerabilities for RCE",
    content: 'alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"SMB Remote Code Execution Attempt"; content:"|FF|SMB"; depth:4; pcre:"/.*\\\\IPC\\$/"; classtype:attempted-admin; sid:1000004; rev:3;)',
    enabled: true,
    category: "attempted-admin",
    reference: "CVE-2017-0144",
    updated: "2025-02-28T16:15:00.000Z"
  },
  {
    id: 5,
    sid: 1000005,
    name: "DNS Zone Transfer",
    description: "Detects DNS zone transfer attempts (AXFR)",
    content: 'alert udp $EXTERNAL_NET any -> $HOME_NET 53 (msg:"DNS Zone Transfer Attempt"; content:"|00 00 FC|"; offset:14; depth:3; classtype:attempted-recon; sid:1000005; rev:1;)',
    enabled: false,
    category: "attempted-recon",
    reference: "CVE-1999-0532",
    updated: "2025-03-05T13:30:00.000Z"
  }
];

// Mock data for Snort configurations
const snortConfigMock = {
  version: "3.1.51.0",
  configPath: "/etc/snort/snort.conf",
  homenet: "192.168.1.0/24",
  externalNet: "!$HOME_NET",
  httpPorts: "80,443",
  preprocessors: [
    { name: "frag3_global", status: "enabled" },
    { name: "frag3_engine", status: "enabled" },
    { name: "stream5_global", status: "enabled" },
    { name: "http_inspect", status: "enabled" },
    { name: "ssh", status: "enabled" },
    { name: "smtp", status: "enabled" }
  ],
  rulesetStats: {
    totalRules: 8721,
    enabledRules: 6543,
    disabledRules: 2178,
    categories: [
      { name: "web-application-attack", count: 1254 },
      { name: "exploit-kit", count: 873 },
      { name: "malware-backdoor", count: 1782 },
      { name: "trojan-activity", count: 1326 },
      { name: "attempted-admin", count: 653 },
      { name: "attempted-recon", count: 422 },
      { name: "policy-violation", count: 265 },
      { name: "other", count: 2146 }
    ]
  },
  status: "running",
  uptime: "5 days, 7 hours, 42 minutes",
  lastReload: "2025-04-12T15:30:22.000Z",
  performance: {
    avgPacketsPerSecond: 8720,
    avgMbitsPerSecond: 512,
    avgMicrosecPerPacket: 28.3,
    packetsDropped: 0.02
  }
};

const SnortTool = () => {
  const [alerts] = useState(snortAlertsMock);
  const [rules, setRules] = useState(snortRulesMock);
  const [config] = useState(snortConfigMock);
  const [searchTerm, setSearchTerm] = useState("");
  const [priorityFilter, setPriorityFilter] = useState("all");
  const [activeTab, setActiveTab] = useState("dashboard");
  const [isRunning, setIsRunning] = useState(config.status === "running");
  
  // New rule form
  const [newRule, setNewRule] = useState({
    name: "",
    description: "",
    content: "",
    enabled: true,
    category: "web-application-attack",
    reference: ""
  });

  // Filter function for alerts based on search and priority
  const filteredAlerts = alerts.filter(alert => {
    const matchesSearch = 
      searchTerm === "" || 
      alert.message.toLowerCase().includes(searchTerm.toLowerCase()) || 
      alert.srcIp.includes(searchTerm) ||
      alert.dstIp.includes(searchTerm) ||
      alert.sid.toString().includes(searchTerm);
    
    const matchesPriority = 
      priorityFilter === "all" || 
      alert.priority.toString() === priorityFilter;
    
    return matchesSearch && matchesPriority;
  });

  // Filter function for rules based on search
  const filteredRules = rules.filter(rule => {
    return (
      searchTerm === "" || 
      rule.name.toLowerCase().includes(searchTerm.toLowerCase()) || 
      rule.description.toLowerCase().includes(searchTerm.toLowerCase()) ||
      rule.content.toLowerCase().includes(searchTerm.toLowerCase()) ||
      rule.sid.toString().includes(searchTerm)
    );
  });

  // Handler for toggling rule enabled status
  const toggleRuleStatus = (id: number) => {
    setRules(
      rules.map(rule => 
        rule.id === id ? { ...rule, enabled: !rule.enabled } : rule
      )
    );
    
    const rule = rules.find(r => r.id === id);
    toast.success(`Rule ${!rule?.enabled ? "enabled" : "disabled"}`, {
      description: `${rule?.name} has been ${!rule?.enabled ? "enabled" : "disabled"}`
    });
  };

  // Handler for adding a new rule
  const addRule = () => {
    if (!newRule.name || !newRule.content) {
      toast.error("Missing required fields", {
        description: "Name and rule content are required"
      });
      return;
    }
    
    const newId = Math.max(...rules.map(r => r.id)) + 1;
    const newSid = Math.max(...rules.map(r => r.sid)) + 1;
    
    const now = new Date().toISOString();
    
    setRules([
      ...rules,
      {
        ...newRule,
        id: newId,
        sid: newSid,
        updated: now
      }
    ]);
    
    // Reset form
    setNewRule({
      name: "",
      description: "",
      content: "",
      enabled: true,
      category: "web-application-attack",
      reference: ""
    });
    
    toast.success("Snort rule created", {
      description: `New rule "${newRule.name}" has been added with SID ${newSid}`
    });
  };

  // Function to toggle Snort service
  const toggleSnortService = () => {
    setIsRunning(!isRunning);
    
    if (isRunning) {
      toast.info("Stopping Snort service", {
        description: "Snort IDS service is shutting down"
      });
    } else {
      toast.success("Starting Snort service", {
        description: "Snort IDS service is now running"
      });
    }
  };

  // Function to reload Snort configuration
  const reloadSnortConfig = () => {
    toast.success("Snort configuration reloaded", {
      description: "All rules and settings have been updated"
    });
  };

  // Function to get color based on priority
  const getPriorityColor = (priority: number) => {
    switch (priority) {
      case 1:
        return "bg-red-500 hover:bg-red-600";
      case 2:
        return "bg-orange-500 hover:bg-orange-600";
      case 3:
        return "bg-yellow-500 hover:bg-yellow-600";
      default:
        return "bg-blue-500 hover:bg-blue-600";
    }
  };

  return (
    <div className="container mx-auto p-4 space-y-6">
      <div className="flex flex-col md:flex-row justify-between md:items-center gap-4">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Snort IDS/IPS</h1>
          <p className="text-muted-foreground">
            Manage and monitor Snort network intrusion detection system
          </p>
        </div>
        <div className="flex gap-2">
          <Button
            variant={isRunning ? "destructive" : "default"}
            className="flex items-center gap-2"
            onClick={toggleSnortService}
          >
            {isRunning ? (
              <>
                <Pause className="h-4 w-4" />
                Stop Service
              </>
            ) : (
              <>
                <Play className="h-4 w-4" />
                Start Service
              </>
            )}
          </Button>
          <Button
            variant="outline"
            className="flex items-center gap-2"
            onClick={reloadSnortConfig}
          >
            <RefreshCw className="h-4 w-4" />
            Reload Config
          </Button>
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="outline" className="flex items-center gap-2">
                <Settings className="h-4 w-4" />
                <span className="hidden md:inline">Actions</span>
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end">
              <DropdownMenuLabel>Snort Actions</DropdownMenuLabel>
              <DropdownMenuSeparator />
              <DropdownMenuItem
                onClick={() => {
                  toast.success("Test alert generated", {
                    description: "A test alert has been added to verify functionality"
                  });
                }}
              >
                <AlertTriangle className="h-4 w-4 mr-2" />
                <span>Generate Test Alert</span>
              </DropdownMenuItem>
              <DropdownMenuItem
                onClick={() => {
                  toast.success("Rules updated from online sources", {
                    description: "Downloaded 257 new and updated rules"
                  });
                }}
              >
                <Download className="h-4 w-4 mr-2" />
                <span>Update Ruleset</span>
              </DropdownMenuItem>
              <DropdownMenuItem
                onClick={() => {
                  toast.success("PCAP analysis started", {
                    description: "Analyzing captured traffic against ruleset"
                  });
                }}
              >
                <Play className="h-4 w-4 mr-2" />
                <span>Analyze PCAP File</span>
              </DropdownMenuItem>
              <DropdownMenuItem
                onClick={() => {
                  toast.info("Advanced configuration", {
                    description: "Configuration editor would open here"
                  });
                }}
              >
                <Code className="h-4 w-4 mr-2" />
                <span>Edit snort.conf</span>
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      </div>

      {/* Service Status Banner */}
      <div className={`flex items-center justify-between p-4 rounded-md ${isRunning ? 'bg-green-500/10 border border-green-500/20' : 'bg-red-500/10 border border-red-500/20'}`}>
        <div className="flex items-center gap-3">
          {isRunning ? (
            <>
              <Shield className="h-5 w-5 text-green-500" />
              <div>
                <p className="font-medium text-green-500">Snort Service Active</p>
                <p className="text-sm text-muted-foreground">Version {config.version} | Uptime: {config.uptime}</p>
              </div>
            </>
          ) : (
            <>
              <AlertTriangle className="h-5 w-5 text-red-500" />
              <div>
                <p className="font-medium text-red-500">Snort Service Inactive</p>
                <p className="text-sm text-muted-foreground">IDS protection is currently disabled</p>
              </div>
            </>
          )}
        </div>
        <div className="flex items-center gap-3 text-sm">
          <div className="flex flex-col items-end">
            <span className="font-medium">{config.rulesetStats.enabledRules}</span>
            <span className="text-xs text-muted-foreground">Enabled Rules</span>
          </div>
          <div className="flex flex-col items-end">
            <span className="font-medium">
              {isRunning ? config.performance.avgPacketsPerSecond : "0"}
            </span>
            <span className="text-xs text-muted-foreground">Packets/sec</span>
          </div>
          <div className="flex flex-col items-end">
            <span className="font-medium">{alerts.length}</span>
            <span className="text-xs text-muted-foreground">Alerts Today</span>
          </div>
        </div>
      </div>

      {/* Search and Filters */}
      <div className="flex flex-col sm:flex-row gap-4">
        <div className="relative flex-1">
          <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
          <Input
            type="search"
            placeholder="Search rules, alerts, or IP addresses..."
            className="pl-8"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
          />
        </div>
        {activeTab === "alerts" && (
          <Select 
            value={priorityFilter} 
            onValueChange={setPriorityFilter}
          >
            <SelectTrigger className="w-full sm:w-[140px]">
              <SelectValue placeholder="Priority" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All Priorities</SelectItem>
              <SelectItem value="1">Priority 1 (High)</SelectItem>
              <SelectItem value="2">Priority 2 (Medium)</SelectItem>
              <SelectItem value="3">Priority 3 (Low)</SelectItem>
            </SelectContent>
          </Select>
        )}
      </div>

      {/* Main Tabs */}
      <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
        <TabsList className="grid grid-cols-1 md:grid-cols-4 w-full max-w-3xl">
          <TabsTrigger value="dashboard" className="flex items-center gap-2">
            <Shield className="h-4 w-4" />
            Dashboard
          </TabsTrigger>
          <TabsTrigger value="alerts" className="flex items-center gap-2">
            <AlertTriangle className="h-4 w-4" />
            Alerts
          </TabsTrigger>
          <TabsTrigger value="rules" className="flex items-center gap-2">
            <FileText className="h-4 w-4" />
            Rules
          </TabsTrigger>
          <TabsTrigger value="settings" className="flex items-center gap-2">
            <Settings className="h-4 w-4" />
            Configuration
          </TabsTrigger>
        </TabsList>
        
        {/* Dashboard Tab */}
        <TabsContent value="dashboard" className="space-y-4">
          {/* Stats Cards */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-medium">Total Rules</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">{config.rulesetStats.totalRules}</div>
                <div className="flex items-center justify-between text-xs text-muted-foreground">
                  <span>{config.rulesetStats.enabledRules} enabled</span>
                  <span>{config.rulesetStats.disabledRules} disabled</span>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-medium">Recent Alerts</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">{alerts.length}</div>
                <p className="text-xs text-muted-foreground">
                  Last: {new Date(alerts[0]?.timestamp).toLocaleTimeString()}
                </p>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-medium">Traffic Rate</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">
                  {isRunning ? config.performance.avgPacketsPerSecond : "0"}
                </div>
                <p className="text-xs text-muted-foreground">
                  {isRunning ? config.performance.avgMbitsPerSecond : "0"} Mbps
                </p>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-medium">Dropped Packets</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">
                  {isRunning ? config.performance.packetsDropped : "0"}%
                </div>
                <p className="text-xs text-muted-foreground">
                  {isRunning ? config.performance.avgMicrosecPerPacket : "0"} μs/packet
                </p>
              </CardContent>
            </Card>
          </div>
          
          {/* Recent Alerts */}
          <Card>
            <CardHeader>
              <CardTitle>Recent Alerts</CardTitle>
              <CardDescription>
                Most recent security events detected by Snort
              </CardDescription>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Time</TableHead>
                    <TableHead>Alert Message</TableHead>
                    <TableHead>Source</TableHead>
                    <TableHead>Destination</TableHead>
                    <TableHead>Priority</TableHead>
                    <TableHead className="text-right">Details</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {alerts.slice(0, 3).map((alert) => (
                    <TableRow key={alert.id}>
                      <TableCell>
                        {new Date(alert.timestamp).toLocaleTimeString()}
                      </TableCell>
                      <TableCell className="font-medium">{alert.message}</TableCell>
                      <TableCell>{alert.srcIp}:{alert.srcPort}</TableCell>
                      <TableCell>{alert.dstIp}:{alert.dstPort}</TableCell>
                      <TableCell>
                        <Badge className={getPriorityColor(alert.priority)}>
                          P{alert.priority}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-right">
                        <Button 
                          variant="ghost" 
                          size="sm"
                          onClick={() => {
                            toast.info(alert.message, {
                              description: `Alert SID: ${alert.sid} | Classification: ${alert.classification}`
                            });
                          }}
                        >
                          <Eye className="h-4 w-4" />
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
              <div className="flex justify-center mt-2">
                <Button 
                  variant="link" 
                  size="sm"
                  className="text-muted-foreground"
                  onClick={() => setActiveTab("alerts")}
                >
                  View all alerts
                </Button>
              </div>
            </CardContent>
          </Card>
          
          {/* Rule Categories */}
          <Card>
            <CardHeader>
              <CardTitle>Ruleset Composition</CardTitle>
              <CardDescription>
                Distribution of rules by category
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {config.rulesetStats.categories.map((category, idx) => (
                  <div key={idx} className="flex items-center gap-4">
                    <div className="w-40 truncate capitalize">{category.name.replace(/-/g, ' ')}</div>
                    <div className="flex-1 h-3 rounded-full bg-secondary overflow-hidden">
                      <div 
                        className="h-full bg-primary"
                        style={{ width: `${(category.count / config.rulesetStats.totalRules) * 100}%` }}
                      />
                    </div>
                    <div className="w-16 text-right text-sm">{category.count}</div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>
        
        {/* Alerts Tab */}
        <TabsContent value="alerts" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Snort Alerts</CardTitle>
              <CardDescription>
                Security events detected by Snort IDS
              </CardDescription>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Time</TableHead>
                    <TableHead>Alert Message</TableHead>
                    <TableHead>Source</TableHead>
                    <TableHead>Destination</TableHead>
                    <TableHead>Protocol</TableHead>
                    <TableHead>Priority</TableHead>
                    <TableHead className="text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filteredAlerts.map((alert) => (
                    <TableRow key={alert.id}>
                      <TableCell>
                        {new Date(alert.timestamp).toLocaleTimeString()}
                      </TableCell>
                      <TableCell>
                        <div className="font-medium truncate max-w-[240px]" title={alert.message}>
                          {alert.message}
                        </div>
                        <div className="text-xs text-muted-foreground">
                          {alert.classification}
                        </div>
                      </TableCell>
                      <TableCell>{alert.srcIp}:{alert.srcPort}</TableCell>
                      <TableCell>{alert.dstIp}:{alert.dstPort}</TableCell>
                      <TableCell>{alert.protocol}</TableCell>
                      <TableCell>
                        <Badge className={getPriorityColor(alert.priority)}>
                          Priority {alert.priority}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-right">
                        <DropdownMenu>
                          <DropdownMenuTrigger asChild>
                            <Button variant="ghost" size="sm">
                              <ChevronDown className="h-4 w-4" />
                            </Button>
                          </DropdownMenuTrigger>
                          <DropdownMenuContent align="end">
                            <DropdownMenuItem
                              onClick={() => {
                                toast.info("Rule Details", {
                                  description: alert.ruleContent
                                });
                              }}
                              className="flex items-center gap-2"
                            >
                              <Code className="h-4 w-4" />
                              <span>View Rule</span>
                            </DropdownMenuItem>
                            <DropdownMenuItem
                              onClick={() => {
                                toast.info("Packet Details", {
                                  description: "Packet capture details would show here"
                                });
                              }}
                              className="flex items-center gap-2"
                            >
                              <Eye className="h-4 w-4" />
                              <span>View Packet</span>
                            </DropdownMenuItem>
                            <DropdownMenuItem
                              onClick={() => {
                                toast.success("Added to blocklist", {
                                  description: `${alert.srcIp} has been added to the blocklist`
                                });
                              }}
                              className="flex items-center gap-2"
                            >
                              <X className="h-4 w-4" />
                              <span>Block Source IP</span>
                            </DropdownMenuItem>
                          </DropdownMenuContent>
                        </DropdownMenu>
                      </TableCell>
                    </TableRow>
                  ))}
                  {filteredAlerts.length === 0 && (
                    <TableRow>
                      <TableCell colSpan={7} className="text-center py-6 text-muted-foreground">
                        No alerts match your search criteria
                      </TableCell>
                    </TableRow>
                  )}
                </TableBody>
              </Table>
            </CardContent>
            <CardFooter className="flex justify-between">
              <Button
                variant="outline"
                className="flex items-center gap-2"
                onClick={() => {
                  toast.success("Alerts exported", {
                    description: "All alerts have been exported to CSV format"
                  });
                }}
              >
                <Download className="h-4 w-4" />
                Export Alerts
              </Button>
              <div className="text-sm text-muted-foreground">
                Showing {filteredAlerts.length} of {alerts.length} alerts
              </div>
            </CardFooter>
          </Card>
        </TabsContent>
        
        {/* Rules Tab */}
        <TabsContent value="rules" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Manage Rules</CardTitle>
              <CardDescription>
                Configure and customize Snort detection rules
              </CardDescription>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-[80px]">SID</TableHead>
                    <TableHead>Rule Name</TableHead>
                    <TableHead>Category</TableHead>
                    <TableHead>Reference</TableHead>
                    <TableHead>Updated</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead className="text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filteredRules.map((rule) => (
                    <TableRow key={rule.id}>
                      <TableCell className="font-mono text-xs">{rule.sid}</TableCell>
                      <TableCell>
                        <div className="font-medium">{rule.name}</div>
                        <div className="text-xs text-muted-foreground">{rule.description}</div>
                      </TableCell>
                      <TableCell>
                        <Badge variant="outline" className="capitalize">
                          {rule.category.replace(/-/g, ' ')}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        {rule.reference ? (
                          <span className="text-xs font-mono">{rule.reference}</span>
                        ) : (
                          <span className="text-xs text-muted-foreground">-</span>
                        )}
                      </TableCell>
                      <TableCell className="text-sm">
                        {new Date(rule.updated).toLocaleDateString()}
                      </TableCell>
                      <TableCell>
                        {rule.enabled ? (
                          <Badge className="bg-green-500 hover:bg-green-600">Enabled</Badge>
                        ) : (
                          <Badge variant="outline">Disabled</Badge>
                        )}
                      </TableCell>
                      <TableCell className="text-right">
                        <div className="flex justify-end gap-2">
                          <Button 
                            variant="ghost" 
                            size="sm"
                            onClick={() => {
                              toast.info("Rule Content", {
                                description: <div className="font-mono text-xs break-all">{rule.content}</div>
                              });
                            }}
                          >
                            <Code className="h-4 w-4" />
                          </Button>
                          <Button 
                            variant={rule.enabled ? "destructive" : "default"}
                            size="sm"
                            onClick={() => toggleRuleStatus(rule.id)}
                          >
                            {rule.enabled ? (
                              <X className="h-4 w-4" />
                            ) : (
                              <Check className="h-4 w-4" />
                            )}
                          </Button>
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
                  {filteredRules.length === 0 && (
                    <TableRow>
                      <TableCell colSpan={7} className="text-center py-6 text-muted-foreground">
                        No rules match your search criteria
                      </TableCell>
                    </TableRow>
                  )}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
          
          {/* Add Custom Rule */}
          <Card>
            <CardHeader>
              <CardTitle>Add Custom Rule</CardTitle>
              <CardDescription>
                Create a new Snort detection rule
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label htmlFor="rule-name">Rule Name</Label>
                  <Input 
                    id="rule-name" 
                    placeholder="e.g., Custom SQL Injection Detection" 
                    value={newRule.name}
                    onChange={(e) => setNewRule({...newRule, name: e.target.value})}
                  />
                </div>
                <div className="grid grid-cols-2 gap-4">
                  <div className="space-y-2">
                    <Label htmlFor="rule-category">Category</Label>
                    <Select 
                      value={newRule.category}
                      onValueChange={(value) => setNewRule({...newRule, category: value})}
                    >
                      <SelectTrigger>
                        <Select.Value placeholder="Select category" />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="web-application-attack">Web Application Attack</SelectItem>
                        <SelectItem value="trojan-activity">Trojan Activity</SelectItem>
                        <SelectItem value="attempted-admin">Attempted Admin</SelectItem>
                        <SelectItem value="attempted-recon">Attempted Recon</SelectItem>
                        <SelectItem value="policy-violation">Policy Violation</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="rule-reference">Reference (optional)</Label>
                    <Input 
                      id="rule-reference" 
                      placeholder="e.g., CVE-2023-12345" 
                      value={newRule.reference}
                      onChange={(e) => setNewRule({...newRule, reference: e.target.value})}
                    />
                  </div>
                </div>
              </div>
              
              <div className="space-y-2">
                <Label htmlFor="rule-description">Description</Label>
                <Input 
                  id="rule-description" 
                  placeholder="Describe what this rule detects" 
                  value={newRule.description}
                  onChange={(e) => setNewRule({...newRule, description: e.target.value})}
                />
              </div>
              
              <div className="space-y-2">
                <div className="flex justify-between items-center">
                  <Label htmlFor="rule-content">Rule Content (Snort format)</Label>
                  <Button 
                    variant="ghost" 
                    size="sm" 
                    className="text-xs"
                    onClick={() => {
                      toast.info("Snort Rule Format Help", {
                        description: "Snort rule documentation would show here"
                      });
                    }}
                  >
                    Format Help
                  </Button>
                </div>
                <Textarea 
                  id="rule-content" 
                  placeholder='alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"Custom Rule"; content:"malicious"; sid:1000042; rev:1;)'
                  className="font-mono h-32"
                  value={newRule.content}
                  onChange={(e) => setNewRule({...newRule, content: e.target.value})}
                />
              </div>
              
              <div className="flex items-center space-x-2">
                <Switch 
                  checked={newRule.enabled}
                  onCheckedChange={(checked) => setNewRule({...newRule, enabled: checked})}
                  id="rule-enabled" 
                />
                <Label htmlFor="rule-enabled">Enable rule after creation</Label>
              </div>
            </CardContent>
            <CardFooter className="flex justify-between">
              <Button 
                variant="outline"
                onClick={() => {
                  setNewRule({
                    name: "",
                    description: "",
                    content: "",
                    enabled: true,
                    category: "web-application-attack",
                    reference: ""
                  });
                }}
              >
                Reset
              </Button>
              <Button 
                onClick={addRule}
                className="flex items-center gap-2"
              >
                <Check className="h-4 w-4" />
                Create Rule
              </Button>
            </CardFooter>
          </Card>
        </TabsContent>
        
        {/* Configuration Tab */}
        <TabsContent value="settings" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Snort Configuration</CardTitle>
              <CardDescription>
                View and modify Snort configuration settings
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div>
                  <h3 className="font-medium mb-2">General Settings</h3>
                  <div className="space-y-4">
                    <div className="grid grid-cols-2 gap-4">
                      <div className="space-y-2">
                        <Label>Snort Version</Label>
                        <div className="p-2 bg-muted rounded text-sm">{config.version}</div>
                      </div>
                      <div className="space-y-2">
                        <Label>Configuration Path</Label>
                        <div className="p-2 bg-muted rounded text-sm font-mono">{config.configPath}</div>
                      </div>
                    </div>
                    
                    <div className="space-y-2">
                      <Label htmlFor="home-net">HOME_NET</Label>
                      <Input 
                        id="home-net" 
                        defaultValue={config.homenet}
                      />
                      <p className="text-xs text-muted-foreground">Define your internal network range</p>
                    </div>
                    
                    <div className="space-y-2">
                      <Label htmlFor="external-net">EXTERNAL_NET</Label>
                      <Input 
                        id="external-net" 
                        defaultValue={config.externalNet}
                      />
                      <p className="text-xs text-muted-foreground">Define external network (typically !$HOME_NET)</p>
                    </div>
                    
                    <div className="space-y-2">
                      <Label htmlFor="http-ports">HTTP_PORTS</Label>
                      <Input 
                        id="http-ports" 
                        defaultValue={config.httpPorts}
                      />
                      <p className="text-xs text-muted-foreground">Comma-separated list of HTTP ports</p>
                    </div>
                  </div>
                </div>
                <div>
                  <h3 className="font-medium mb-2">Preprocessors</h3>
                  <div className="space-y-2">
                    {config.preprocessors.map((preprocessor, idx) => (
                      <div key={idx} className="flex items-center justify-between p-2 bg-muted rounded">
                        <span className="font-mono text-sm">{preprocessor.name}</span>
                        <div>
                          <Badge variant={preprocessor.status === "enabled" ? "default" : "outline"}>
                            {preprocessor.status}
                          </Badge>
                        </div>
                      </div>
                    ))}
                  </div>
                  
                  <h3 className="font-medium mt-6 mb-2">Performance Settings</h3>
                  <div className="space-y-4">
                    <div className="grid grid-cols-2 gap-4">
                      <div className="space-y-2">
                        <Label htmlFor="perf-mode">Detection Mode</Label>
                        <Select defaultValue="balanced">
                          <SelectTrigger id="perf-mode">
                            <SelectValue placeholder="Select mode" />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectItem value="balanced">Balanced</SelectItem>
                            <SelectItem value="speed">Maximum Speed</SelectItem>
                            <SelectItem value="coverage">Maximum Coverage</SelectItem>
                          </SelectContent>
                        </Select>
                      </div>
                      <div className="space-y-2">
                        <Label htmlFor="perf-threads">Detection Threads</Label>
                        <Select defaultValue="auto">
                          <SelectTrigger id="perf-threads">
                            <SelectValue placeholder="Select threads" />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectItem value="auto">Auto (Based on CPU)</SelectItem>
                            <SelectItem value="1">1 Thread</SelectItem>
                            <SelectItem value="2">2 Threads</SelectItem>
                            <SelectItem value="4">4 Threads</SelectItem>
                            <SelectItem value="8">8 Threads</SelectItem>
                          </SelectContent>
                        </Select>
                      </div>
                    </div>
                    
                    <div className="space-y-2">
                      <div className="flex items-center justify-between">
                        <Label htmlFor="perf-pkt-size">Maximum Packet Size</Label>
                        <span className="text-sm">9000 bytes</span>
                      </div>
                      <Input 
                        id="perf-pkt-size" 
                        type="range"
                        min="1500"
                        max="65535"
                        defaultValue="9000"
                      />
                      <p className="text-xs text-muted-foreground">Larger values use more memory but can handle jumbo frames</p>
                    </div>
                  </div>
                </div>
              </div>
              
              <div className="border-t pt-6">
                <h3 className="font-medium mb-2">Output Options</h3>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  <div className="space-y-2">
                    <div className="flex items-center space-x-2">
                      <Switch id="alert-fast" defaultChecked />
                      <Label htmlFor="alert-fast">Fast Alert Output</Label>
                    </div>
                    <p className="text-xs text-muted-foreground">Basic alerts with minimal information</p>
                  </div>
                  <div className="space-y-2">
                    <div className="flex items-center space-x-2">
                      <Switch id="alert-full" defaultChecked />
                      <Label htmlFor="alert-full">Full Alert Output</Label>
                    </div>
                    <p className="text-xs text-muted-foreground">Detailed alerts with packet data</p>
                  </div>
                  <div className="space-y-2">
                    <div className="flex items-center space-x-2">
                      <Switch id="alert-syslog" />
                      <Label htmlFor="alert-syslog">Syslog Output</Label>
                    </div>
                    <p className="text-xs text-muted-foreground">Send alerts to system log</p>
                  </div>
                </div>
              </div>
            </CardContent>
            <CardFooter className="flex justify-between">
              <Button 
                variant="outline"
                onClick={() => {
                  toast.info("Configuration reset", {
                    description: "All changes have been discarded"
                  });
                }}
              >
                Reset Changes
              </Button>
              <Button 
                onClick={() => {
                  toast.success("Configuration saved", {
                    description: "Changes will take effect after service restart"
                  });
                }}
                className="flex items-center gap-2"
              >
                <Save className="h-4 w-4" />
                Save Configuration
              </Button>
            </CardFooter>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
};

export default SnortTool;
