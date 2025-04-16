
import { useState } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Progress } from "@/components/ui/progress";
import { Badge } from "@/components/ui/badge";
import { toast } from "sonner";
import { 
  AlertCircle, 
  CheckCircle2, 
  ChevronDown, 
  CircleAlert, 
  FileText, 
  FilterX, 
  Play, 
  RefreshCw, 
  Shield, 
  XCircle,
  Search as SearchIcon,
  Save as SaveIcon
} from "lucide-react";
import { 
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue
} from "@/components/ui/select";

// Mock data for Snort rules
const mockRules = [
  {
    id: 1,
    enabled: true,
    rule: "alert tcp any any -> any 80 (msg:\"HTTP Traffic\"; sid:1000001; rev:1;)",
    category: "Web",
    severity: "low",
    description: "Detects HTTP traffic on port 80"
  },
  {
    id: 2,
    enabled: true,
    rule: "alert tcp any any -> any 443 (msg:\"HTTPS Traffic\"; sid:1000002; rev:1;)",
    category: "Web",
    severity: "low",
    description: "Detects HTTPS traffic on port 443"
  },
  {
    id: 3,
    enabled: false,
    rule: "alert icmp any any -> any any (msg:\"ICMP Traffic\"; sid:1000003; rev:1;)",
    category: "Network",
    severity: "info",
    description: "Detects ICMP traffic"
  },
  {
    id: 4,
    enabled: true,
    rule: "alert tcp any any -> any 22 (msg:\"SSH Traffic\"; sid:1000004; rev:1;)",
    category: "Remote Access",
    severity: "medium",
    description: "Detects SSH traffic on port 22"
  },
  {
    id: 5,
    enabled: true,
    rule: "alert tcp any any -> any 3389 (msg:\"RDP Traffic\"; sid:1000005; rev:1;)",
    category: "Remote Access",
    severity: "medium",
    description: "Detects RDP traffic on port 3389"
  },
  {
    id: 6,
    enabled: true,
    rule: "alert tcp any any -> any 445 (msg:\"SMB Traffic\"; sid:1000006; rev:1;)",
    category: "Network",
    severity: "medium",
    description: "Detects SMB traffic on port 445"
  }
];

// Mock data for alerts
const mockAlerts = [
  {
    id: 1,
    timestamp: new Date().toISOString(),
    rule_id: 1,
    source_ip: "192.168.1.5",
    source_port: 49723,
    dest_ip: "142.250.185.142",
    dest_port: 80,
    protocol: "TCP",
    message: "HTTP Traffic",
    severity: "low",
    status: "new"
  },
  {
    id: 2,
    timestamp: new Date(Date.now() - 5 * 60000).toISOString(),
    rule_id: 2,
    source_ip: "192.168.1.5",
    source_port: 49724,
    dest_ip: "142.250.185.142",
    dest_port: 443,
    protocol: "TCP",
    message: "HTTPS Traffic",
    severity: "low",
    status: "acknowledged"
  },
  {
    id: 3,
    timestamp: new Date(Date.now() - 15 * 60000).toISOString(),
    rule_id: 6,
    source_ip: "192.168.1.10",
    source_port: 49725,
    dest_ip: "192.168.1.5",
    dest_port: 445,
    protocol: "TCP",
    message: "SMB Traffic",
    severity: "medium",
    status: "resolved"
  },
  {
    id: 4,
    timestamp: new Date(Date.now() - 30 * 60000).toISOString(),
    rule_id: 4,
    source_ip: "192.168.1.15",
    source_port: 49726,
    dest_ip: "22.22.22.22",
    dest_port: 22,
    protocol: "TCP",
    message: "SSH Traffic",
    severity: "medium",
    status: "new"
  }
];

// Mock data for packet captures
const mockCaptures = [
  {
    id: 1,
    name: "morning-traffic-sample.pcap",
    date: new Date(Date.now() - 4 * 60 * 60000).toISOString(),
    size: "1.2 MB",
    packets: 4502,
    duration: "00:15:00"
  },
  {
    id: 2,
    name: "afternoon-traffic-sample.pcap",
    date: new Date(Date.now() - 2 * 60 * 60000).toISOString(),
    size: "2.5 MB",
    packets: 9871,
    duration: "00:30:00"
  },
  {
    id: 3,
    name: "evening-traffic-sample.pcap",
    date: new Date(Date.now() - 1 * 60 * 60000).toISOString(),
    size: "1.8 MB",
    packets: 6543,
    duration: "00:20:00"
  }
];

// Mock data for Snort statistics
const mockStats = {
  packets_received: 125432,
  packets_analyzed: 125432,
  packets_dropped: 0,
  alerts_generated: 37,
  uptime: "03:45:12",
  cpu_usage: 5.2,
  memory_usage: 256.3
};

const getSeverityBadgeClass = (severity: string) => {
  switch (severity) {
    case "critical": return "bg-red-500 text-white";
    case "high": return "bg-orange-500 text-white";
    case "medium": return "bg-yellow-500 text-black";
    case "low": return "bg-blue-500 text-white";
    case "info": return "bg-gray-500 text-white";
    default: return "bg-gray-500 text-white";
  }
};

const getStatusBadgeClass = (status: string) => {
  switch (status) {
    case "new": return "bg-red-500 text-white";
    case "acknowledged": return "bg-yellow-500 text-black";
    case "resolved": return "bg-green-500 text-white";
    default: return "bg-gray-500 text-white";
  }
};

const SnortTool = () => {
  const [rules, setRules] = useState(mockRules);
  const [alerts, setAlerts] = useState(mockAlerts);
  const [captures, setCaptures] = useState(mockCaptures);
  const [stats, setStats] = useState(mockStats);
  const [isRunning, setIsRunning] = useState(false);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [analyzeProgress, setAnalyzeProgress] = useState(0);
  const [newRule, setNewRule] = useState("");
  const [newRuleCategory, setNewRuleCategory] = useState("Web");
  const [newRuleSeverity, setNewRuleSeverity] = useState("low");
  const [newRuleDescription, setNewRuleDescription] = useState("");
  const [selectedAlert, setSelectedAlert] = useState<number | null>(null);
  const [filterCategory, setFilterCategory] = useState("all");
  const [filterSeverity, setFilterSeverity] = useState("all");
  const [searchTerm, setSearchTerm] = useState("");

  const startSnort = () => {
    setIsRunning(true);
    toast.success("Snort service started");
  };

  const stopSnort = () => {
    setIsRunning(false);
    toast.warning("Snort service stopped");
  };

  const acknowledgeAlert = (id: number) => {
    setAlerts(alerts.map(alert => 
      alert.id === id ? { ...alert, status: "acknowledged" } : alert
    ));
    toast.info("Alert acknowledged");
  };

  const resolveAlert = (id: number) => {
    setAlerts(alerts.map(alert => 
      alert.id === id ? { ...alert, status: "resolved" } : alert
    ));
    toast.success("Alert resolved");
  };

  const toggleRuleEnabled = (id: number) => {
    setRules(rules.map(rule => 
      rule.id === id ? { ...rule, enabled: !rule.enabled } : rule
    ));
  };

  const handleAddRule = () => {
    // In a real app, validation would be more complex
    if (!newRule.trim()) return;
    
    const newId = Math.max(...rules.map(r => r.id)) + 1;
    setRules([...rules, {
      id: newId,
      enabled: true,
      rule: newRule,
      category: newRuleCategory,
      severity: newRuleSeverity,
      description: newRuleDescription
    }]);
    
    // Reset form
    setNewRule("");
    setNewRuleCategory("Web");
    setNewRuleSeverity("low");
    setNewRuleDescription("");
  };

  const handleChangeAlertStatus = (id: number, status: string) => {
    setAlerts(alerts.map(alert => 
      alert.id === id ? { ...alert, status } : alert
    ));
    setSelectedAlert(null);
  };

  const analyzeCapture = (id: number) => {
    setIsAnalyzing(true);
    setAnalyzeProgress(0);
    
    // Simulate analysis progress
    const interval = setInterval(() => {
      setAnalyzeProgress(prev => {
        if (prev >= 100) {
          clearInterval(interval);
          setIsAnalyzing(false);
          
          // Simulate finding an alert
          const newAlert = {
            id: Math.max(...alerts.map(a => a.id)) + 1,
            timestamp: new Date().toISOString(),
            rule_id: 6,
            source_ip: "192.168.1.10",
            source_port: 49725,
            dest_ip: "192.168.1.5",
            dest_port: 445,
            protocol: "TCP",
            message: "SMB Traffic",
            severity: "medium",
            status: "new"
          };
          
          setAlerts(prev => [newAlert, ...prev]);
          
          return 100;
        }
        return prev + 5;
      });
    }, 200);
  };

  // Filter rules based on selected filters and search term
  const filteredRules = rules.filter(rule => {
    if (filterCategory !== "all" && rule.category !== filterCategory) return false;
    if (filterSeverity !== "all" && rule.severity !== filterSeverity) return false;
    if (searchTerm && !rule.rule.toLowerCase().includes(searchTerm.toLowerCase()) && 
        !rule.description.toLowerCase().includes(searchTerm.toLowerCase())) return false;
    return true;
  });

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-3xl font-bold tracking-tight">Snort IDS/IPS Tool</h2>
          <p className="text-muted-foreground">
            Open-source network intrusion prevention system
          </p>
        </div>
        <div className="flex items-center space-x-2">
          <Button 
            variant={isRunning ? "destructive" : "default"}
            onClick={isRunning ? stopSnort : startSnort}
          >
            {isRunning ? (
              <>
                <XCircle className="mr-2 h-4 w-4" />
                Stop Snort
              </>
            ) : (
              <>
                <Play className="mr-2 h-4 w-4" />
                Start Snort
              </>
            )}
          </Button>
        </div>
      </div>

      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium">Service Status</CardTitle>
            {isRunning ? (
              <CheckCircle2 className="h-4 w-4 text-green-500" />
            ) : (
              <XCircle className="h-4 w-4 text-red-500" />
            )}
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold capitalize">{isRunning ? "Running" : "Stopped"}</div>
            <p className="text-xs text-muted-foreground">
              {isRunning ? `Uptime: ${stats.uptime}` : "Service is offline"}
            </p>
          </CardContent>
        </Card>
        
        <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium">Packets</CardTitle>
            <Shield className="h-4 w-4 text-sentinel-accent" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats.packets_analyzed.toLocaleString()}</div>
            <p className="text-xs text-muted-foreground">
              {stats.packets_dropped} packets dropped
            </p>
          </CardContent>
        </Card>
        
        <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium">Alerts</CardTitle>
            <AlertCircle className="h-4 w-4 text-sentinel-warning" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats.alerts_generated}</div>
            <p className="text-xs text-muted-foreground">
              {alerts.filter(a => a.status === "new").length} need attention
            </p>
          </CardContent>
        </Card>
        
        <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium">Resources</CardTitle>
            <CircleAlert className="h-4 w-4 text-sentinel-info" />
          </CardHeader>
          <CardContent>
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs text-muted-foreground">CPU</span>
              <span className="text-xs">{stats.cpu_usage}%</span>
            </div>
            <Progress value={stats.cpu_usage} className="h-1 mb-3" />
            
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs text-muted-foreground">Memory</span>
              <span className="text-xs">{stats.memory_usage} MB</span>
            </div>
            <Progress value={(stats.memory_usage / 512) * 100} className="h-1" />
          </CardContent>
        </Card>
      </div>

      <Tabs defaultValue="rules" className="space-y-4">
        <TabsList className="grid grid-cols-4 md:w-[400px] bg-background/50">
          <TabsTrigger value="rules">Rules</TabsTrigger>
          <TabsTrigger value="alerts">Alerts</TabsTrigger>
          <TabsTrigger value="captures">Captures</TabsTrigger>
          <TabsTrigger value="configuration">Configuration</TabsTrigger>
        </TabsList>
        
        {/* Rules Tab */}
        <TabsContent value="rules" className="space-y-4">
          <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm">
            <CardHeader>
              <CardTitle>Snort Rules</CardTitle>
              <CardDescription>
                Define patterns for matching network traffic
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="flex flex-col md:flex-row gap-4">
                <div className="flex-1">
                  <div className="flex items-center space-x-2">
                    <div className="relative flex-1">
                      <SearchIcon className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
                      <Input
                        placeholder="Search rules..."
                        className="pl-8"
                        value={searchTerm}
                        onChange={(e) => setSearchTerm(e.target.value)}
                      />
                    </div>
                    <Select
                      value={filterCategory}
                      onValueChange={setFilterCategory}
                    >
                      <SelectTrigger className="w-[150px]">
                        <SelectValue placeholder="Category" />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="all">All Categories</SelectItem>
                        <SelectItem value="Web">Web</SelectItem>
                        <SelectItem value="Network">Network</SelectItem>
                        <SelectItem value="Remote Access">Remote Access</SelectItem>
                      </SelectContent>
                    </Select>
                    <Select
                      value={filterSeverity}
                      onValueChange={setFilterSeverity}
                    >
                      <SelectTrigger className="w-[150px]">
                        <SelectValue placeholder="Severity" />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="all">All Severities</SelectItem>
                        <SelectItem value="critical">Critical</SelectItem>
                        <SelectItem value="high">High</SelectItem>
                        <SelectItem value="medium">Medium</SelectItem>
                        <SelectItem value="low">Low</SelectItem>
                        <SelectItem value="info">Info</SelectItem>
                      </SelectContent>
                    </Select>
                    <Button 
                      variant="outline" 
                      size="icon"
                      onClick={() => {
                        setSearchTerm("");
                        setFilterCategory("all");
                        setFilterSeverity("all");
                      }}
                    >
                      <FilterX className="h-4 w-4" />
                    </Button>
                  </div>
                </div>
              </div>
              
              <div className="rounded-md border border-sentinel-light/10">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead className="w-[50px]">Status</TableHead>
                      <TableHead>Rule</TableHead>
                      <TableHead className="hidden md:table-cell">Category</TableHead>
                      <TableHead className="hidden md:table-cell">Severity</TableHead>
                      <TableHead className="text-right">Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {filteredRules.map((rule) => (
                      <TableRow key={rule.id}>
                        <TableCell>
                          <div
                            className={`h-3 w-3 rounded-full ${rule.enabled ? 'bg-green-500' : 'bg-gray-400'}`}
                            onClick={() => toggleRuleEnabled(rule.id)}
                            role="button"
                            tabIndex={0}
                            aria-label={rule.enabled ? "Disable rule" : "Enable rule"}
                          />
                        </TableCell>
                        <TableCell className="font-mono text-xs">
                          {rule.rule}
                          <div className="text-xs text-muted-foreground font-sans mt-1">
                            {rule.description}
                          </div>
                        </TableCell>
                        <TableCell className="hidden md:table-cell">{rule.category}</TableCell>
                        <TableCell className="hidden md:table-cell">
                          <Badge className={getSeverityBadgeClass(rule.severity)}>
                            {rule.severity}
                          </Badge>
                        </TableCell>
                        <TableCell className="text-right">
                          <Button variant="ghost" size="sm">
                            Edit
                          </Button>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
              
              <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm">
                <CardHeader>
                  <CardTitle>Add New Rule</CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="space-y-2">
                    <label className="text-sm font-medium" htmlFor="rule">Rule</label>
                    <Textarea 
                      id="rule"
                      placeholder="alert tcp any any -> any 80 (msg:\"HTTP Traffic\"; sid:1000001; rev:1;)"
                      value={newRule}
                      onChange={(e) => setNewRule(e.target.value)}
                      rows={3}
                      className="font-mono"
                    />
                  </div>
                  
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div className="space-y-2">
                      <label className="text-sm font-medium" htmlFor="category">Category</label>
                      <Select
                        value={newRuleCategory}
                        onValueChange={setNewRuleCategory}
                      >
                        <SelectTrigger>
                          <SelectValue placeholder="Select category" />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="Web">Web</SelectItem>
                          <SelectItem value="Network">Network</SelectItem>
                          <SelectItem value="Remote Access">Remote Access</SelectItem>
                          <SelectItem value="Malware">Malware</SelectItem>
                          <SelectItem value="DoS">DoS</SelectItem>
                          <SelectItem value="Policy">Policy</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                    
                    <div className="space-y-2">
                      <label className="text-sm font-medium" htmlFor="severity">Severity</label>
                      <Select
                        value={newRuleSeverity}
                        onValueChange={setNewRuleSeverity}
                      >
                        <SelectTrigger>
                          <SelectValue placeholder="Select severity" />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="critical">Critical</SelectItem>
                          <SelectItem value="high">High</SelectItem>
                          <SelectItem value="medium">Medium</SelectItem>
                          <SelectItem value="low">Low</SelectItem>
                          <SelectItem value="info">Info</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                  </div>
                  
                  <div className="space-y-2">
                    <label className="text-sm font-medium" htmlFor="description">Description</label>
                    <Textarea 
                      id="description"
                      placeholder="Briefly describe what this rule detects"
                      value={newRuleDescription}
                      onChange={(e) => setNewRuleDescription(e.target.value)}
                      rows={2}
                    />
                  </div>
                  
                  <div className="flex justify-end">
                    <Button onClick={handleAddRule} className="flex items-center">
                      <SaveIcon className="mr-2 h-4 w-4" />
                      Add Rule
                    </Button>
                  </div>
                </CardContent>
              </Card>
            </CardContent>
          </Card>
        </TabsContent>
        
        {/* Alerts Tab */}
        <TabsContent value="alerts" className="space-y-4">
          <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm">
            <CardHeader>
              <CardTitle>Snort Alerts</CardTitle>
              <CardDescription>
                Real-time alerts triggered by Snort rules
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="rounded-md border border-sentinel-light/10">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Time</TableHead>
                      <TableHead>Source</TableHead>
                      <TableHead>Destination</TableHead>
                      <TableHead>Message</TableHead>
                      <TableHead>Severity</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead className="text-right">Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {alerts.map((alert) => (
                      <TableRow key={alert.id}>
                        <TableCell>{new Date(alert.timestamp).toLocaleTimeString()}</TableCell>
                        <TableCell>{alert.source_ip}:{alert.source_port}</TableCell>
                        <TableCell>{alert.dest_ip}:{alert.dest_port}</TableCell>
                        <TableCell>{alert.message}</TableCell>
                        <TableCell>
                          <Badge className={getSeverityBadgeClass(alert.severity)}>
                            {alert.severity}
                          </Badge>
                        </TableCell>
                        <TableCell>
                          <Badge className={getStatusBadgeClass(alert.status)}>
                            {alert.status}
                          </Badge>
                        </TableCell>
                        <TableCell className="text-right">
                          {alert.status === "new" ? (
                            <>
                              <Button variant="ghost" size="sm" onClick={() => acknowledgeAlert(alert.id)}>
                                Acknowledge
                              </Button>
                              <Button variant="default" size="sm" onClick={() => resolveAlert(alert.id)}>
                                Resolve
                              </Button>
                            </>
                          ) : alert.status === "acknowledged" ? (
                            <Button variant="default" size="sm" onClick={() => resolveAlert(alert.id)}>
                              Resolve
                            </Button>
                          ) : (
                            <span className="text-muted-foreground">Resolved</span>
                          )}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
        
        {/* Captures Tab */}
        <TabsContent value="captures" className="space-y-4">
          <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm">
            <CardHeader>
              <CardTitle>Packet Captures</CardTitle>
              <CardDescription>
                Analyze network traffic from PCAP files
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="rounded-md border border-sentinel-light/10">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Name</TableHead>
                      <TableHead className="hidden md:table-cell">Date</TableHead>
                      <TableHead className="hidden md:table-cell">Size</TableHead>
                      <TableHead>Packets</TableHead>
                      <TableHead>Duration</TableHead>
                      <TableHead className="text-right">Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {captures.map((capture) => (
                      <TableRow key={capture.id}>
                        <TableCell>{capture.name}</TableCell>
                        <TableCell className="hidden md:table-cell">{new Date(capture.date).toLocaleDateString()}</TableCell>
                        <TableCell className="hidden md:table-cell">{capture.size}</TableCell>
                        <TableCell>{capture.packets.toLocaleString()}</TableCell>
                        <TableCell>{capture.duration}</TableCell>
                        <TableCell className="text-right">
                          {isAnalyzing && analyzeProgress < 100 ? (
                            <Button variant="ghost" size="sm" disabled>
                              Analyzing...
                              <RefreshCw className="ml-2 h-4 w-4 animate-spin" />
                            </Button>
                          ) : (
                            <Button variant="ghost" size="sm" onClick={() => analyzeCapture(capture.id)}>
                              Analyze
                            </Button>
                          )}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
              
              {isAnalyzing && (
                <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm">
                  <CardHeader>
                    <CardTitle>Analyzing Capture</CardTitle>
                    <CardDescription>
                      Analyzing packet capture for potential threats
                    </CardDescription>
                  </CardHeader>
                  <CardContent>
                    <Progress value={analyzeProgress} className="h-2" />
                    <p className="text-sm text-muted-foreground mt-2">
                      {analyzeProgress}% complete
                    </p>
                  </CardContent>
                </Card>
              )}
            </CardContent>
          </Card>
        </TabsContent>
        
        {/* Configuration Tab */}
        <TabsContent value="configuration" className="space-y-4">
          <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm">
            <CardHeader>
              <CardTitle>Snort Configuration</CardTitle>
              <CardDescription>
                Configure Snort settings and parameters
              </CardDescription>
            </CardHeader>
            <CardContent>
              <p>Configuration options coming soon...</p>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
};

export default SnortTool;
