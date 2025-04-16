
import { useState, useEffect } from "react";
import { Shield, AlertTriangle, X, Plus, Check, Globe, Network, Truck, Timer, RefreshCw } from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Progress } from "@/components/ui/progress";
import { toast } from "sonner";

// Mock blocked IPs
const initialBlockedIPs = [
  { 
    id: 1, 
    ip: "203.0.113.42", 
    reason: "Brute Force Attack", 
    timestamp: new Date(Date.now() - 15 * 60000).toISOString(), 
    duration: "Permanent", 
    source: "Manual" 
  },
  { 
    id: 2, 
    ip: "198.51.100.74", 
    reason: "Malware C2 Communication", 
    timestamp: new Date(Date.now() - 45 * 60000).toISOString(), 
    duration: "24 hours", 
    source: "Automated" 
  },
  { 
    id: 3, 
    ip: "203.0.113.15", 
    reason: "Port Scanning", 
    timestamp: new Date(Date.now() - 120 * 60000).toISOString(), 
    duration: "12 hours", 
    source: "Automated" 
  },
  { 
    id: 4, 
    ip: "198.51.100.123", 
    reason: "SQL Injection", 
    timestamp: new Date(Date.now() - 300 * 60000).toISOString(), 
    duration: "Permanent", 
    source: "Manual" 
  }
];

// Mock blocked ports
const initialBlockedPorts = [
  { 
    id: 1, 
    port: 3389, 
    protocol: "TCP", 
    direction: "Inbound", 
    reason: "RDP Vulnerability", 
    timestamp: new Date(Date.now() - 30 * 60000).toISOString(), 
    source: "Automated" 
  },
  { 
    id: 2, 
    port: 445, 
    protocol: "TCP", 
    direction: "Inbound", 
    reason: "SMB Vulnerability", 
    timestamp: new Date(Date.now() - 60 * 60000).toISOString(), 
    source: "Manual" 
  },
  { 
    id: 3, 
    port: 25, 
    protocol: "TCP", 
    direction: "Outbound", 
    reason: "Spam Prevention", 
    timestamp: new Date(Date.now() - 240 * 60000).toISOString(), 
    source: "Manual" 
  }
];

// Mock firewall rules
const initialFirewallRules = [
  { 
    id: 1, 
    name: "Block External RDP", 
    action: "block", 
    source: "any", 
    destination: "internal", 
    port: 3389, 
    protocol: "TCP", 
    enabled: true 
  },
  { 
    id: 2, 
    name: "Block Known Malware C2", 
    action: "block", 
    source: "198.51.100.0/24", 
    destination: "any", 
    port: "any", 
    protocol: "any", 
    enabled: true 
  },
  { 
    id: 3, 
    name: "Allow Internal HTTP", 
    action: "allow", 
    source: "internal", 
    destination: "internal", 
    port: 80, 
    protocol: "TCP", 
    enabled: true 
  },
  { 
    id: 4, 
    name: "Block Telnet", 
    action: "block", 
    source: "any", 
    destination: "internal", 
    port: 23, 
    protocol: "TCP", 
    enabled: true 
  },
  { 
    id: 5, 
    name: "Block External SMB", 
    action: "block", 
    source: "external", 
    destination: "internal", 
    port: 445, 
    protocol: "TCP", 
    enabled: true 
  }
];

// Mock recent block actions
const initialBlockActions = [
  {
    id: 1,
    timestamp: new Date(Date.now() - 5 * 60000).toISOString(),
    action: "IP Block",
    target: "203.0.113.42",
    reason: "Brute Force Attack",
    status: "success"
  },
  {
    id: 2,
    timestamp: new Date(Date.now() - 12 * 60000).toISOString(),
    action: "Port Block",
    target: "TCP 3389 (Inbound)",
    reason: "RDP Vulnerability",
    status: "success"
  },
  {
    id: 3,
    timestamp: new Date(Date.now() - 30 * 60000).toISOString(),
    action: "IP Block",
    target: "198.51.100.74",
    reason: "Malware C2 Communication",
    status: "success"
  },
  {
    id: 4,
    timestamp: new Date(Date.now() - 45 * 60000).toISOString(),
    action: "Rule Addition",
    target: "Block Known Malware C2",
    reason: "Automated protection",
    status: "success"
  },
  {
    id: 5,
    timestamp: new Date(Date.now() - 60 * 60000).toISOString(),
    action: "IP Block",
    target: "203.0.113.15",
    reason: "Port Scanning",
    status: "success"
  }
];

const TrafficBlocking = () => {
  const [blockedIPs, setBlockedIPs] = useState(initialBlockedIPs);
  const [blockedPorts, setBlockedPorts] = useState(initialBlockedPorts);
  const [firewallRules, setFirewallRules] = useState(initialFirewallRules);
  const [blockActions, setBlockActions] = useState(initialBlockActions);
  const [blockStatus, setBlockStatus] = useState("active");
  const [newIP, setNewIP] = useState("");
  const [ipReason, setIPReason] = useState("");
  const [ipDuration, setIPDuration] = useState("Permanent");
  const [newPort, setNewPort] = useState("");
  const [portProtocol, setPortProtocol] = useState("TCP");
  const [portDirection, setPortDirection] = useState("Inbound");
  const [portReason, setPortReason] = useState("");
  const [newRule, setNewRule] = useState({
    name: "",
    action: "block",
    source: "",
    destination: "",
    port: "",
    protocol: "TCP",
  });
  const [blockStats, setBlockStats] = useState({
    totalBlocked: 127,
    ipsBlocked: 42,
    portsBlocked: 15,
    activeRules: 5
  });
  const [systemStatus, setSystemStatus] = useState({
    cpu: 24,
    memory: 38,
    disk: 52,
    network: 65
  });

  // Simulate real-time block updates
  useEffect(() => {
    if (blockStatus !== "active") return;

    // Update system stats periodically
    const statsInterval = setInterval(() => {
      setSystemStatus({
        cpu: Math.floor(Math.random() * 30) + 15,
        memory: Math.floor(Math.random() * 20) + 30,
        disk: Math.floor(Math.random() * 15) + 45,
        network: Math.floor(Math.random() * 25) + 55
      });
      
      // Occasionally update block stats
      if (Math.random() > 0.7) {
        setBlockStats(prev => ({
          ...prev,
          totalBlocked: prev.totalBlocked + Math.floor(Math.random() * 3) + 1
        }));
      }
    }, 5000);
    
    // Occasionally add a new block action
    const actionInterval = setInterval(() => {
      if (Math.random() > 0.7) {
        const actionTypes = ["IP Block", "Port Block", "Rule Addition"];
        const randomType = actionTypes[Math.floor(Math.random() * actionTypes.length)];
        
        let target = "";
        let reason = "";
        
        if (randomType === "IP Block") {
          target = `192.168.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;
          reason = ["Brute Force Attack", "Malware C2 Communication", "Port Scanning", "SQL Injection"][Math.floor(Math.random() * 4)];
        } else if (randomType === "Port Block") {
          const commonPorts = [21, 22, 23, 25, 80, 443, 445, 3389, 8080];
          target = `${portProtocol} ${commonPorts[Math.floor(Math.random() * commonPorts.length)]} (${portDirection})`;
          reason = ["Vulnerability Mitigation", "Suspicious Activity", "Policy Enforcement"][Math.floor(Math.random() * 3)];
        } else {
          target = ["Block External Access", "Block Suspicious IPs", "Restrict Service Access"][Math.floor(Math.random() * 3)];
          reason = "Automated protection";
        }
        
        const newAction = {
          id: Math.floor(Math.random() * 10000),
          timestamp: new Date().toISOString(),
          action: randomType,
          target,
          reason,
          status: "success"
        };
        
        setBlockActions(prev => [newAction, ...prev.slice(0, 19)]);
        
        // Show toast notification for new action
        toast.info(`New ${randomType}`, {
          description: `${target}: ${reason}`
        });
        
        // If it was an IP block, add to blocked IPs
        if (randomType === "IP Block") {
          const newIP = {
            id: Math.floor(Math.random() * 10000),
            ip: target,
            reason,
            timestamp: new Date().toISOString(),
            duration: Math.random() > 0.5 ? "Permanent" : `${Math.floor(Math.random() * 24) + 1} hours`,
            source: "Automated"
          };
          
          setBlockedIPs(prev => [newIP, ...prev]);
          setBlockStats(prev => ({
            ...prev,
            ipsBlocked: prev.ipsBlocked + 1,
            totalBlocked: prev.totalBlocked + 1
          }));
        }
      }
    }, 30000);

    return () => {
      clearInterval(statsInterval);
      clearInterval(actionInterval);
    };
  }, [blockStatus, portDirection, portProtocol]);

  const toggleBlockStatus = () => {
    const newStatus = blockStatus === "active" ? "paused" : "active";
    setBlockStatus(newStatus);
    toast.info(`Traffic blocking ${newStatus}`);
  };

  const addBlockedIP = () => {
    if (!newIP) {
      toast.error("Please enter an IP address");
      return;
    }
    
    // Basic IP validation
    const ipPattern = /^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$/;
    if (!ipPattern.test(newIP)) {
      toast.error("Please enter a valid IP address");
      return;
    }
    
    if (!ipReason) {
      toast.error("Please enter a reason for blocking");
      return;
    }
    
    const newBlockedIP = {
      id: Math.floor(Math.random() * 10000),
      ip: newIP,
      reason: ipReason,
      timestamp: new Date().toISOString(),
      duration: ipDuration,
      source: "Manual"
    };
    
    setBlockedIPs([newBlockedIP, ...blockedIPs]);
    setBlockStats(prev => ({
      ...prev,
      ipsBlocked: prev.ipsBlocked + 1,
      totalBlocked: prev.totalBlocked + 1
    }));
    
    // Add action to block history
    const newAction = {
      id: Math.floor(Math.random() * 10000),
      timestamp: new Date().toISOString(),
      action: "IP Block",
      target: newIP,
      reason: ipReason,
      status: "success"
    };
    
    setBlockActions([newAction, ...blockActions]);
    
    // Reset form
    setNewIP("");
    setIPReason("");
    
    toast.success(`IP ${newIP} blocked successfully`);
  };

  const addBlockedPort = () => {
    if (!newPort) {
      toast.error("Please enter a port number");
      return;
    }
    
    // Port validation
    const portNum = parseInt(newPort);
    if (isNaN(portNum) || portNum < 1 || portNum > 65535) {
      toast.error("Please enter a valid port number (1-65535)");
      return;
    }
    
    if (!portReason) {
      toast.error("Please enter a reason for blocking");
      return;
    }
    
    const newBlockedPort = {
      id: Math.floor(Math.random() * 10000),
      port: portNum,
      protocol: portProtocol,
      direction: portDirection,
      reason: portReason,
      timestamp: new Date().toISOString(),
      source: "Manual"
    };
    
    setBlockedPorts([newBlockedPort, ...blockedPorts]);
    setBlockStats(prev => ({
      ...prev,
      portsBlocked: prev.portsBlocked + 1,
      totalBlocked: prev.totalBlocked + 1
    }));
    
    // Add action to block history
    const newAction = {
      id: Math.floor(Math.random() * 10000),
      timestamp: new Date().toISOString(),
      action: "Port Block",
      target: `${portProtocol} ${portNum} (${portDirection})`,
      reason: portReason,
      status: "success"
    };
    
    setBlockActions([newAction, ...blockActions]);
    
    // Reset form
    setNewPort("");
    setPortReason("");
    
    toast.success(`Port ${portNum} (${portProtocol}) blocked successfully`);
  };

  const addFirewallRule = () => {
    if (!newRule.name || !newRule.source || !newRule.destination || !newRule.port) {
      toast.error("Please fill in all rule fields");
      return;
    }
    
    const ruleToAdd = {
      ...newRule,
      id: Math.max(...firewallRules.map(r => r.id), 0) + 1,
      enabled: true
    };
    
    setFirewallRules([ruleToAdd, ...firewallRules]);
    setBlockStats(prev => ({
      ...prev,
      activeRules: prev.activeRules + 1,
      totalBlocked: prev.totalBlocked + 1
    }));
    
    // Add action to block history
    const newAction = {
      id: Math.floor(Math.random() * 10000),
      timestamp: new Date().toISOString(),
      action: "Rule Addition",
      target: ruleToAdd.name,
      reason: "Manual rule creation",
      status: "success"
    };
    
    setBlockActions([newAction, ...blockActions]);
    
    // Reset form
    setNewRule({
      name: "",
      action: "block",
      source: "",
      destination: "",
      port: "",
      protocol: "TCP",
    });
    
    toast.success(`Firewall rule "${ruleToAdd.name}" added successfully`);
  };

  const removeBlockedIP = (id: number) => {
    const ip = blockedIPs.find(i => i.id === id);
    if (ip) {
      setBlockedIPs(blockedIPs.filter(i => i.id !== id));
      setBlockStats(prev => ({
        ...prev,
        ipsBlocked: Math.max(0, prev.ipsBlocked - 1)
      }));
      toast.success(`IP ${ip.ip} unblocked`);
    }
  };

  const removeBlockedPort = (id: number) => {
    const port = blockedPorts.find(p => p.id === id);
    if (port) {
      setBlockedPorts(blockedPorts.filter(p => p.id !== id));
      setBlockStats(prev => ({
        ...prev,
        portsBlocked: Math.max(0, prev.portsBlocked - 1)
      }));
      toast.success(`Port ${port.port} (${port.protocol}) unblocked`);
    }
  };

  const toggleFirewallRule = (id: number) => {
    setFirewallRules(firewallRules.map(rule => 
      rule.id === id ? { ...rule, enabled: !rule.enabled } : rule
    ));
    
    const rule = firewallRules.find(r => r.id === id);
    if (rule) {
      setBlockStats(prev => ({
        ...prev,
        activeRules: rule.enabled ? prev.activeRules - 1 : prev.activeRules + 1
      }));
      toast.info(`Rule "${rule.name}" ${rule.enabled ? 'disabled' : 'enabled'}`);
    }
  };

  const formatTimestamp = (timestamp: string) => {
    const date = new Date(timestamp);
    return date.toLocaleTimeString();
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-3xl font-bold tracking-tight">Traffic Blocking</h2>
          <p className="text-muted-foreground">
            Automated prevention of malicious network activity
          </p>
        </div>
        <div className="flex items-center space-x-2">
          <Button 
            variant={blockStatus === "active" ? "destructive" : "default"}
            onClick={toggleBlockStatus}
          >
            {blockStatus === "active" ? "Disable Blocking" : "Enable Blocking"}
          </Button>
        </div>
      </div>

      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium">Total Blocked</CardTitle>
            <Shield className="h-4 w-4 text-sentinel-success" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{blockStats.totalBlocked}</div>
            <p className="text-xs text-muted-foreground">
              Threats blocked this session
            </p>
          </CardContent>
        </Card>
        
        <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium">IPs Blocked</CardTitle>
            <Globe className="h-4 w-4 text-sentinel-info" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{blockStats.ipsBlocked}</div>
            <p className="text-xs text-muted-foreground">
              Individual IP addresses
            </p>
          </CardContent>
        </Card>
        
        <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium">Ports Blocked</CardTitle>
            <Network className="h-4 w-4 text-sentinel-warning" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{blockStats.portsBlocked}</div>
            <p className="text-xs text-muted-foreground">
              Network ports restricted
            </p>
          </CardContent>
        </Card>
        
        <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium">Active Rules</CardTitle>
            <AlertTriangle className="h-4 w-4 text-sentinel-accent" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{blockStats.activeRules}</div>
            <p className="text-xs text-muted-foreground">
              Firewall rules enabled
            </p>
          </CardContent>
        </Card>
      </div>

      <div className="grid gap-4 md:grid-cols-4">
        <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm col-span-3">
          <CardHeader>
            <CardTitle>Recent Block Actions</CardTitle>
            <CardDescription>
              History of traffic blocking measures
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="rounded-md border border-sentinel-light/10">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Time</TableHead>
                    <TableHead>Action</TableHead>
                    <TableHead>Target</TableHead>
                    <TableHead className="hidden md:table-cell">Reason</TableHead>
                    <TableHead>Status</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {blockActions.slice(0, 10).map((action) => (
                    <TableRow key={action.id} className="animate-fade-in">
                      <TableCell>
                        {formatTimestamp(action.timestamp)}
                      </TableCell>
                      <TableCell className="font-medium">{action.action}</TableCell>
                      <TableCell>{action.target}</TableCell>
                      <TableCell className="hidden md:table-cell">{action.reason}</TableCell>
                      <TableCell>
                        <Badge 
                          className={
                            action.status === "success" 
                              ? "bg-green-500 text-black" 
                              : "bg-red-500 text-white"
                          }
                        >
                          {action.status}
                        </Badge>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          </CardContent>
        </Card>
        
        <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm">
          <CardHeader>
            <CardTitle>System Status</CardTitle>
            <CardDescription>
              Resource utilization
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2">
              <div className="flex items-center justify-between text-sm">
                <span>CPU</span>
                <span className="font-bold">{systemStatus.cpu}%</span>
              </div>
              <Progress value={systemStatus.cpu} className="h-2" />
            </div>
            
            <div className="space-y-2">
              <div className="flex items-center justify-between text-sm">
                <span>Memory</span>
                <span className="font-bold">{systemStatus.memory}%</span>
              </div>
              <Progress value={systemStatus.memory} className="h-2" />
            </div>
            
            <div className="space-y-2">
              <div className="flex items-center justify-between text-sm">
                <span>Disk</span>
                <span className="font-bold">{systemStatus.disk}%</span>
              </div>
              <Progress value={systemStatus.disk} className="h-2" />
            </div>
            
            <div className="space-y-2">
              <div className="flex items-center justify-between text-sm">
                <span>Network</span>
                <span className="font-bold">{systemStatus.network}%</span>
              </div>
              <Progress value={systemStatus.network} className="h-2" />
            </div>
            
            <Button 
              variant="outline" 
              className="w-full mt-2"
              onClick={() => {
                setSystemStatus({
                  cpu: Math.floor(Math.random() * 30) + 15,
                  memory: Math.floor(Math.random() * 20) + 30,
                  disk: Math.floor(Math.random() * 15) + 45,
                  network: Math.floor(Math.random() * 25) + 55
                });
              }}
            >
              <RefreshCw className="mr-2 h-4 w-4" />
              Refresh Status
            </Button>
          </CardContent>
        </Card>
      </div>

      <Tabs defaultValue="ips" className="space-y-4">
        <TabsList className="grid grid-cols-3 md:w-[400px] bg-background/50">
          <TabsTrigger value="ips">Blocked IPs</TabsTrigger>
          <TabsTrigger value="ports">Blocked Ports</TabsTrigger>
          <TabsTrigger value="rules">Firewall Rules</TabsTrigger>
        </TabsList>
        
        <TabsContent value="ips" className="space-y-4">
          <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm">
            <CardHeader>
              <CardTitle>Add IP Block</CardTitle>
              <CardDescription>
                Block a specific IP address from accessing your network
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div className="space-y-2">
                  <Label htmlFor="ip-address">IP Address</Label>
                  <Input 
                    id="ip-address"
                    placeholder="192.168.1.1"
                    value={newIP}
                    onChange={(e) => setNewIP(e.target.value)}
                  />
                </div>
                
                <div className="space-y-2">
                  <Label htmlFor="ip-reason">Reason</Label>
                  <Input 
                    id="ip-reason"
                    placeholder="Suspicious activity"
                    value={ipReason}
                    onChange={(e) => setIPReason(e.target.value)}
                  />
                </div>
                
                <div className="space-y-2">
                  <Label htmlFor="ip-duration">Duration</Label>
                  <select
                    id="ip-duration"
                    className="flex h-10 w-full rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2"
                    value={ipDuration}
                    onChange={(e) => setIPDuration(e.target.value)}
                  >
                    <option value="1 hour">1 hour</option>
                    <option value="6 hours">6 hours</option>
                    <option value="12 hours">12 hours</option>
                    <option value="24 hours">24 hours</option>
                    <option value="Permanent">Permanent</option>
                  </select>
                </div>
              </div>
              
              <Button 
                className="w-full mt-4"
                onClick={addBlockedIP}
              >
                <Plus className="mr-2 h-4 w-4" /> Block IP Address
              </Button>
            </CardContent>
          </Card>
          
          <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm">
            <CardHeader>
              <CardTitle>Blocked IP Addresses</CardTitle>
              <CardDescription>
                Currently blocked IP addresses
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="rounded-md border border-sentinel-light/10">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>IP Address</TableHead>
                      <TableHead>Reason</TableHead>
                      <TableHead className="hidden md:table-cell">Time</TableHead>
                      <TableHead className="hidden md:table-cell">Duration</TableHead>
                      <TableHead>Source</TableHead>
                      <TableHead className="text-right">Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {blockedIPs.map((ip) => (
                      <TableRow key={ip.id} className="animate-fade-in">
                        <TableCell className="font-medium">{ip.ip}</TableCell>
                        <TableCell>{ip.reason}</TableCell>
                        <TableCell className="hidden md:table-cell">{formatTimestamp(ip.timestamp)}</TableCell>
                        <TableCell className="hidden md:table-cell">{ip.duration}</TableCell>
                        <TableCell>
                          <Badge 
                            className={
                              ip.source === "Manual" 
                                ? "bg-blue-500 text-white" 
                                : "bg-green-500 text-black"
                            }
                          >
                            {ip.source}
                          </Badge>
                        </TableCell>
                        <TableCell className="text-right">
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => removeBlockedIP(ip.id)}
                            className="text-destructive"
                          >
                            <X className="h-4 w-4" />
                          </Button>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
        
        <TabsContent value="ports" className="space-y-4">
          <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm">
            <CardHeader>
              <CardTitle>Add Port Block</CardTitle>
              <CardDescription>
                Block network traffic on a specific port
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                <div className="space-y-2">
                  <Label htmlFor="port-number">Port Number</Label>
                  <Input 
                    id="port-number"
                    placeholder="80"
                    value={newPort}
                    onChange={(e) => setNewPort(e.target.value)}
                  />
                </div>
                
                <div className="space-y-2">
                  <Label htmlFor="port-protocol">Protocol</Label>
                  <select
                    id="port-protocol"
                    className="flex h-10 w-full rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2"
                    value={portProtocol}
                    onChange={(e) => setPortProtocol(e.target.value)}
                  >
                    <option value="TCP">TCP</option>
                    <option value="UDP">UDP</option>
                    <option value="TCP/UDP">TCP/UDP</option>
                  </select>
                </div>
                
                <div className="space-y-2">
                  <Label htmlFor="port-direction">Direction</Label>
                  <select
                    id="port-direction"
                    className="flex h-10 w-full rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2"
                    value={portDirection}
                    onChange={(e) => setPortDirection(e.target.value)}
                  >
                    <option value="Inbound">Inbound</option>
                    <option value="Outbound">Outbound</option>
                    <option value="Both">Both</option>
                  </select>
                </div>
                
                <div className="space-y-2">
                  <Label htmlFor="port-reason">Reason</Label>
                  <Input 
                    id="port-reason"
                    placeholder="Vulnerability mitigation"
                    value={portReason}
                    onChange={(e) => setPortReason(e.target.value)}
                  />
                </div>
              </div>
              
              <Button 
                className="w-full mt-4"
                onClick={addBlockedPort}
              >
                <Plus className="mr-2 h-4 w-4" /> Block Port
              </Button>
            </CardContent>
          </Card>
          
          <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm">
            <CardHeader>
              <CardTitle>Blocked Ports</CardTitle>
              <CardDescription>
                Currently blocked network ports
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="rounded-md border border-sentinel-light/10">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Port</TableHead>
                      <TableHead>Protocol</TableHead>
                      <TableHead>Direction</TableHead>
                      <TableHead className="hidden md:table-cell">Reason</TableHead>
                      <TableHead className="hidden md:table-cell">Time</TableHead>
                      <TableHead className="text-right">Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {blockedPorts.map((port) => (
                      <TableRow key={port.id} className="animate-fade-in">
                        <TableCell className="font-medium">{port.port}</TableCell>
                        <TableCell>{port.protocol}</TableCell>
                        <TableCell>{port.direction}</TableCell>
                        <TableCell className="hidden md:table-cell">{port.reason}</TableCell>
                        <TableCell className="hidden md:table-cell">{formatTimestamp(port.timestamp)}</TableCell>
                        <TableCell className="text-right">
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => removeBlockedPort(port.id)}
                            className="text-destructive"
                          >
                            <X className="h-4 w-4" />
                          </Button>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
        
        <TabsContent value="rules" className="space-y-4">
          <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm">
            <CardHeader>
              <CardTitle>Add Firewall Rule</CardTitle>
              <CardDescription>
                Create a custom firewall rule
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div className="space-y-2">
                  <Label htmlFor="rule-name">Rule Name</Label>
                  <Input 
                    id="rule-name"
                    placeholder="Block External RDP"
                    value={newRule.name}
                    onChange={(e) => setNewRule({...newRule, name: e.target.value})}
                  />
                </div>
                
                <div className="space-y-2">
                  <Label htmlFor="rule-action">Action</Label>
                  <select
                    id="rule-action"
                    className="flex h-10 w-full rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2"
                    value={newRule.action}
                    onChange={(e) => setNewRule({...newRule, action: e.target.value})}
                  >
                    <option value="block">Block</option>
                    <option value="allow">Allow</option>
                  </select>
                </div>
                
                <div className="space-y-2">
                  <Label htmlFor="rule-protocol">Protocol</Label>
                  <select
                    id="rule-protocol"
                    className="flex h-10 w-full rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2"
                    value={newRule.protocol}
                    onChange={(e) => setNewRule({...newRule, protocol: e.target.value})}
                  >
                    <option value="TCP">TCP</option>
                    <option value="UDP">UDP</option>
                    <option value="ICMP">ICMP</option>
                    <option value="any">Any</option>
                  </select>
                </div>
                
                <div className="space-y-2">
                  <Label htmlFor="rule-source">Source</Label>
                  <Input 
                    id="rule-source"
                    placeholder="any, internal, 192.168.1.0/24"
                    value={newRule.source}
                    onChange={(e) => setNewRule({...newRule, source: e.target.value})}
                  />
                </div>
                
                <div className="space-y-2">
                  <Label htmlFor="rule-destination">Destination</Label>
                  <Input 
                    id="rule-destination"
                    placeholder="any, internal, 10.0.0.1"
                    value={newRule.destination}
                    onChange={(e) => setNewRule({...newRule, destination: e.target.value})}
                  />
                </div>
                
                <div className="space-y-2">
                  <Label htmlFor="rule-port">Port</Label>
                  <Input 
                    id="rule-port"
                    placeholder="80, 443, any"
                    value={newRule.port}
                    onChange={(e) => setNewRule({...newRule, port: e.target.value})}
                  />
                </div>
              </div>
              
              <Button 
                className="w-full mt-4"
                onClick={addFirewallRule}
              >
                <Plus className="mr-2 h-4 w-4" /> Add Rule
              </Button>
            </CardContent>
          </Card>
          
          <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm">
            <CardHeader>
              <CardTitle>Firewall Rules</CardTitle>
              <CardDescription>
                Active firewall rules configuration
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="rounded-md border border-sentinel-light/10">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Status</TableHead>
                      <TableHead>Name</TableHead>
                      <TableHead>Action</TableHead>
                      <TableHead className="hidden md:table-cell">Source</TableHead>
                      <TableHead className="hidden md:table-cell">Destination</TableHead>
                      <TableHead className="hidden md:table-cell">Port</TableHead>
                      <TableHead className="text-right">Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {firewallRules.map((rule) => (
                      <TableRow key={rule.id} className="animate-fade-in">
                        <TableCell>
                          <div 
                            className={`w-3 h-3 rounded-full ${rule.enabled ? 'bg-green-500' : 'bg-red-500'}`}
                          ></div>
                        </TableCell>
                        <TableCell className="font-medium">{rule.name}</TableCell>
                        <TableCell className="capitalize">{rule.action}</TableCell>
                        <TableCell className="hidden md:table-cell">{rule.source}</TableCell>
                        <TableCell className="hidden md:table-cell">{rule.destination}</TableCell>
                        <TableCell className="hidden md:table-cell">{rule.port}</TableCell>
                        <TableCell className="text-right">
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => toggleFirewallRule(rule.id)}
                          >
                            {rule.enabled ? 'Disable' : 'Enable'}
                          </Button>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
};

export default TrafficBlocking;
