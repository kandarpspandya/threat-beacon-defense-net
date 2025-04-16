
import { useState, useEffect } from "react";
import { Shield, Terminal, Play, AlertTriangle, FileText, X, Check, RefreshCw, Edit, Trash, Plus, Save } from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Progress } from "@/components/ui/progress";
import { toast } from "sonner";
import { ScrollArea } from "@/components/ui/scroll-area";

// Mock Snort rules
const initialRules = [
  {
    id: 1,
    enabled: true,
    rule: 'alert tcp any any -> $HOME_NET 22 (msg:"SSH brute force attempt"; flow:to_server; threshold:type threshold, track by_src, count 5, seconds 60; classtype:attempted-admin; sid:1000001; rev:1;)',
    description: "Detects SSH brute force attempts"
  },
  {
    id: 2,
    enabled: true,
    rule: 'alert tcp any any -> $HOME_NET 80 (msg:"SQL Injection attempt"; content:"SELECT"; nocase; content:"FROM"; nocase; content:"WHERE"; nocase; pcre:"/(union|select|insert|update|delete|replace|truncate)/i"; classtype:web-application-attack; sid:1000002; rev:1;)',
    description: "Detects SQL injection attempts in HTTP requests"
  },
  {
    id: 3,
    enabled: true,
    rule: 'alert tcp any any -> any any (msg:"Malware C2 Communication"; content:"|00 00 00 01 00 00 00 00|"; depth:8; classtype:trojan-activity; sid:1000003; rev:1;)',
    description: "Detects communication with known malware command and control servers"
  },
  {
    id: 4,
    enabled: true,
    rule: 'alert tcp any any -> $HOME_NET any (msg:"Port Scanning"; flags:S; threshold:type threshold, track by_src, count 20, seconds 60; classtype:attempted-recon; sid:1000004; rev:1;)',
    description: "Detects port scanning activity"
  },
  {
    id: 5,
    enabled: false,
    rule: 'alert udp any any -> any 53 (msg:"DNS Tunneling"; content:"|01 00 00 01 00 00 00 00 00 00|"; depth:10; content:!"|03|www"; content:!"|06|google"; content:!"|05|gmail"; pcre:"/[a-zA-Z0-9-]{30,}\\.(com|net|org)/i"; classtype:trojan-activity; sid:1000005; rev:1;)',
    description: "Detects potential DNS tunneling"
  }
];

// Mock alerts based on the rules
const initialAlerts = [
  {
    id: 1,
    timestamp: new Date(Date.now() - 5 * 60000).toISOString(),
    rule_id: 1,
    source_ip: "203.0.113.42",
    destination_ip: "192.168.1.10",
    message: "SSH brute force attempt",
    protocol: "TCP",
    source_port: 45123,
    destination_port: 22,
    severity: "high",
    details: "Multiple failed SSH login attempts detected"
  },
  {
    id: 2,
    timestamp: new Date(Date.now() - 15 * 60000).toISOString(),
    rule_id: 2,
    source_ip: "203.0.113.15",
    destination_ip: "192.168.1.25",
    message: "SQL Injection attempt",
    protocol: "TCP",
    source_port: 55123,
    destination_port: 80,
    severity: "critical",
    details: "Malicious SQL pattern detected in HTTP request"
  },
  {
    id: 3,
    timestamp: new Date(Date.now() - 30 * 60000).toISOString(),
    rule_id: 3,
    source_ip: "192.168.1.35",
    destination_ip: "198.51.100.74",
    message: "Malware C2 Communication",
    protocol: "TCP",
    source_port: 49347,
    destination_port: 443,
    severity: "critical",
    details: "Communication with known malware C2 server detected"
  },
  {
    id: 4,
    timestamp: new Date(Date.now() - 60 * 60000).toISOString(),
    rule_id: 4,
    source_ip: "203.0.113.67",
    destination_ip: "192.168.1.1",
    message: "Port Scanning",
    protocol: "TCP",
    source_port: 34567,
    destination_port: "multiple",
    severity: "medium",
    details: "Sequential port scan detected targeting multiple ports"
  }
];

// Mock console output
const initialConsoleOutput = [
  { timestamp: new Date(Date.now() - 120000).toISOString(), message: "Snort starting..." },
  { timestamp: new Date(Date.now() - 115000).toISOString(), message: "Loading rules from local configuration..." },
  { timestamp: new Date(Date.now() - 110000).toISOString(), message: "Loaded 5 rules successfully" },
  { timestamp: new Date(Date.now() - 105000).toISOString(), message: "Initializing network interfaces..." },
  { timestamp: new Date(Date.now() - 100000).toISOString(), message: "Listening on interface eth0" },
  { timestamp: new Date(Date.now() - 95000).toISOString(), message: "Starting packet processing engine..." },
  { timestamp: new Date(Date.now() - 90000).toISOString(), message: "Snort IDS/IPS engine running" },
  { timestamp: new Date(Date.now() - 60000).toISOString(), message: "ALERT: [1:1000001:1] SSH brute force attempt [Classification: Attempted Administrator Privilege Gain] [Priority: 1] {TCP} 203.0.113.42:45123 -> 192.168.1.10:22" },
  { timestamp: new Date(Date.now() - 30000).toISOString(), message: "ALERT: [1:1000002:1] SQL Injection attempt [Classification: Web Application Attack] [Priority: 1] {TCP} 203.0.113.15:55123 -> 192.168.1.25:80" },
  { timestamp: new Date(Date.now() - 10000).toISOString(), message: "Packet statistics: Received: 15243, Analyzed: 15243, Dropped: 0" }
];

const SnortTool = () => {
  const [rules, setRules] = useState(initialRules);
  const [alerts, setAlerts] = useState(initialAlerts);
  const [consoleOutput, setConsoleOutput] = useState(initialConsoleOutput);
  const [snortStatus, setSnortStatus] = useState("running");
  const [editingRule, setEditingRule] = useState<any>(null);
  const [newRule, setNewRule] = useState({
    rule: "",
    description: ""
  });
  const [stats, setStats] = useState({
    packetsAnalyzed: 15243,
    alertsGenerated: 4,
    rulesFired: 3,
    dropper: false,
    uptime: "00:45:20"
  });
  const [selectedAlert, setSelectedAlert] = useState<any>(null);
  
  // Simulate Snort runtime
  useEffect(() => {
    if (snortStatus !== "running") return;
    
    // Update console output periodically
    const consoleInterval = setInterval(() => {
      // Generate a new console message
      const messageTypes = [
        "Packet statistics: Received: {packets}, Analyzed: {packets}, Dropped: 0",
        "Processing traffic from network segments: 192.168.1.0/24 -> External Networks",
        "Current packet rate: {rate} packets/sec",
        "Snort instance healthy, memory usage: {memory}MB",
        "No fragmentation attacks detected in the last 5 minutes",
        "Rule performance: Average match time {time}ms"
      ];
      
      const randomType = messageTypes[Math.floor(Math.random() * messageTypes.length)];
      const newPackets = stats.packetsAnalyzed + Math.floor(Math.random() * 500) + 100;
      const rate = Math.floor(Math.random() * 200) + 100;
      const memory = Math.floor(Math.random() * 100) + 150;
      const time = (Math.random() * 0.5 + 0.1).toFixed(2);
      
      let message = randomType
        .replace("{packets}", newPackets.toString())
        .replace("{rate}", rate.toString())
        .replace("{memory}", memory.toString())
        .replace("{time}", time);
      
      // Occasionally generate an alert
      if (Math.random() > 0.7) {
        const randomRule = rules[Math.floor(Math.random() * rules.length)];
        if (randomRule && randomRule.enabled) {
          const srcIP = `203.0.113.${Math.floor(Math.random() * 255)}`;
          const dstIP = `192.168.1.${Math.floor(Math.random() * 255)}`;
          const srcPort = Math.floor(Math.random() * 60000) + 1024;
          const dstPort = randomRule.rule.includes("22") ? 22 : 
                         randomRule.rule.includes("80") ? 80 : 
                         randomRule.rule.includes("443") ? 443 : 
                         Math.floor(Math.random() * 1000);
          
          const alertMessage = `ALERT: [1:${randomRule.id}:1] ${randomRule.description} [Priority: 1] {TCP} ${srcIP}:${srcPort} -> ${dstIP}:${dstPort}`;
          
          setConsoleOutput(prev => [...prev, {
            timestamp: new Date().toISOString(),
            message: alertMessage
          }]);
          
          // Also add to alerts
          const newAlert = {
            id: Date.now(),
            timestamp: new Date().toISOString(),
            rule_id: randomRule.id,
            source_ip: srcIP,
            destination_ip: dstIP,
            message: randomRule.description,
            protocol: "TCP",
            source_port: srcPort,
            destination_port: dstPort,
            severity: randomRule.rule.includes("attempted-admin") ? "high" : 
                     randomRule.rule.includes("web-application-attack") ? "critical" : 
                     randomRule.rule.includes("trojan-activity") ? "critical" : "medium",
            details: `Alert triggered by Snort rule id ${randomRule.id}`
          };
          
          setAlerts(prev => [newAlert, ...prev]);
          setStats(prev => ({
            ...prev,
            alertsGenerated: prev.alertsGenerated + 1,
            rulesFired: Math.min(rules.length, prev.rulesFired + (Math.random() > 0.7 ? 1 : 0))
          }));
          
          // Show toast for new alert
          toast.warning(`New Snort Alert: ${randomRule.description}`, {
            description: `From ${srcIP} to ${dstIP}`,
            action: {
              label: "View",
              onClick: () => setSelectedAlert(newAlert)
            }
          });
        }
      } else {
        setConsoleOutput(prev => [...prev, {
          timestamp: new Date().toISOString(),
          message
        }]);
      }
      
      // Update stats
      setStats(prev => {
        // Parse uptime and add seconds
        const [hours, minutes, seconds] = prev.uptime.split(':').map(Number);
        const uptimeInSeconds = hours * 3600 + minutes * 60 + seconds + 10;
        const newHours = Math.floor(uptimeInSeconds / 3600);
        const newMinutes = Math.floor((uptimeInSeconds % 3600) / 60);
        const newSeconds = uptimeInSeconds % 60;
        
        // Format with leading zeros
        const formattedUptime = `${newHours.toString().padStart(2, '0')}:${newMinutes.toString().padStart(2, '0')}:${newSeconds.toString().padStart(2, '0')}`;
        
        return {
          ...prev,
          packetsAnalyzed: newPackets,
          uptime: formattedUptime
        };
      });
    }, 10000);
    
    return () => clearInterval(consoleInterval);
  }, [snortStatus, rules, stats]);
  
  const toggleSnortStatus = () => {
    const newStatus = snortStatus === "running" ? "stopped" : "running";
    setSnortStatus(newStatus);
    
    const statusMessage = {
      timestamp: new Date().toISOString(),
      message: newStatus === "running" ? "Snort engine started" : "Snort engine stopped"
    };
    
    setConsoleOutput(prev => [...prev, statusMessage]);
    
    toast.info(`Snort ${newStatus}`, {
      description: newStatus === "running" ? "IDS engine is now active" : "IDS engine has been stopped"
    });
  };
  
  const toggleRuleStatus = (id: number) => {
    setRules(rules.map(rule => 
      rule.id === id ? { ...rule, enabled: !rule.enabled } : rule
    ));
    
    const rule = rules.find(r => r.id === id);
    if (rule) {
      const statusMessage = {
        timestamp: new Date().toISOString(),
        message: `Rule ${id} ${rule.enabled ? 'disabled' : 'enabled'}: ${rule.description}`
      };
      
      setConsoleOutput(prev => [...prev, statusMessage]);
      
      toast.info(`Rule ${rule.enabled ? 'disabled' : 'enabled'}`, {
        description: rule.description
      });
    }
  };
  
  const editRule = (rule: any) => {
    setEditingRule(rule);
  };
  
  const deleteRule = (id: number) => {
    const rule = rules.find(r => r.id === id);
    if (rule) {
      setRules(rules.filter(r => r.id !== id));
      
      const statusMessage = {
        timestamp: new Date().toISOString(),
        message: `Rule ${id} deleted: ${rule.description}`
      };
      
      setConsoleOutput(prev => [...prev, statusMessage]);
      
      toast.success(`Rule deleted`, {
        description: rule.description
      });
    }
  };
  
  const saveRule = () => {
    if (!editingRule.rule || !editingRule.description) {
      toast.error("Rule content and description are required");
      return;
    }
    
    setRules(rules.map(rule => 
      rule.id === editingRule.id ? editingRule : rule
    ));
    
    const statusMessage = {
      timestamp: new Date().toISOString(),
      message: `Rule ${editingRule.id} updated: ${editingRule.description}`
    };
    
    setConsoleOutput(prev => [...prev, statusMessage]);
    
    toast.success(`Rule updated`, {
      description: editingRule.description
    });
    
    setEditingRule(null);
  };
  
  const addRule = () => {
    if (!newRule.rule || !newRule.description) {
      toast.error("Rule content and description are required");
      return;
    }
    
    const ruleToAdd = {
      ...newRule,
      id: Math.max(...rules.map(r => r.id), 0) + 1,
      enabled: true
    };
    
    setRules([...rules, ruleToAdd]);
    
    const statusMessage = {
      timestamp: new Date().toISOString(),
      message: `Rule ${ruleToAdd.id} added: ${ruleToAdd.description}`
    };
    
    setConsoleOutput(prev => [...prev, statusMessage]);
    
    toast.success(`Rule added`, {
      description: ruleToAdd.description
    });
    
    setNewRule({
      rule: "",
      description: ""
    });
  };
  
  const toggleDropperMode = () => {
    setStats({
      ...stats,
      dropper: !stats.dropper
    });
    
    const statusMessage = {
      timestamp: new Date().toISOString(),
      message: `IPS mode ${!stats.dropper ? 'enabled' : 'disabled'}: ${!stats.dropper ? 'Dropping' : 'Only alerting on'} malicious packets`
    };
    
    setConsoleOutput(prev => [...prev, statusMessage]);
    
    toast.info(`IPS mode ${!stats.dropper ? 'enabled' : 'disabled'}`, {
      description: !stats.dropper ? 'Malicious packets will be dropped' : 'Alerts only mode activated'
    });
  };
  
  const clearConsole = () => {
    setConsoleOutput([{
      timestamp: new Date().toISOString(),
      message: "Console cleared"
    }]);
  };
  
  const formatTimestamp = (timestamp: string) => {
    const date = new Date(timestamp);
    return date.toLocaleTimeString();
  };
  
  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-3xl font-bold tracking-tight">Snort IDS/IPS</h2>
          <p className="text-muted-foreground">
            Open-source intrusion detection and prevention system
          </p>
        </div>
        <div className="flex items-center space-x-2">
          <Button 
            variant={stats.dropper ? "destructive" : "outline"}
            onClick={toggleDropperMode}
          >
            {stats.dropper ? "IPS Mode (Active)" : "IDS Mode (Passive)"}
          </Button>
          <Button 
            variant={snortStatus === "running" ? "destructive" : "default"}
            onClick={toggleSnortStatus}
          >
            {snortStatus === "running" ? "Stop Snort" : "Start Snort"}
          </Button>
        </div>
      </div>

      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium">Engine Status</CardTitle>
            <Shield className={`h-4 w-4 ${snortStatus === "running" ? "text-sentinel-success" : "text-destructive"}`} />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold capitalize">{snortStatus}</div>
            <p className="text-xs text-muted-foreground">
              Uptime: {stats.uptime}
            </p>
          </CardContent>
        </Card>
        
        <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium">Packets Analyzed</CardTitle>
            <Terminal className="h-4 w-4 text-sentinel-info" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats.packetsAnalyzed.toLocaleString()}</div>
            <p className="text-xs text-muted-foreground">
              {Math.round(stats.packetsAnalyzed / (stats.uptime.split(":")[0] * 60 + parseInt(stats.uptime.split(":")[1])))} packets/min
            </p>
          </CardContent>
        </Card>
        
        <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium">Alerts Generated</CardTitle>
            <AlertTriangle className="h-4 w-4 text-sentinel-warning" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats.alertsGenerated}</div>
            <p className="text-xs text-muted-foreground">
              From {stats.rulesFired} different rules
            </p>
          </CardContent>
        </Card>
        
        <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium">Active Rules</CardTitle>
            <FileText className="h-4 w-4 text-sentinel-accent" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{rules.filter(r => r.enabled).length}</div>
            <p className="text-xs text-muted-foreground">
              {rules.length} total rules configured
            </p>
          </CardContent>
        </Card>
      </div>

      <Tabs defaultValue="console" className="space-y-4">
        <TabsList className="grid grid-cols-3 md:w-[400px] bg-background/50">
          <TabsTrigger value="console">Console Output</TabsTrigger>
          <TabsTrigger value="rules">Rules</TabsTrigger>
          <TabsTrigger value="alerts">Alerts</TabsTrigger>
        </TabsList>
        
        <TabsContent value="console" className="space-y-4">
          <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm">
            <CardHeader className="flex justify-between items-center">
              <div>
                <CardTitle>Snort Console</CardTitle>
                <CardDescription>
                  Real-time engine output
                </CardDescription>
              </div>
              <Button 
                variant="outline"
                size="sm"
                onClick={clearConsole}
              >
                Clear Console
              </Button>
            </CardHeader>
            <CardContent>
              <ScrollArea className="h-[400px] w-full rounded-md border border-sentinel-light/10 bg-sentinel-dark/50 p-4">
                <div className="space-y-2 font-mono text-sm">
                  {consoleOutput.map((line, index) => (
                    <div key={index} className="flex">
                      <span className="text-sentinel-accent mr-2">[{formatTimestamp(line.timestamp)}]</span>
                      <span className={
                        line.message.includes("ALERT") 
                          ? "text-red-500" 
                          : line.message.includes("ERROR") 
                            ? "text-orange-500"
                            : line.message.includes("WARNING")
                              ? "text-yellow-500"
                              : "text-gray-200"
                      }>
                        {line.message}
                      </span>
                    </div>
                  ))}
                </div>
              </ScrollArea>
            </CardContent>
          </Card>
        </TabsContent>
        
        <TabsContent value="rules" className="space-y-4">
          <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm">
            <CardHeader>
              <CardTitle>Snort Rules</CardTitle>
              <CardDescription>
                Detection rules configuration
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="rounded-md border border-sentinel-light/10 mb-4">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead className="w-[100px]">Status</TableHead>
                      <TableHead>Description</TableHead>
                      <TableHead className="text-right">Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {rules.map((rule) => (
                      <TableRow key={rule.id} className="animate-fade-in">
                        <TableCell>
                          <Button 
                            variant={rule.enabled ? "default" : "outline"} 
                            size="sm"
                            onClick={() => toggleRuleStatus(rule.id)}
                          >
                            {rule.enabled ? (
                              <><Check className="h-4 w-4 mr-1" /> Enabled</>
                            ) : (
                              <><X className="h-4 w-4 mr-1" /> Disabled</>
                            )}
                          </Button>
                        </TableCell>
                        <TableCell className="font-medium">{rule.description}</TableCell>
                        <TableCell className="text-right space-x-2">
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => editRule(rule)}
                          >
                            <Edit className="h-4 w-4" />
                          </Button>
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => deleteRule(rule.id)}
                            className="text-destructive"
                          >
                            <Trash className="h-4 w-4" />
                          </Button>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
              
              {editingRule ? (
                <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm animate-scale-in">
                  <CardHeader>
                    <CardTitle>Edit Rule</CardTitle>
                    <CardDescription>
                      Modify rule #{editingRule.id}
                    </CardDescription>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    <div className="space-y-2">
                      <Label htmlFor="edit-rule-description">Description</Label>
                      <Input 
                        id="edit-rule-description"
                        value={editingRule.description}
                        onChange={(e) => setEditingRule({...editingRule, description: e.target.value})}
                      />
                    </div>
                    <div className="space-y-2">
                      <Label htmlFor="edit-rule-content">Rule Content</Label>
                      <textarea 
                        id="edit-rule-content"
                        className="flex min-h-[120px] w-full rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50"
                        value={editingRule.rule}
                        onChange={(e) => setEditingRule({...editingRule, rule: e.target.value})}
                      />
                    </div>
                    <div className="flex justify-between">
                      <Button
                        variant="outline"
                        onClick={() => setEditingRule(null)}
                      >
                        Cancel
                      </Button>
                      <Button
                        onClick={saveRule}
                      >
                        <Save className="mr-2 h-4 w-4" /> Save Rule
                      </Button>
                    </div>
                  </CardContent>
                </Card>
              ) : (
                <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm">
                  <CardHeader>
                    <CardTitle>Add New Rule</CardTitle>
                    <CardDescription>
                      Create a custom Snort rule
                    </CardDescription>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    <div className="space-y-2">
                      <Label htmlFor="rule-description">Description</Label>
                      <Input 
                        id="rule-description"
                        placeholder="Detects SSH brute force attempts"
                        value={newRule.description}
                        onChange={(e) => setNewRule({...newRule, description: e.target.value})}
                      />
                    </div>
                    <div className="space-y-2">
                      <Label htmlFor="rule-content">Rule Content</Label>
                      <textarea 
                        id="rule-content"
                        className="flex min-h-[120px] w-full rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50"
                        placeholder="alert tcp any any -> $HOME_NET 22 (msg:\"SSH brute force attempt\"; flow:to_server; threshold:type threshold, track by_src, count 5, seconds 60; classtype:attempted-admin; sid:1000001; rev:1;)"
                        value={newRule.rule}
                        onChange={(e) => setNewRule({...newRule, rule: e.target.value})}
                      />
                    </div>
                    <Button 
                      className="w-full"
                      onClick={addRule}
                    >
                      <Plus className="mr-2 h-4 w-4" /> Add Rule
                    </Button>
                  </CardContent>
                </Card>
              )}
            </CardContent>
          </Card>
        </TabsContent>
        
        <TabsContent value="alerts" className="space-y-4">
          <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm">
            <CardHeader>
              <CardTitle>Snort Alerts</CardTitle>
              <CardDescription>
                Recent detections from Snort engine
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="rounded-md border border-sentinel-light/10">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Time</TableHead>
                      <TableHead>Message</TableHead>
                      <TableHead className="hidden md:table-cell">Source</TableHead>
                      <TableHead className="hidden md:table-cell">Destination</TableHead>
                      <TableHead>Severity</TableHead>
                      <TableHead className="text-right">Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {alerts.map((alert) => (
                      <TableRow key={alert.id} className="animate-fade-in">
                        <TableCell>
                          {formatTimestamp(alert.timestamp)}
                        </TableCell>
                        <TableCell className="font-medium">{alert.message}</TableCell>
                        <TableCell className="hidden md:table-cell">{alert.source_ip}:{alert.source_port}</TableCell>
                        <TableCell className="hidden md:table-cell">{alert.destination_ip}:{alert.destination_port}</TableCell>
                        <TableCell>
                          <Badge 
                            className={
                              alert.severity === "critical" 
                                ? "bg-red-500 text-white" 
                                : alert.severity === "high"
                                  ? "bg-orange-500 text-white"
                                  : alert.severity === "medium"
                                    ? "bg-yellow-500 text-black"
                                    : "bg-blue-500 text-white"
                            }
                          >
                            {alert.severity}
                          </Badge>
                        </TableCell>
                        <TableCell className="text-right">
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => setSelectedAlert(alert)}
                          >
                            Details
                          </Button>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
              
              {selectedAlert && (
                <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm animate-scale-in mt-4">
                  <CardHeader>
                    <CardTitle className="flex items-center justify-between">
                      <span>Alert Details</span>
                      <Badge 
                        className={
                          selectedAlert.severity === "critical" 
                            ? "bg-red-500 text-white" 
                            : selectedAlert.severity === "high"
                              ? "bg-orange-500 text-white"
                              : selectedAlert.severity === "medium"
                                ? "bg-yellow-500 text-black"
                                : "bg-blue-500 text-white"
                        }
                      >
                        {selectedAlert.severity}
                      </Badge>
                    </CardTitle>
                    <CardDescription>
                      {new Date(selectedAlert.timestamp).toLocaleString()}
                    </CardDescription>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    <div className="grid grid-cols-2 gap-4">
                      <div>
                        <Label className="text-sm text-muted-foreground">Rule ID</Label>
                        <p>{selectedAlert.rule_id}</p>
                      </div>
                      <div>
                        <Label className="text-sm text-muted-foreground">Protocol</Label>
                        <p>{selectedAlert.protocol}</p>
                      </div>
                      <div>
                        <Label className="text-sm text-muted-foreground">Source</Label>
                        <p>{selectedAlert.source_ip}:{selectedAlert.source_port}</p>
                      </div>
                      <div>
                        <Label className="text-sm text-muted-foreground">Destination</Label>
                        <p>{selectedAlert.destination_ip}:{selectedAlert.destination_port}</p>
                      </div>
                    </div>
                    
                    <div>
                      <Label className="text-sm text-muted-foreground">Message</Label>
                      <p>{selectedAlert.message}</p>
                    </div>
                    
                    <div>
                      <Label className="text-sm text-muted-foreground">Details</Label>
                      <p>{selectedAlert.details}</p>
                    </div>
                    
                    <div className="pt-2 flex justify-between">
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => setSelectedAlert(null)}
                      >
                        Close
                      </Button>
                      
                      <div className="space-x-2">
                        {stats.dropper && (
                          <Button
                            variant="destructive"
                            size="sm"
                          >
                            Block Source IP
                          </Button>
                        )}
                        <Button
                          variant="default"
                          size="sm"
                        >
                          Add to Report
                        </Button>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
};

export default SnortTool;
