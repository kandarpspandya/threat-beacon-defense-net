
import { useState, useEffect } from "react";
import { Shield, AlertTriangle, FileText, Check, X, Plus, Trash2 } from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Badge } from "@/components/ui/badge";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Progress } from "@/components/ui/progress";
import { toast } from "sonner";

// Mock rule data - in a real app, these would come from the backend
const initialRules = [
  { 
    id: 1, 
    name: "SSH Brute Force", 
    description: "Detects SSH brute force attempts", 
    pattern: "alert tcp any any -> $HOME_NET 22 (msg:\"SSH brute force attempt\"; flow:to_server; threshold:type threshold, track by_src, count 5, seconds 60; classtype:attempted-admin; sid:1000001; rev:1;)", 
    enabled: true, 
    category: "Authentication",
    severity: "high"
  },
  { 
    id: 2, 
    name: "SQL Injection", 
    description: "Detects SQL injection attempts in HTTP requests", 
    pattern: "alert tcp any any -> $HOME_NET 80 (msg:\"SQL Injection attempt\"; content:\"SELECT\"; nocase; content:\"FROM\"; nocase; content:\"WHERE\"; nocase; pcre:\"/(union|select|insert|update|delete|replace|truncate)/i\"; classtype:web-application-attack; sid:1000002; rev:1;)", 
    enabled: true, 
    category: "Web Attack",
    severity: "critical" 
  },
  { 
    id: 3, 
    name: "Malware C2 Communication", 
    description: "Detects communication with known malware command and control servers", 
    pattern: "alert tcp any any -> any any (msg:\"Malware C2 Communication\"; content:\"|00 00 00 01 00 00 00 00|\"; depth:8; classtype:trojan-activity; sid:1000003; rev:1;)", 
    enabled: true, 
    category: "Malware",
    severity: "critical" 
  },
  { 
    id: 4, 
    name: "Port Scanning", 
    description: "Detects port scanning activity", 
    pattern: "alert tcp any any -> $HOME_NET any (msg:\"Port Scanning\"; flags:S; threshold:type threshold, track by_src, count 20, seconds 60; classtype:attempted-recon; sid:1000004; rev:1;)", 
    enabled: true, 
    category: "Reconnaissance",
    severity: "medium" 
  },
  { 
    id: 5, 
    name: "DNS Tunneling", 
    description: "Detects potential DNS tunneling", 
    pattern: "alert udp any any -> any 53 (msg:\"DNS Tunneling\"; content:\"|01 00 00 01 00 00 00 00 00 00|\"; depth:10; content:!\"|03|www\"; content:!\"|06|google\"; content:!\"|05|gmail\"; pcre:\"/[a-zA-Z0-9-]{30,}\\.(com|net|org)/i\"; classtype:trojan-activity; sid:1000005; rev:1;)", 
    enabled: false, 
    category: "Data Exfiltration",
    severity: "high" 
  }
];

// Mock detection events based on the rules
const mockDetectionEvents = [
  { 
    id: 1, 
    ruleId: 1, 
    timestamp: new Date(Date.now() - 15 * 60000).toISOString(), 
    source: "198.51.100.123", 
    destination: "10.0.0.15", 
    message: "SSH brute force attempt", 
    details: "Multiple failed SSH login attempts detected",
    severity: "high"
  },
  { 
    id: 2, 
    ruleId: 2, 
    timestamp: new Date(Date.now() - 35 * 60000).toISOString(), 
    source: "203.0.113.42", 
    destination: "10.0.0.25", 
    message: "SQL Injection attempt", 
    details: "Malicious SQL pattern detected in HTTP request",
    severity: "critical"
  },
  { 
    id: 3, 
    ruleId: 3, 
    timestamp: new Date(Date.now() - 55 * 60000).toISOString(), 
    source: "10.0.0.35", 
    destination: "198.51.100.74", 
    message: "Malware C2 Communication", 
    details: "Communication with known malware C2 server detected",
    severity: "critical"
  },
  { 
    id: 4, 
    ruleId: 4, 
    timestamp: new Date(Date.now() - 120 * 60000).toISOString(), 
    source: "203.0.113.15", 
    destination: "10.0.0.1", 
    message: "Port Scanning", 
    details: "Sequential port scan detected",
    severity: "medium"
  }
];

const SignatureDetection = () => {
  const [rules, setRules] = useState<any[]>(initialRules);
  const [events, setEvents] = useState<any[]>(mockDetectionEvents);
  const [selectedRule, setSelectedRule] = useState<any>(null);
  const [isEditing, setIsEditing] = useState(false);
  const [newRule, setNewRule] = useState({
    name: "",
    description: "",
    pattern: "",
    category: "General",
    severity: "medium"
  });
  const [engineStatus, setEngineStatus] = useState("running");
  const [filterSeverity, setFilterSeverity] = useState("all");

  // Simulate real-time signature matching
  useEffect(() => {
    // Add a new detection event every 30 seconds
    const interval = setInterval(() => {
      if (engineStatus === "running") {
        const randomRule = rules[Math.floor(Math.random() * rules.length)];
        if (randomRule && randomRule.enabled) {
          const newEvent = {
            id: Math.floor(Math.random() * 10000),
            ruleId: randomRule.id,
            timestamp: new Date().toISOString(),
            source: `192.168.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
            destination: `10.0.0.${Math.floor(Math.random() * 255)}`,
            message: randomRule.name,
            details: `Signature match: ${randomRule.description}`,
            severity: randomRule.severity
          };
          
          setEvents(prevEvents => [newEvent, ...prevEvents]);
          
          // Show toast notification for new detection
          toast.warning(`New threat detected: ${randomRule.name}`, {
            description: `From ${newEvent.source} to ${newEvent.destination}`,
            action: {
              label: "View",
              onClick: () => setSelectedRule(randomRule)
            }
          });
        }
      }
    }, 30000);

    return () => clearInterval(interval);
  }, [rules, engineStatus]);

  const toggleRuleStatus = (id: number) => {
    setRules(rules.map(rule => 
      rule.id === id ? { ...rule, enabled: !rule.enabled } : rule
    ));
    
    const rule = rules.find(r => r.id === id);
    if (rule) {
      toast.info(`Rule ${rule.enabled ? 'disabled' : 'enabled'}: ${rule.name}`);
    }
  };

  const addRule = () => {
    if (!newRule.name || !newRule.pattern) {
      toast.error("Rule name and pattern are required");
      return;
    }
    
    const ruleToAdd = {
      ...newRule,
      id: Math.max(...rules.map(r => r.id), 0) + 1,
      enabled: true
    };
    
    setRules([...rules, ruleToAdd]);
    setNewRule({
      name: "",
      description: "",
      pattern: "",
      category: "General",
      severity: "medium"
    });
    
    toast.success(`Rule added: ${ruleToAdd.name}`);
  };

  const deleteRule = (id: number) => {
    const rule = rules.find(r => r.id === id);
    if (rule) {
      setRules(rules.filter(rule => rule.id !== id));
      toast.success(`Rule deleted: ${rule.name}`);
    }
  };

  const toggleEngine = () => {
    const newStatus = engineStatus === "running" ? "stopped" : "running";
    setEngineStatus(newStatus);
    toast.info(`Signature detection engine ${newStatus}`);
  };

  const filteredEvents = filterSeverity === "all" 
    ? events 
    : events.filter(event => event.severity === filterSeverity);

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case "critical": return "bg-red-500 text-white";
      case "high": return "bg-orange-500 text-white";
      case "medium": return "bg-yellow-500 text-black";
      case "low": return "bg-blue-500 text-white";
      default: return "bg-gray-500 text-white";
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-3xl font-bold tracking-tight">Signature-Based Detection</h2>
          <p className="text-muted-foreground">
            Pattern matching against known threats and attack signatures
          </p>
        </div>
        <div className="flex items-center space-x-2">
          <Button 
            variant={engineStatus === "running" ? "destructive" : "default"}
            onClick={toggleEngine}
          >
            {engineStatus === "running" ? "Stop Engine" : "Start Engine"}
          </Button>
        </div>
      </div>

      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
        <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium">Detection Engine</CardTitle>
            <Shield className={`h-4 w-4 ${engineStatus === "running" ? "text-sentinel-success" : "text-destructive"}`} />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{engineStatus === "running" ? "Active" : "Inactive"}</div>
            <p className="text-xs text-muted-foreground">
              {engineStatus === "running" ? "Analyzing traffic in real-time" : "Engine stopped"}
            </p>
          </CardContent>
        </Card>
        
        <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium">Signature Rules</CardTitle>
            <FileText className="h-4 w-4 text-sentinel-info" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{rules.length}</div>
            <p className="text-xs text-muted-foreground">
              {rules.filter(r => r.enabled).length} active rules
            </p>
          </CardContent>
        </Card>
        
        <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium">Detected Events</CardTitle>
            <AlertTriangle className="h-4 w-4 text-sentinel-warning" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{events.length}</div>
            <p className="text-xs text-muted-foreground">
              In the last 24 hours
            </p>
          </CardContent>
        </Card>
      </div>

      <Tabs defaultValue="rules" className="space-y-4">
        <TabsList className="grid grid-cols-3 md:w-[400px] bg-background/50">
          <TabsTrigger value="rules">Signature Rules</TabsTrigger>
          <TabsTrigger value="events">Detection Events</TabsTrigger>
          <TabsTrigger value="add">Add Rule</TabsTrigger>
        </TabsList>
        
        <TabsContent value="rules" className="space-y-4">
          <div className="rounded-md border border-sentinel-light/10">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-[100px]">Status</TableHead>
                  <TableHead>Name</TableHead>
                  <TableHead className="hidden md:table-cell">Category</TableHead>
                  <TableHead className="hidden md:table-cell">Severity</TableHead>
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
                    <TableCell className="font-medium">{rule.name}</TableCell>
                    <TableCell className="hidden md:table-cell">{rule.category}</TableCell>
                    <TableCell className="hidden md:table-cell">
                      <Badge className={getSeverityColor(rule.severity)}>
                        {rule.severity}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-right">
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => {
                          setSelectedRule(rule);
                          setIsEditing(false);
                        }}
                      >
                        View
                      </Button>
                      <Button
                        variant="ghost"
                        size="sm"
                        className="text-destructive"
                        onClick={() => deleteRule(rule.id)}
                      >
                        <Trash2 className="h-4 w-4" />
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>

          {selectedRule && !isEditing && (
            <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm animate-scale-in">
              <CardHeader>
                <CardTitle className="flex items-center justify-between">
                  <span>{selectedRule.name}</span>
                  <Badge className={getSeverityColor(selectedRule.severity)}>
                    {selectedRule.severity}
                  </Badge>
                </CardTitle>
                <CardDescription>{selectedRule.description}</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div>
                  <h4 className="text-sm font-semibold mb-1">Pattern</h4>
                  <pre className="bg-sentinel-dark/70 p-3 rounded-md text-xs overflow-x-auto">
                    {selectedRule.pattern}
                  </pre>
                </div>
                <div className="flex justify-between">
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => setSelectedRule(null)}
                  >
                    Close
                  </Button>
                  <Button
                    variant={selectedRule.enabled ? "destructive" : "default"}
                    size="sm"
                    onClick={() => toggleRuleStatus(selectedRule.id)}
                  >
                    {selectedRule.enabled ? "Disable Rule" : "Enable Rule"}
                  </Button>
                </div>
              </CardContent>
            </Card>
          )}
        </TabsContent>
        
        <TabsContent value="events" className="space-y-4">
          <div className="flex justify-between items-center">
            <h3 className="text-lg font-semibold">Recent Detection Events</h3>
            <div className="flex space-x-2">
              <Button 
                variant={filterSeverity === "all" ? "default" : "outline"} 
                size="sm"
                onClick={() => setFilterSeverity("all")}
              >
                All
              </Button>
              <Button 
                variant={filterSeverity === "critical" ? "default" : "outline"} 
                size="sm"
                className="bg-red-500 text-white hover:bg-red-600"
                onClick={() => setFilterSeverity("critical")}
              >
                Critical
              </Button>
              <Button 
                variant={filterSeverity === "high" ? "default" : "outline"} 
                size="sm"
                className="bg-orange-500 text-white hover:bg-orange-600"
                onClick={() => setFilterSeverity("high")}
              >
                High
              </Button>
              <Button 
                variant={filterSeverity === "medium" ? "default" : "outline"} 
                size="sm"
                className="bg-yellow-500 text-black hover:bg-yellow-600"
                onClick={() => setFilterSeverity("medium")}
              >
                Medium
              </Button>
            </div>
          </div>
          
          <div className="rounded-md border border-sentinel-light/10">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Time</TableHead>
                  <TableHead>Rule</TableHead>
                  <TableHead className="hidden md:table-cell">Source</TableHead>
                  <TableHead className="hidden md:table-cell">Destination</TableHead>
                  <TableHead>Severity</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filteredEvents.map((event) => {
                  const rule = rules.find(r => r.id === event.ruleId);
                  const eventTime = new Date(event.timestamp);
                  
                  return (
                    <TableRow key={event.id} className="animate-fade-in">
                      <TableCell>
                        {eventTime.toLocaleTimeString()}
                      </TableCell>
                      <TableCell className="font-medium">{rule?.name || event.message}</TableCell>
                      <TableCell className="hidden md:table-cell">{event.source}</TableCell>
                      <TableCell className="hidden md:table-cell">{event.destination}</TableCell>
                      <TableCell>
                        <Badge className={getSeverityColor(event.severity)}>
                          {event.severity}
                        </Badge>
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </div>
        </TabsContent>
        
        <TabsContent value="add" className="space-y-4">
          <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm">
            <CardHeader>
              <CardTitle>Add New Signature Rule</CardTitle>
              <CardDescription>
                Create a new signature for detecting specific threats
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div className="col-span-2 md:col-span-1 space-y-2">
                  <Label htmlFor="rule-name">Rule Name</Label>
                  <Input 
                    id="rule-name"
                    placeholder="SSH Brute Force"
                    value={newRule.name}
                    onChange={(e) => setNewRule({...newRule, name: e.target.value})}
                  />
                </div>
                
                <div className="col-span-2 md:col-span-1 space-y-2">
                  <Label htmlFor="rule-category">Category</Label>
                  <Input 
                    id="rule-category"
                    placeholder="Authentication"
                    value={newRule.category}
                    onChange={(e) => setNewRule({...newRule, category: e.target.value})}
                  />
                </div>
                
                <div className="col-span-2 space-y-2">
                  <Label htmlFor="rule-description">Description</Label>
                  <Input 
                    id="rule-description"
                    placeholder="Detects SSH brute force attempts"
                    value={newRule.description}
                    onChange={(e) => setNewRule({...newRule, description: e.target.value})}
                  />
                </div>
                
                <div className="col-span-2 space-y-2">
                  <Label htmlFor="rule-pattern">Rule Pattern</Label>
                  <textarea 
                    id="rule-pattern"
                    className="flex h-20 w-full rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2"
                    placeholder="alert tcp any any -> $HOME_NET 22 (msg:\"SSH brute force attempt\"; flow:to_server; threshold:type threshold, track by_src, count 5, seconds 60; classtype:attempted-admin; sid:1000001; rev:1;)"
                    value={newRule.pattern}
                    onChange={(e) => setNewRule({...newRule, pattern: e.target.value})}
                  />
                </div>
                
                <div className="col-span-2 md:col-span-1 space-y-2">
                  <Label htmlFor="rule-severity">Severity</Label>
                  <select
                    id="rule-severity"
                    className="flex h-10 w-full rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2"
                    value={newRule.severity}
                    onChange={(e) => setNewRule({...newRule, severity: e.target.value})}
                  >
                    <option value="low">Low</option>
                    <option value="medium">Medium</option>
                    <option value="high">High</option>
                    <option value="critical">Critical</option>
                  </select>
                </div>
              </div>
              
              <Button 
                className="w-full"
                onClick={addRule}
              >
                <Plus className="mr-2 h-4 w-4" /> Add Signature Rule
              </Button>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
};

export default SignatureDetection;
