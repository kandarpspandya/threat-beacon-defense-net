
import { useState } from "react";
import { 
  Network, 
  Activity, 
  Search, 
  Layers, 
  ShieldAlert, 
  RefreshCw, 
  HardDrive, 
  Filter, 
  Eye, 
  ArrowUpDown, 
  Check, 
  X, 
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
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";

// Mock data for protocol states
const protocolStatesMock = [
  {
    id: 1,
    protocol: "TCP",
    srcIp: "192.168.1.105",
    srcPort: 49821,
    dstIp: "93.184.216.34",
    dstPort: 443,
    state: "ESTABLISHED",
    age: "00:03:42",
    bytes: 12842,
    flags: "PSH,ACK",
    lastActivity: "00:00:12",
    risk: "low"
  },
  {
    id: 2,
    protocol: "HTTP",
    srcIp: "192.168.1.105",
    srcPort: 49821,
    dstIp: "93.184.216.34",
    dstPort: 443,
    state: "REQUEST",
    age: "00:01:17",
    bytes: 1240,
    flags: "GET /index.html",
    lastActivity: "00:00:22",
    risk: "medium"
  },
  {
    id: 3,
    protocol: "DNS",
    srcIp: "192.168.1.105",
    srcPort: 53247,
    dstIp: "8.8.8.8",
    dstPort: 53,
    state: "QUERY",
    age: "00:02:05",
    bytes: 64,
    flags: "Standard query",
    lastActivity: "00:00:05",
    risk: "low"
  },
  {
    id: 4,
    protocol: "HTTPS",
    srcIp: "192.168.1.105",
    srcPort: 49832,
    dstIp: "172.217.7.142",
    dstPort: 443,
    state: "TLS_HANDSHAKE",
    age: "00:01:30",
    bytes: 3840,
    flags: "Client Hello",
    lastActivity: "00:00:18",
    risk: "low"
  },
  {
    id: 5,
    protocol: "SMB",
    srcIp: "192.168.1.110",
    srcPort: 49715,
    dstIp: "192.168.1.5",
    dstPort: 445,
    state: "NEGOTIATE",
    age: "00:05:22",
    bytes: 540,
    flags: "NEGOTIATE_REQUEST",
    lastActivity: "00:01:02",
    risk: "high"
  },
  {
    id: 6,
    protocol: "FTP",
    srcIp: "192.168.1.110",
    srcPort: 38654,
    dstIp: "37.59.239.66",
    dstPort: 21,
    state: "COMMAND",
    age: "00:04:10",
    bytes: 284,
    flags: "USER anonymous",
    lastActivity: "00:00:42",
    risk: "medium"
  },
  {
    id: 7,
    protocol: "TCP",
    srcIp: "192.168.1.114",
    srcPort: 63594,
    dstIp: "173.194.222.147",
    dstPort: 443,
    state: "CLOSED",
    age: "00:08:31",
    bytes: 8723,
    flags: "FIN,ACK",
    lastActivity: "00:01:31",
    risk: "low"
  }
];

// Mock data for protocol anomalies
const protocolAnomaliesMock = [
  {
    id: 1,
    timestamp: "2025-04-16T10:23:45.000Z",
    protocol: "HTTP",
    srcIp: "192.168.1.110",
    dstIp: "203.0.113.42",
    anomalyType: "INVALID_VERSION",
    description: "HTTP version not recognized: HTTP/9.0",
    severity: "medium"
  },
  {
    id: 2,
    timestamp: "2025-04-16T09:18:27.000Z",
    protocol: "DNS",
    srcIp: "192.168.1.105",
    dstIp: "8.8.8.8",
    anomalyType: "OVERSIZED_PACKET",
    description: "DNS packet exceeds max recommended size (4728 bytes)",
    severity: "high"
  },
  {
    id: 3,
    timestamp: "2025-04-16T08:42:13.000Z",
    protocol: "SMB",
    srcIp: "192.168.1.110",
    dstIp: "192.168.1.5",
    anomalyType: "DEPRECATED_COMMAND",
    description: "Use of deprecated SMBv1 commands (CVE-2017-0143)",
    severity: "critical"
  },
  {
    id: 4,
    timestamp: "2025-04-15T23:56:04.000Z",
    protocol: "TLS",
    srcIp: "192.168.1.105",
    dstIp: "93.184.216.34",
    anomalyType: "INSECURE_CIPHER",
    description: "Negotiation of known-weak cipher (RC4)",
    severity: "high"
  },
  {
    id: 5,
    timestamp: "2025-04-15T22:47:19.000Z",
    protocol: "FTP",
    srcIp: "192.168.1.110",
    dstIp: "37.59.239.66",
    anomalyType: "CLEARTEXT_CREDENTIALS",
    description: "Credentials transmitted in clear text",
    severity: "medium"
  }
];

// Mock data for protocol inspection rules
const protocolRulesMock = [
  {
    id: 1,
    protocol: "HTTP",
    name: "HTTP Header Validation",
    description: "Inspects HTTP headers for RFC compliance",
    enabled: true,
    actions: ["log", "alert"]
  },
  {
    id: 2,
    protocol: "DNS",
    name: "DNS Amplification Detection",
    description: "Detects DNS amplification attack patterns",
    enabled: true,
    actions: ["log", "alert", "block"]
  },
  {
    id: 3,
    protocol: "SSL/TLS",
    name: "Weak Cipher Detection",
    description: "Identifies negotiation of insecure ciphers",
    enabled: true,
    actions: ["log", "alert"]
  },
  {
    id: 4,
    protocol: "SMB",
    name: "SMBv1 Detection",
    description: "Detects usage of legacy SMBv1 protocol",
    enabled: true,
    actions: ["log", "alert", "block"]
  },
  {
    id: 5,
    protocol: "FTP",
    name: "FTP Command Validation",
    description: "Verifies FTP commands follow proper syntax",
    enabled: false,
    actions: ["log"]
  },
  {
    id: 6,
    protocol: "SMTP",
    name: "SMTP STARTTLS Enforcement",
    description: "Ensures SMTP connections use encryption",
    enabled: true,
    actions: ["log", "alert"]
  },
  {
    id: 7,
    protocol: "RDP",
    name: "RDP Vulnerability Scanner",
    description: "Checks for known RDP vulnerabilities",
    enabled: true,
    actions: ["log", "alert", "block"]
  }
];

// Mock protocols for the summary stats
const protocolStatsMock = [
  { name: "HTTP/HTTPS", connections: 42, bandwidth: "1.2 GB", anomalies: 2 },
  { name: "DNS", connections: 104, bandwidth: "12 MB", anomalies: 1 },
  { name: "SMB/CIFS", connections: 18, bandwidth: "350 MB", anomalies: 3 },
  { name: "FTP", connections: 5, bandwidth: "85 MB", anomalies: 2 },
  { name: "SSH", connections: 7, bandwidth: "28 MB", anomalies: 0 },
  { name: "SMTP", connections: 12, bandwidth: "45 MB", anomalies: 0 },
  { name: "RDP", connections: 3, bandwidth: "220 MB", anomalies: 1 }
];

const ProtocolAnalysis = () => {
  const [activeTab, setActiveTab] = useState("state-tracking");
  const [protocolStates] = useState(protocolStatesMock);
  const [protocolAnomalies] = useState(protocolAnomaliesMock);
  const [protocolRules, setProtocolRules] = useState(protocolRulesMock);
  const [protocolStats] = useState(protocolStatsMock);
  const [searchTerm, setSearchTerm] = useState("");
  const [selectedProtocol, setSelectedProtocol] = useState("all");

  // Handler for toggling rule enabled status
  const toggleRuleStatus = (ruleId: number) => {
    setProtocolRules(
      protocolRules.map(rule => 
        rule.id === ruleId ? { ...rule, enabled: !rule.enabled } : rule
      )
    );
    
    const rule = protocolRules.find(r => r.id === ruleId);
    toast.success(`Rule ${!rule?.enabled ? "enabled" : "disabled"}`, {
      description: `${rule?.name} has been ${!rule?.enabled ? "enabled" : "disabled"}`
    });
  };

  // Filter function for protocol states based on search and selected protocol
  const filteredStates = protocolStates.filter(state => {
    const matchesSearch = 
      searchTerm === "" || 
      state.srcIp.includes(searchTerm) || 
      state.dstIp.includes(searchTerm) || 
      state.protocol.toLowerCase().includes(searchTerm.toLowerCase());
    
    const matchesProtocol = 
      selectedProtocol === "all" || 
      state.protocol.toLowerCase() === selectedProtocol.toLowerCase();
    
    return matchesSearch && matchesProtocol;
  });

  // Filter function for protocol anomalies based on search
  const filteredAnomalies = protocolAnomalies.filter(anomaly => {
    const matchesSearch = 
      searchTerm === "" || 
      anomaly.srcIp.includes(searchTerm) || 
      anomaly.dstIp.includes(searchTerm) || 
      anomaly.protocol.toLowerCase().includes(searchTerm.toLowerCase()) ||
      anomaly.anomalyType.toLowerCase().includes(searchTerm.toLowerCase());
    
    const matchesProtocol = 
      selectedProtocol === "all" || 
      anomaly.protocol.toLowerCase() === selectedProtocol.toLowerCase();
    
    return matchesSearch && matchesProtocol;
  });

  // Filter function for protocol rules based on search
  const filteredRules = protocolRules.filter(rule => {
    const matchesSearch = 
      searchTerm === "" || 
      rule.name.toLowerCase().includes(searchTerm.toLowerCase()) || 
      rule.description.toLowerCase().includes(searchTerm.toLowerCase());
    
    const matchesProtocol = 
      selectedProtocol === "all" || 
      rule.protocol.toLowerCase().includes(selectedProtocol.toLowerCase());
    
    return matchesSearch && matchesProtocol;
  });

  // Function to get style based on risk level
  const getRiskBadgeStyle = (risk: string) => {
    switch (risk.toLowerCase()) {
      case "low":
        return "bg-blue-500 hover:bg-blue-600";
      case "medium":
        return "bg-yellow-500 hover:bg-yellow-600";
      case "high":
        return "bg-orange-500 hover:bg-orange-600";
      case "critical":
        return "bg-red-500 hover:bg-red-600";
      default:
        return "bg-gray-500 hover:bg-gray-600";
    }
  };

  return (
    <div className="container mx-auto p-4 space-y-6">
      <div className="flex flex-col md:flex-row justify-between md:items-center gap-4">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Protocol Analysis</h1>
          <p className="text-muted-foreground">
            Stateful inspection and analysis of network protocols
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            className="flex items-center gap-2"
            onClick={() => {
              toast.success("Protocol analysis refreshed", {
                description: "All protocol data has been updated"
              });
            }}
          >
            <RefreshCw className="h-4 w-4" />
            Refresh
          </Button>
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="default" className="flex items-center gap-2">
                <Filter className="h-4 w-4" />
                Actions
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent>
              <DropdownMenuLabel>Analysis Actions</DropdownMenuLabel>
              <DropdownMenuSeparator />
              <DropdownMenuItem
                onClick={() => {
                  toast.success("Deep protocol scan initiated", {
                    description: "Scanning all active network sessions"
                  });
                }}
              >
                <Search className="h-4 w-4 mr-2" />
                <span>Deep Protocol Scan</span>
              </DropdownMenuItem>
              <DropdownMenuItem
                onClick={() => {
                  toast.success("Rule diagnostics started", {
                    description: "Testing all protocol rules for effectiveness"
                  });
                }}
              >
                <Activity className="h-4 w-4 mr-2" />
                <span>Run Rule Diagnostics</span>
              </DropdownMenuItem>
              <DropdownMenuItem
                onClick={() => {
                  toast.success("Protocol baseline created", {
                    description: "Current network state saved as baseline"
                  });
                }}
              >
                <HardDrive className="h-4 w-4 mr-2" />
                <span>Save Protocol Baseline</span>
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      </div>

      {/* Protocol Summary Stats */}
      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4">
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">Active Protocol Sessions</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">184</div>
            <p className="text-xs text-muted-foreground">+12 in the last hour</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">Protocol Anomalies</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{protocolAnomalies.length}</div>
            <p className="text-xs text-muted-foreground">3 critical, 2 high severity</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">State Tracking Rules</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{protocolRules.length}</div>
            <p className="text-xs text-muted-foreground">{protocolRules.filter(r => r.enabled).length} enabled</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">Protocol Coverage</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">94.2%</div>
            <p className="text-xs text-muted-foreground">+2.1% from last scan</p>
          </CardContent>
        </Card>
      </div>

      {/* Search and Protocol Filter */}
      <div className="flex flex-col sm:flex-row gap-4">
        <div className="relative flex-1">
          <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
          <Input
            type="search"
            placeholder="Search by IP, protocol, or keyword..."
            className="pl-8"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
          />
        </div>
        <Select 
          value={selectedProtocol} 
          onValueChange={setSelectedProtocol}
        >
          <SelectTrigger className="w-full sm:w-[180px]">
            <SelectValue placeholder="Protocol" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Protocols</SelectItem>
            <SelectItem value="http">HTTP/HTTPS</SelectItem>
            <SelectItem value="dns">DNS</SelectItem>
            <SelectItem value="tcp">TCP</SelectItem>
            <SelectItem value="smb">SMB/CIFS</SelectItem>
            <SelectItem value="ftp">FTP</SelectItem>
            <SelectItem value="ssh">SSH</SelectItem>
            <SelectItem value="smtp">SMTP</SelectItem>
            <SelectItem value="rdp">RDP</SelectItem>
          </SelectContent>
        </Select>
      </div>

      {/* Main Content Tabs */}
      <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
        <TabsList className="grid grid-cols-1 md:grid-cols-3 w-full max-w-md">
          <TabsTrigger value="state-tracking" className="flex items-center gap-2">
            <Layers className="h-4 w-4" />
            State Tracking
          </TabsTrigger>
          <TabsTrigger value="anomalies" className="flex items-center gap-2">
            <ShieldAlert className="h-4 w-4" />
            Protocol Anomalies
          </TabsTrigger>
          <TabsTrigger value="rules" className="flex items-center gap-2">
            <Network className="h-4 w-4" />
            Inspection Rules
          </TabsTrigger>
        </TabsList>
        
        {/* State Tracking Tab */}
        <TabsContent value="state-tracking" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Protocol State Tracking</CardTitle>
              <CardDescription>
                Current state of active network protocol sessions
              </CardDescription>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-[100px]">Protocol</TableHead>
                    <TableHead>Source</TableHead>
                    <TableHead>Destination</TableHead>
                    <TableHead>State</TableHead>
                    <TableHead>Age</TableHead>
                    <TableHead>Last Activity</TableHead>
                    <TableHead>Risk</TableHead>
                    <TableHead className="text-right">Details</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filteredStates.map((state) => (
                    <TableRow key={state.id}>
                      <TableCell className="font-medium">{state.protocol}</TableCell>
                      <TableCell>{state.srcIp}:{state.srcPort}</TableCell>
                      <TableCell>{state.dstIp}:{state.dstPort}</TableCell>
                      <TableCell>{state.state}</TableCell>
                      <TableCell>{state.age}</TableCell>
                      <TableCell>{state.lastActivity}</TableCell>
                      <TableCell>
                        <Badge className={getRiskBadgeStyle(state.risk)}>
                          {state.risk.charAt(0).toUpperCase() + state.risk.slice(1)}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-right">
                        <Button 
                          variant="ghost" 
                          size="sm"
                          onClick={() => {
                            toast.info(`${state.protocol} Details`, {
                              description: `Connection between ${state.srcIp}:${state.srcPort} and ${state.dstIp}:${state.dstPort}. Flags: ${state.flags}, Bytes: ${state.bytes}`
                            });
                          }}
                        >
                          <Eye className="h-4 w-4" />
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))}
                  {filteredStates.length === 0 && (
                    <TableRow>
                      <TableCell colSpan={8} className="text-center py-6 text-muted-foreground">
                        No protocol states match your filters
                      </TableCell>
                    </TableRow>
                  )}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>
        
        {/* Protocol Anomalies Tab */}
        <TabsContent value="anomalies" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Protocol Anomalies</CardTitle>
              <CardDescription>
                Detected deviations from expected protocol behavior
              </CardDescription>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Time</TableHead>
                    <TableHead>Protocol</TableHead>
                    <TableHead>Source</TableHead>
                    <TableHead>Destination</TableHead>
                    <TableHead>Anomaly</TableHead>
                    <TableHead>Severity</TableHead>
                    <TableHead className="text-right">Details</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filteredAnomalies.map((anomaly) => (
                    <TableRow key={anomaly.id}>
                      <TableCell>
                        {new Date(anomaly.timestamp).toLocaleTimeString()}
                      </TableCell>
                      <TableCell className="font-medium">{anomaly.protocol}</TableCell>
                      <TableCell>{anomaly.srcIp}</TableCell>
                      <TableCell>{anomaly.dstIp}</TableCell>
                      <TableCell>{anomaly.anomalyType}</TableCell>
                      <TableCell>
                        <Badge className={getRiskBadgeStyle(anomaly.severity)}>
                          {anomaly.severity.charAt(0).toUpperCase() + anomaly.severity.slice(1)}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-right">
                        <Button 
                          variant="ghost" 
                          size="sm"
                          onClick={() => {
                            toast.info(`Anomaly Details`, {
                              description: anomaly.description
                            });
                          }}
                        >
                          <Info className="h-4 w-4" />
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))}
                  {filteredAnomalies.length === 0 && (
                    <TableRow>
                      <TableCell colSpan={7} className="text-center py-6 text-muted-foreground">
                        No protocol anomalies match your filters
                      </TableCell>
                    </TableRow>
                  )}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>
        
        {/* Inspection Rules Tab */}
        <TabsContent value="rules" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Protocol Inspection Rules</CardTitle>
              <CardDescription>
                Configure rules for protocol state monitoring and anomaly detection
              </CardDescription>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-[100px]">Protocol</TableHead>
                    <TableHead>Rule Name</TableHead>
                    <TableHead>Description</TableHead>
                    <TableHead>Actions</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead className="text-right">Toggle</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filteredRules.map((rule) => (
                    <TableRow key={rule.id}>
                      <TableCell>{rule.protocol}</TableCell>
                      <TableCell className="font-medium">{rule.name}</TableCell>
                      <TableCell>{rule.description}</TableCell>
                      <TableCell>
                        <div className="flex gap-1">
                          {rule.actions.map((action, index) => (
                            <Badge key={index} variant="outline" className="capitalize">
                              {action}
                            </Badge>
                          ))}
                        </div>
                      </TableCell>
                      <TableCell>
                        {rule.enabled ? (
                          <Badge className="bg-green-500 hover:bg-green-600">Enabled</Badge>
                        ) : (
                          <Badge variant="outline">Disabled</Badge>
                        )}
                      </TableCell>
                      <TableCell className="text-right">
                        <Button 
                          variant={rule.enabled ? "destructive" : "default"}
                          size="sm"
                          onClick={() => toggleRuleStatus(rule.id)}
                        >
                          {rule.enabled ? (
                            <>
                              <X className="h-4 w-4 mr-1" />
                              Disable
                            </>
                          ) : (
                            <>
                              <Check className="h-4 w-4 mr-1" />
                              Enable
                            </>
                          )}
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))}
                  {filteredRules.length === 0 && (
                    <TableRow>
                      <TableCell colSpan={6} className="text-center py-6 text-muted-foreground">
                        No protocol rules match your filters
                      </TableCell>
                    </TableRow>
                  )}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      {/* Protocol Statistics Table */}
      <Card>
        <CardHeader>
          <CardTitle>Protocol Statistics</CardTitle>
          <CardDescription>
            Summary of monitored protocol activity
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Protocol</TableHead>
                <TableHead>Active Connections</TableHead>
                <TableHead>Bandwidth Usage</TableHead>
                <TableHead>Anomalies Detected</TableHead>
                <TableHead className="text-right">Trend</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {protocolStats.map((stat, index) => (
                <TableRow key={index}>
                  <TableCell className="font-medium">{stat.name}</TableCell>
                  <TableCell>{stat.connections}</TableCell>
                  <TableCell>{stat.bandwidth}</TableCell>
                  <TableCell>
                    {stat.anomalies > 0 ? (
                      <Badge className={
                        stat.anomalies > 2 
                          ? "bg-red-500 hover:bg-red-600" 
                          : "bg-yellow-500 hover:bg-yellow-600"
                      }>
                        {stat.anomalies}
                      </Badge>
                    ) : (
                      <Badge variant="outline" className="bg-green-50 text-green-700 border-green-200">
                        None
                      </Badge>
                    )}
                  </TableCell>
                  <TableCell className="text-right">
                    <Activity className="h-4 w-4 inline" />
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  );
};

export default ProtocolAnalysis;
