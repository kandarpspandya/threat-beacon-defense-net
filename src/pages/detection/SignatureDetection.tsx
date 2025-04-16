
import { useState } from "react";
import { 
  Search, 
  FileText, 
  Shield, 
  RefreshCw, 
  Upload, 
  Check, 
  X, 
  Filter, 
  Download, 
  Plus,
  AlertTriangle,
  Trash2,
  FileCode2,
  Code
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
  Table, 
  TableBody, 
  TableCaption, 
  TableCell, 
  TableHead, 
  TableHeader, 
  TableRow 
} from "@/components/ui/table";
import { 
  Select, 
  SelectContent, 
  SelectItem, 
  SelectTrigger, 
  SelectValue 
} from "@/components/ui/select";
import { toast } from "sonner";
import { Textarea } from "@/components/ui/textarea";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";

// Mock data for signature rules
const signatureRulesMock = [
  {
    id: 1,
    sid: 1000001,
    name: "SQL Injection Attempt",
    description: "Detects common SQL injection patterns in HTTP requests",
    content: 'alert tcp any any -> any 80 (msg:"SQL Injection Attempt"; content:"SELECT"; nocase; content:"FROM"; distance:0; nocase; content:"WHERE"; distance:0; nocase; classtype:web-application-attack; sid:1000001; rev:1;)',
    severity: "high",
    category: "web-attacks",
    enabled: true,
    created: "2025-03-15T14:30:00.000Z",
    lastMatched: "2025-04-16T08:45:22.000Z",
    matchCount: 17
  },
  {
    id: 2,
    sid: 1000002,
    name: "Potential XSS Attack",
    description: "Detects cross-site scripting attempts in URI parameters",
    content: 'alert tcp any any -> any 80 (msg:"Potential XSS Attack"; content:"<script>"; nocase; pcre:"/<script.*?>.*?<\/script>/i"; classtype:web-application-attack; sid:1000002; rev:2;)',
    severity: "high",
    category: "web-attacks",
    enabled: true,
    created: "2025-03-18T11:20:00.000Z",
    lastMatched: "2025-04-15T19:12:43.000Z",
    matchCount: 8
  },
  {
    id: 3,
    sid: 1000003,
    name: "Suspicious PowerShell Command",
    description: "Detects obfuscated or suspicious PowerShell commands",
    content: 'alert tcp any any -> any any (msg:"Suspicious PowerShell Command"; content:"powershell"; nocase; content:"-enc"; distance:0; nocase; content:"-exec"; distance:0; nocase; classtype:trojan-activity; sid:1000003; rev:1;)',
    severity: "critical",
    category: "malware",
    enabled: true,
    created: "2025-03-22T09:45:00.000Z",
    lastMatched: "2025-04-16T02:34:56.000Z",
    matchCount: 4
  },
  {
    id: 4,
    sid: 1000004,
    name: "SMB Remote Code Execution Attempt",
    description: "Detects attempts to exploit SMB vulnerabilities for RCE",
    content: 'alert tcp any any -> any 445 (msg:"SMB Remote Code Execution Attempt"; content:"|FF|SMB"; depth:4; pcre:"/.*\\\\IPC\\$/"; classtype:attempted-admin; sid:1000004; rev:3;)',
    severity: "critical",
    category: "exploits",
    enabled: true,
    created: "2025-02-28T16:15:00.000Z",
    lastMatched: "2025-04-14T21:09:33.000Z",
    matchCount: 2
  },
  {
    id: 5,
    sid: 1000005,
    name: "DNS Zone Transfer",
    description: "Detects DNS zone transfer attempts (AXFR)",
    content: 'alert udp any any -> any 53 (msg:"DNS Zone Transfer Attempt"; content:"|00 00 FC|"; offset:14; depth:3; classtype:attempted-recon; sid:1000005; rev:1;)',
    severity: "medium",
    category: "recon",
    enabled: false,
    created: "2025-03-05T13:30:00.000Z",
    lastMatched: null,
    matchCount: 0
  },
  {
    id: 6,
    sid: 1000006,
    name: "SSH Brute Force Attempt",
    description: "Detects multiple failed SSH authentication attempts",
    content: 'alert tcp any any -> any 22 (msg:"SSH Brute Force Attempt"; flow:established; threshold:type threshold, track by_src, count 5, seconds 60; classtype:attempted-admin; sid:1000006; rev:2;)',
    severity: "medium",
    category: "brute-force",
    enabled: true,
    created: "2025-03-10T10:00:00.000Z",
    lastMatched: "2025-04-16T11:23:44.000Z",
    matchCount: 32
  },
  {
    id: 7,
    sid: 1000007,
    name: "ICMP Large Packet",
    description: "Detects unusually large ICMP packets (potential tunneling)",
    content: 'alert icmp any any -> any any (msg:"ICMP Large Packet"; dsize:>800; classtype:bad-unknown; sid:1000007; rev:1;)',
    severity: "low",
    category: "policy-violation",
    enabled: true,
    created: "2025-03-25T08:45:00.000Z",
    lastMatched: "2025-04-13T14:22:11.000Z",
    matchCount: 3
  }
];

// Mock data for alert matches
const signatureMatchesMock = [
  {
    id: 1,
    timestamp: "2025-04-16T11:23:44.000Z",
    ruleName: "SSH Brute Force Attempt",
    ruleSid: 1000006,
    srcIp: "203.0.113.42",
    dstIp: "192.168.1.15",
    protocol: "TCP",
    severity: "medium",
    packetData: "4500 0048 495b 4000 4006 77e1 cb00 712a c0a8 010f 9c49 0016 0000 0000 0000 0000 a002 16d0 596a 0000 0204 05b4 0402 080a 001a 8199 0000 0000 0103 0303"
  },
  {
    id: 2,
    timestamp: "2025-04-16T08:45:22.000Z",
    ruleName: "SQL Injection Attempt",
    ruleSid: 1000001,
    srcIp: "192.168.1.105",
    dstIp: "203.0.113.28",
    protocol: "TCP",
    severity: "high",
    packetData: "4500 00b4 1c2b 4000 4006 a3c8 c0a8 0169 cb00 711c 4e22 0050 0000 0000 0000 0000 a002 16d0 742c 0000 0204 05b4 0402 080a 002c 9e1f 0000 0000 0103 0303 4745 5420 2f70 726f 6475 6374 732e 7068 703f 6964 3d31 2720 5345 4c45 4354 202a 2046 524f 4d20 7573 6572 7320 5748 4552 4520 313d 3120 4854 5450 2f31 2e31 0d0a 486f 7374 3a20 6578 616d 706c 652e 636f 6d0d 0a"
  },
  {
    id: 3,
    timestamp: "2025-04-16T02:34:56.000Z",
    ruleName: "Suspicious PowerShell Command",
    ruleSid: 1000003,
    srcIp: "192.168.1.110",
    dstIp: "192.168.1.120",
    protocol: "TCP",
    severity: "critical",
    packetData: "4500 012c 1a2b 4000 8006 3dca c0a8 016e c0a8 0178 d34a 0a8c 0000 0000 0000 0000 a002 16d0 8a4c 0000 0204 05b4 0402 080a 003a 8b2c 0000 0000 0103 0303 7061 7973 6865 6c6c 2e65 7865 202d 6578 6563 2062 7970 6173 7320 2d6e 6f70 726f 6669 6c65 202d 656e 6320 5a47 566d 4948 5668 6369 426c 6348 4169 4946 4e6c 6448 5674 4c55 6c75 6447 5679 626d 5630 4c6e 4e6c 636e 5a70 5932 5575 2e2e 2e"
  },
  {
    id: 4,
    timestamp: "2025-04-15T19:12:43.000Z",
    ruleName: "Potential XSS Attack",
    ruleSid: 1000002,
    srcIp: "203.0.113.15",
    dstIp: "192.168.1.100",
    protocol: "TCP",
    severity: "high",
    packetData: "4500 00e2 3c1d 4000 4006 8299 cb00 710f c0a8 0164 a69c 0050 0000 0000 0000 0000 a002 16d0 d6e5 0000 0204 05b4 0402 080a 0048 7516 0000 0000 0103 0303 4745 5420 2f73 6561 7263 682e 7068 703f 713d 3c73 6372 6970 7420 7372 633d 6874 7470 733a 2f2f 6d61 6c69 6369 6f75 732e 6578 616d 706c 652f 6d61 6c77 6172 652e 6a73 3e3c 2f73 6372 6970 743e 2048 5454 502f 312e 310d 0a48 6f73 743a 2065 7861 6d70 6c65 2e63 6f6d 0d0a"
  },
  {
    id: 5,
    timestamp: "2025-04-14T21:09:33.000Z",
    ruleName: "SMB Remote Code Execution Attempt",
    ruleSid: 1000004,
    srcIp: "203.0.113.55",
    dstIp: "192.168.1.5",
    protocol: "TCP",
    severity: "critical",
    packetData: "4500 0084 6e91 4000 3706 ed46 cb00 7137 c0a8 0105 c917 01bd 0000 0000 0000 0000 a002 16d0 6289 0000 0204 05b4 0402 080a 006e 3f08 0000 0000 0103 0303 ff53 4d42 7200 0000 0008 0100 0000 0000 0000 0000 0000 0000 0000 0000 ffff ffff 0000 5c49 5043 245c"
  }
];

const SignatureDetection = () => {
  const [signatures, setSignatures] = useState(signatureRulesMock);
  const [matches] = useState(signatureMatchesMock);
  const [searchTerm, setSearchTerm] = useState("");
  const [severityFilter, setSeverityFilter] = useState("all");
  const [categoryFilter, setCategoryFilter] = useState("all");
  const [activeTab, setActiveTab] = useState("signatures");
  
  // New signature rule form
  const [newSignature, setNewSignature] = useState({
    name: "",
    description: "",
    content: "",
    severity: "medium",
    category: "web-attacks",
    enabled: true
  });

  // Filter function for signatures based on search, severity, and category
  const filteredSignatures = signatures.filter(sig => {
    const matchesSearch = 
      searchTerm === "" || 
      sig.name.toLowerCase().includes(searchTerm.toLowerCase()) || 
      sig.description.toLowerCase().includes(searchTerm.toLowerCase()) ||
      sig.content.toLowerCase().includes(searchTerm.toLowerCase()) ||
      sig.sid.toString().includes(searchTerm);
    
    const matchesSeverity = 
      severityFilter === "all" || 
      sig.severity.toLowerCase() === severityFilter.toLowerCase();
    
    const matchesCategory = 
      categoryFilter === "all" || 
      sig.category.toLowerCase() === categoryFilter.toLowerCase();
    
    return matchesSearch && matchesSeverity && matchesCategory;
  });

  // Filter function for matches based on search and severity
  const filteredMatches = matches.filter(match => {
    const matchesSearch = 
      searchTerm === "" || 
      match.ruleName.toLowerCase().includes(searchTerm.toLowerCase()) || 
      match.srcIp.includes(searchTerm) ||
      match.dstIp.includes(searchTerm) ||
      match.ruleSid.toString().includes(searchTerm);
    
    const matchesSeverity = 
      severityFilter === "all" || 
      match.severity.toLowerCase() === severityFilter.toLowerCase();
    
    return matchesSearch && matchesSeverity;
  });

  // Handler for toggling signature enabled status
  const toggleSignatureStatus = (id: number) => {
    setSignatures(
      signatures.map(sig => 
        sig.id === id ? { ...sig, enabled: !sig.enabled } : sig
      )
    );
    
    const signature = signatures.find(s => s.id === id);
    toast.success(`Signature ${!signature?.enabled ? "enabled" : "disabled"}`, {
      description: `${signature?.name} has been ${!signature?.enabled ? "enabled" : "disabled"}`
    });
  };

  // Handler for adding a new signature
  const addSignature = () => {
    if (!newSignature.name || !newSignature.content) {
      toast.error("Missing required fields", {
        description: "Name and signature content are required"
      });
      return;
    }
    
    const newId = Math.max(...signatures.map(s => s.id)) + 1;
    const newSid = Math.max(...signatures.map(s => s.sid)) + 1;
    
    const now = new Date().toISOString();
    
    setSignatures([
      ...signatures,
      {
        ...newSignature,
        id: newId,
        sid: newSid,
        created: now,
        lastMatched: null,
        matchCount: 0
      }
    ]);
    
    // Reset form
    setNewSignature({
      name: "",
      description: "",
      content: "",
      severity: "medium",
      category: "web-attacks",
      enabled: true
    });
    
    toast.success("Signature rule created", {
      description: `New rule "${newSignature.name}" has been added`
    });
  };

  // Handler for deleting a signature
  const deleteSignature = (id: number) => {
    const signature = signatures.find(s => s.id === id);
    setSignatures(signatures.filter(sig => sig.id !== id));
    
    toast.success("Signature rule deleted", {
      description: `"${signature?.name}" has been removed`
    });
  };

  // Function to get style based on severity level
  const getSeverityBadgeStyle = (severity: string) => {
    switch (severity.toLowerCase()) {
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
          <h1 className="text-3xl font-bold tracking-tight">Signature Detection</h1>
          <p className="text-muted-foreground">
            Pattern matching against known threat signatures
          </p>
        </div>
        <div className="flex gap-2">
          <Button
            variant="outline"
            className="flex items-center gap-2"
            onClick={() => {
              toast.success("Signatures refreshed", {
                description: "All signature data has been updated"
              });
            }}
          >
            <RefreshCw className="h-4 w-4" />
            Refresh
          </Button>
          <Button 
            className="flex items-center gap-2"
            onClick={() => {
              toast({
                title: "Import signatures",
                description: "Upload Snort or Suricata compatible rule files",
                action: {
                  label: "Select File",
                  onClick: () => {
                    toast.success("Rules imported successfully", {
                      description: "42 new signatures have been added"
                    });
                  }
                }
              });
            }}
          >
            <Upload className="h-4 w-4" />
            Import
          </Button>
        </div>
      </div>

      {/* Summary Stats */}
      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4">
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">Total Signatures</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{signatures.length}</div>
            <p className="text-xs text-muted-foreground">
              {signatures.filter(s => s.enabled).length} active, {signatures.filter(s => !s.enabled).length} disabled
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">Recent Matches</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{matches.length}</div>
            <p className="text-xs text-muted-foreground">
              Last match: {new Date(matches[0]?.timestamp).toLocaleTimeString()}
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">Critical Alerts</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{matches.filter(m => m.severity === "critical").length}</div>
            <p className="text-xs text-muted-foreground">
              {matches.filter(m => m.severity === "high").length} high severity alerts
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">Coverage</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {signatures.filter(s => s.matchCount > 0).length}/{signatures.length}
            </div>
            <p className="text-xs text-muted-foreground">
              Signatures with matches
            </p>
          </CardContent>
        </Card>
      </div>

      {/* Search and Filters */}
      <div className="flex flex-col sm:flex-row gap-4">
        <div className="relative flex-1">
          <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
          <Input
            type="search"
            placeholder="Search signatures, SIDs, or IP addresses..."
            className="pl-8"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
          />
        </div>
        <Select 
          value={severityFilter} 
          onValueChange={setSeverityFilter}
        >
          <SelectTrigger className="w-full sm:w-[140px]">
            <SelectValue placeholder="Severity" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Severities</SelectItem>
            <SelectItem value="low">Low</SelectItem>
            <SelectItem value="medium">Medium</SelectItem>
            <SelectItem value="high">High</SelectItem>
            <SelectItem value="critical">Critical</SelectItem>
          </SelectContent>
        </Select>
        <Select 
          value={categoryFilter} 
          onValueChange={setCategoryFilter}
        >
          <SelectTrigger className="w-full sm:w-[160px]">
            <SelectValue placeholder="Category" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Categories</SelectItem>
            <SelectItem value="web-attacks">Web Attacks</SelectItem>
            <SelectItem value="malware">Malware</SelectItem>
            <SelectItem value="exploits">Exploits</SelectItem>
            <SelectItem value="recon">Reconnaissance</SelectItem>
            <SelectItem value="brute-force">Brute Force</SelectItem>
            <SelectItem value="policy-violation">Policy Violation</SelectItem>
          </SelectContent>
        </Select>
      </div>

      {/* Main Tabs */}
      <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
        <TabsList className="grid grid-cols-1 md:grid-cols-3 w-full max-w-md">
          <TabsTrigger value="signatures" className="flex items-center gap-2">
            <Shield className="h-4 w-4" />
            Signature Rules
          </TabsTrigger>
          <TabsTrigger value="matches" className="flex items-center gap-2">
            <AlertTriangle className="h-4 w-4" />
            Signature Matches
          </TabsTrigger>
          <TabsTrigger value="create" className="flex items-center gap-2">
            <Plus className="h-4 w-4" />
            Create Signature
          </TabsTrigger>
        </TabsList>
        
        {/* Signature Rules Tab */}
        <TabsContent value="signatures" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Signature Rules</CardTitle>
              <CardDescription>
                Pattern-matching rules for detecting known threats
              </CardDescription>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-[80px]">SID</TableHead>
                    <TableHead>Signature Name</TableHead>
                    <TableHead>Severity</TableHead>
                    <TableHead>Category</TableHead>
                    <TableHead>Matches</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead className="text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filteredSignatures.map((sig) => (
                    <TableRow key={sig.id}>
                      <TableCell className="font-mono text-xs">{sig.sid}</TableCell>
                      <TableCell>
                        <div>
                          <div className="font-medium">{sig.name}</div>
                          <div className="text-xs text-muted-foreground">{sig.description}</div>
                        </div>
                      </TableCell>
                      <TableCell>
                        <Badge className={getSeverityBadgeStyle(sig.severity)}>
                          {sig.severity.charAt(0).toUpperCase() + sig.severity.slice(1)}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <Badge variant="outline" className="capitalize">
                          {sig.category}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        {sig.matchCount > 0 ? (
                          <div className="text-sm">
                            {sig.matchCount}
                            <span className="text-xs text-muted-foreground ml-1">
                              (last: {new Date(sig.lastMatched).toLocaleDateString()})
                            </span>
                          </div>
                        ) : (
                          <span className="text-xs text-muted-foreground">No matches</span>
                        )}
                      </TableCell>
                      <TableCell>
                        {sig.enabled ? (
                          <Badge className="bg-green-500 hover:bg-green-600">Enabled</Badge>
                        ) : (
                          <Badge variant="outline">Disabled</Badge>
                        )}
                      </TableCell>
                      <TableCell className="text-right">
                        <DropdownMenu>
                          <DropdownMenuTrigger asChild>
                            <Button variant="ghost" size="sm">
                              <FileText className="h-4 w-4" />
                            </Button>
                          </DropdownMenuTrigger>
                          <DropdownMenuContent align="end">
                            <DropdownMenuLabel>Rule Actions</DropdownMenuLabel>
                            <DropdownMenuSeparator />
                            <DropdownMenuItem
                              onClick={() => {
                                toast.info("Signature Details", {
                                  description: sig.content
                                });
                              }}
                              className="flex items-center gap-2"
                            >
                              <Code className="h-4 w-4" />
                              <span>View Rule</span>
                            </DropdownMenuItem>
                            <DropdownMenuItem
                              onClick={() => toggleSignatureStatus(sig.id)}
                              className="flex items-center gap-2"
                            >
                              {sig.enabled ? (
                                <>
                                  <X className="h-4 w-4" />
                                  <span>Disable</span>
                                </>
                              ) : (
                                <>
                                  <Check className="h-4 w-4" />
                                  <span>Enable</span>
                                </>
                              )}
                            </DropdownMenuItem>
                            <DropdownMenuItem
                              onClick={() => deleteSignature(sig.id)}
                              className="flex items-center gap-2 text-red-600"
                            >
                              <Trash2 className="h-4 w-4" />
                              <span>Delete</span>
                            </DropdownMenuItem>
                          </DropdownMenuContent>
                        </DropdownMenu>
                      </TableCell>
                    </TableRow>
                  ))}
                  {filteredSignatures.length === 0 && (
                    <TableRow>
                      <TableCell colSpan={7} className="text-center py-6 text-muted-foreground">
                        No signatures match your filters
                      </TableCell>
                    </TableRow>
                  )}
                </TableBody>
              </Table>
            </CardContent>
            <CardFooter className="justify-between">
              <Button
                variant="outline"
                className="flex items-center gap-2"
                onClick={() => {
                  toast.success("Rules exported", {
                    description: "All rules exported to signatures.rules"
                  });
                }}
              >
                <Download className="h-4 w-4" />
                Export Rules
              </Button>
              <div className="text-sm text-muted-foreground">
                Showing {filteredSignatures.length} of {signatures.length} signatures
              </div>
            </CardFooter>
          </Card>
        </TabsContent>
        
        {/* Signature Matches Tab */}
        <TabsContent value="matches" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Signature Matches</CardTitle>
              <CardDescription>
                Recent traffic matching signature detection rules
              </CardDescription>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Time</TableHead>
                    <TableHead>Rule Name (SID)</TableHead>
                    <TableHead>Source</TableHead>
                    <TableHead>Destination</TableHead>
                    <TableHead>Protocol</TableHead>
                    <TableHead>Severity</TableHead>
                    <TableHead className="text-right">Packet</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filteredMatches.map((match) => (
                    <TableRow key={match.id}>
                      <TableCell>
                        {new Date(match.timestamp).toLocaleTimeString()}
                      </TableCell>
                      <TableCell>
                        <div className="font-medium">{match.ruleName}</div>
                        <div className="text-xs text-muted-foreground">SID: {match.ruleSid}</div>
                      </TableCell>
                      <TableCell>{match.srcIp}</TableCell>
                      <TableCell>{match.dstIp}</TableCell>
                      <TableCell>{match.protocol}</TableCell>
                      <TableCell>
                        <Badge className={getSeverityBadgeStyle(match.severity)}>
                          {match.severity.charAt(0).toUpperCase() + match.severity.slice(1)}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-right">
                        <Button 
                          variant="ghost" 
                          size="sm"
                          onClick={() => {
                            toast.info(`Packet Data (${match.ruleName})`, {
                              description: <div className="font-mono text-xs break-all">{match.packetData}</div>
                            });
                          }}
                        >
                          <FileCode2 className="h-4 w-4" />
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))}
                  {filteredMatches.length === 0 && (
                    <TableRow>
                      <TableCell colSpan={7} className="text-center py-6 text-muted-foreground">
                        No signature matches found for the current filters
                      </TableCell>
                    </TableRow>
                  )}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>
        
        {/* Create Signature Tab */}
        <TabsContent value="create" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Create New Signature</CardTitle>
              <CardDescription>
                Define pattern-matching rules to detect malicious traffic
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label htmlFor="rule-name">Rule Name</Label>
                  <Input 
                    id="rule-name" 
                    placeholder="e.g., SQL Injection Detection" 
                    value={newSignature.name}
                    onChange={(e) => setNewSignature({...newSignature, name: e.target.value})}
                  />
                </div>
                <div className="grid grid-cols-2 gap-4">
                  <div className="space-y-2">
                    <Label htmlFor="rule-severity">Severity</Label>
                    <Select 
                      value={newSignature.severity}
                      onValueChange={(value) => setNewSignature({...newSignature, severity: value})}
                    >
                      <SelectTrigger>
                        <SelectValue placeholder="Select severity" />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="low">Low</SelectItem>
                        <SelectItem value="medium">Medium</SelectItem>
                        <SelectItem value="high">High</SelectItem>
                        <SelectItem value="critical">Critical</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="rule-category">Category</Label>
                    <Select 
                      value={newSignature.category}
                      onValueChange={(value) => setNewSignature({...newSignature, category: value})}
                    >
                      <SelectTrigger>
                        <SelectValue placeholder="Select category" />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="web-attacks">Web Attacks</SelectItem>
                        <SelectItem value="malware">Malware</SelectItem>
                        <SelectItem value="exploits">Exploits</SelectItem>
                        <SelectItem value="recon">Reconnaissance</SelectItem>
                        <SelectItem value="brute-force">Brute Force</SelectItem>
                        <SelectItem value="policy-violation">Policy Violation</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                </div>
              </div>
              
              <div className="space-y-2">
                <Label htmlFor="rule-description">Description</Label>
                <Input 
                  id="rule-description" 
                  placeholder="Describe what this rule detects" 
                  value={newSignature.description}
                  onChange={(e) => setNewSignature({...newSignature, description: e.target.value})}
                />
              </div>
              
              <div className="space-y-2">
                <div className="flex justify-between items-center">
                  <Label htmlFor="rule-content">Signature Content (Snort/Suricata format)</Label>
                  <Button variant="ghost" size="sm" className="text-xs">
                    Format Help
                  </Button>
                </div>
                <Textarea 
                  id="rule-content" 
                  placeholder='alert tcp any any -> any 80 (msg:"Example Rule"; content:"malicious"; sid:1000042; rev:1;)'
                  className="font-mono h-32"
                  value={newSignature.content}
                  onChange={(e) => setNewSignature({...newSignature, content: e.target.value})}
                />
              </div>
              
              <div className="flex items-center space-x-2">
                <Switch 
                  checked={newSignature.enabled}
                  onCheckedChange={(checked) => setNewSignature({...newSignature, enabled: checked})}
                  id="rule-enabled" 
                />
                <Label htmlFor="rule-enabled">Enable rule after creation</Label>
              </div>
            </CardContent>
            <CardFooter className="flex justify-between">
              <Button 
                variant="outline"
                onClick={() => {
                  setNewSignature({
                    name: "",
                    description: "",
                    content: "",
                    severity: "medium",
                    category: "web-attacks",
                    enabled: true
                  });
                  toast.info("Form reset", {
                    description: "All fields have been cleared"
                  });
                }}
              >
                Reset
              </Button>
              <Button 
                onClick={addSignature}
                className="flex items-center gap-2"
              >
                <Plus className="h-4 w-4" />
                Create Signature
              </Button>
            </CardFooter>
          </Card>
          
          <Card>
            <CardHeader>
              <CardTitle>Template Library</CardTitle>
              <CardDescription>
                Use common signature templates to get started quickly
              </CardDescription>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Template</TableHead>
                    <TableHead>Description</TableHead>
                    <TableHead>Category</TableHead>
                    <TableHead className="text-right">Use</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  <TableRow>
                    <TableCell className="font-medium">SQL Injection</TableCell>
                    <TableCell>Common SQL injection patterns in HTTP requests</TableCell>
                    <TableCell>
                      <Badge variant="outline">Web Attacks</Badge>
                    </TableCell>
                    <TableCell className="text-right">
                      <Button 
                        variant="ghost" 
                        size="sm"
                        onClick={() => {
                          setNewSignature({
                            ...newSignature,
                            name: "SQL Injection Detection",
                            description: "Detects common SQL injection patterns in HTTP requests",
                            category: "web-attacks",
                            content: 'alert tcp any any -> any 80 (msg:"SQL Injection Detection"; content:"SELECT"; nocase; content:"FROM"; distance:0; nocase; content:"WHERE"; distance:0; nocase; classtype:web-application-attack; sid:1000099; rev:1;)'
                          });
                          toast.success("Template applied", {
                            description: "SQL Injection template has been loaded"
                          });
                        }}
                      >
                        <Plus className="h-4 w-4" />
                      </Button>
                    </TableCell>
                  </TableRow>
                  <TableRow>
                    <TableCell className="font-medium">Command Injection</TableCell>
                    <TableCell>Common OS command injection attempts</TableCell>
                    <TableCell>
                      <Badge variant="outline">Web Attacks</Badge>
                    </TableCell>
                    <TableCell className="text-right">
                      <Button 
                        variant="ghost" 
                        size="sm"
                        onClick={() => {
                          setNewSignature({
                            ...newSignature,
                            name: "Command Injection Detection",
                            description: "Detects OS command injection attempts in HTTP parameters",
                            category: "web-attacks",
                            content: 'alert tcp any any -> any 80 (msg:"Command Injection Detection"; content:"|3b|"; pcre:"/;\\s*(curl|wget|bash|sh|rm|cat|nc|netcat)/i"; classtype:web-application-attack; sid:1000100; rev:1;)'
                          });
                          toast.success("Template applied", {
                            description: "Command Injection template has been loaded"
                          });
                        }}
                      >
                        <Plus className="h-4 w-4" />
                      </Button>
                    </TableCell>
                  </TableRow>
                  <TableRow>
                    <TableCell className="font-medium">CVE-2023-12345</TableCell>
                    <TableCell>Example vulnerability signature for CVE-2023-12345</TableCell>
                    <TableCell>
                      <Badge variant="outline">Exploits</Badge>
                    </TableCell>
                    <TableCell className="text-right">
                      <Button 
                        variant="ghost" 
                        size="sm"
                        onClick={() => {
                          setNewSignature({
                            ...newSignature,
                            name: "CVE-2023-12345 Exploit Detection",
                            description: "Detects exploitation attempts of the CVE-2023-12345 vulnerability",
                            category: "exploits",
                            severity: "critical",
                            content: 'alert tcp any any -> any any (msg:"CVE-2023-12345 Exploit Attempt"; flow:established,to_server; content:"EXPLOIT"; fast_pattern; content:"CVE-2023-12345"; distance:0; within:20; classtype:attempted-admin; sid:1000101; rev:1;)'
                          });
                          toast.success("Template applied", {
                            description: "CVE-2023-12345 template has been loaded"
                          });
                        }}
                      >
                        <Plus className="h-4 w-4" />
                      </Button>
                    </TableCell>
                  </TableRow>
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
};

export default SignatureDetection;
