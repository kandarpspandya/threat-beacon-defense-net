
import { useState } from "react";
import { Shield, AlertTriangle, Filter, Download, Clock, ArrowRight, Search } from "lucide-react";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Badge } from "@/components/ui/badge";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { format } from "date-fns";

interface Alert {
  id: number;
  type: string;
  source: string;
  destination: string;
  severity: "high" | "medium" | "low";
  timestamp: string;
  status: "blocked" | "monitoring" | "investigating";
  description: string;
  protocol: string;
}

const AlertsPage = () => {
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedSeverity, setSelectedSeverity] = useState<string>("all");
  const [selectedStatus, setSelectedStatus] = useState<string>("all");
  
  // Mock alerts data
  const alerts: Alert[] = [
    {
      id: 1,
      type: "Ransomware",
      source: "45.123.45.123",
      destination: "192.168.1.5",
      severity: "high",
      timestamp: "2023-10-10T14:23:45Z",
      status: "blocked",
      description: "Suspicious binary execution followed by file encryption activity",
      protocol: "HTTPS",
    },
    {
      id: 2,
      type: "SQL Injection",
      source: "89.234.53.12",
      destination: "192.168.1.20",
      severity: "medium",
      timestamp: "2023-10-10T13:42:32Z",
      status: "blocked",
      description: "Malformed SQL statements detected in HTTP request",
      protocol: "HTTP",
    },
    {
      id: 3,
      type: "Port Scan",
      source: "107.45.67.89",
      destination: "192.168.1.1",
      severity: "low",
      timestamp: "2023-10-10T12:56:18Z",
      status: "monitoring",
      description: "Sequential connection attempts to multiple ports",
      protocol: "TCP",
    },
    {
      id: 4,
      type: "Brute Force",
      source: "91.234.123.45",
      destination: "192.168.1.10",
      severity: "medium",
      timestamp: "2023-10-10T11:20:45Z",
      status: "blocked",
      description: "Multiple failed login attempts to SSH service",
      protocol: "SSH",
    },
    {
      id: 5,
      type: "Data Exfiltration",
      source: "192.168.1.42",
      destination: "suspicious-domain.com",
      severity: "high",
      timestamp: "2023-10-10T10:15:22Z",
      status: "investigating",
      description: "Unusual outbound data transfer to unknown domain",
      protocol: "DNS",
    },
    {
      id: 6,
      type: "XSS Attack",
      source: "78.45.123.210",
      destination: "192.168.1.30",
      severity: "medium",
      timestamp: "2023-10-10T09:45:11Z",
      status: "blocked",
      description: "Malicious JavaScript injection attempt detected",
      protocol: "HTTP",
    },
    {
      id: 7,
      type: "DDoS",
      source: "Multiple",
      destination: "192.168.1.1",
      severity: "high",
      timestamp: "2023-10-10T08:30:55Z",
      status: "investigating",
      description: "Abnormal traffic spike from multiple sources",
      protocol: "UDP",
    },
    {
      id: 8,
      type: "Phishing",
      source: "fake-bank.example.com",
      destination: "192.168.1.15",
      severity: "medium",
      timestamp: "2023-10-10T07:20:33Z",
      status: "blocked",
      description: "Suspicious email with credential harvesting link",
      protocol: "SMTP",
    },
  ];

  const severityColor = (severity: Alert["severity"]) => {
    switch (severity) {
      case "high":
        return "border-sentinel-danger/30 bg-sentinel-danger/10 text-sentinel-danger";
      case "medium":
        return "border-sentinel-warning/30 bg-sentinel-warning/10 text-sentinel-warning";
      case "low":
        return "border-sentinel-info/30 bg-sentinel-info/10 text-sentinel-info";
      default:
        return "border-muted/30 bg-muted/10 text-muted-foreground";
    }
  };

  const statusColor = (status: Alert["status"]) => {
    switch (status) {
      case "blocked":
        return "border-sentinel-success/30 bg-sentinel-success/10 text-sentinel-success";
      case "monitoring":
        return "border-sentinel-info/30 bg-sentinel-info/10 text-sentinel-info";
      case "investigating":
        return "border-sentinel-warning/30 bg-sentinel-warning/10 text-sentinel-warning";
      default:
        return "border-muted/30 bg-muted/10 text-muted-foreground";
    }
  };

  // Filter alerts based on search query, severity, and status
  const filteredAlerts = alerts.filter((alert) => {
    const matchesSearch =
      searchQuery === "" ||
      alert.type.toLowerCase().includes(searchQuery.toLowerCase()) ||
      alert.source.toLowerCase().includes(searchQuery.toLowerCase()) ||
      alert.destination.toLowerCase().includes(searchQuery.toLowerCase()) ||
      alert.description.toLowerCase().includes(searchQuery.toLowerCase());

    const matchesSeverity = selectedSeverity === "all" || alert.severity === selectedSeverity;
    const matchesStatus = selectedStatus === "all" || alert.status === selectedStatus;

    return matchesSearch && matchesSeverity && matchesStatus;
  });

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-3xl font-bold tracking-tight">Alerts</h2>
        <div className="flex items-center space-x-2">
          <Button variant="outline" size="sm">
            <Download className="mr-2 h-4 w-4" />
            Export
          </Button>
        </div>
      </div>

      <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm">
        <CardHeader>
          <CardTitle>Alert Management</CardTitle>
          <CardDescription>
            View and manage detected security threats
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Tabs defaultValue="all" className="space-y-4">
            <div className="flex flex-col space-y-4 md:flex-row md:items-center md:justify-between md:space-y-0">
              <TabsList className="bg-background/50">
                <TabsTrigger value="all">All Alerts</TabsTrigger>
                <TabsTrigger value="high">
                  <AlertTriangle className="mr-1 h-4 w-4 text-sentinel-danger" />
                  High Severity
                </TabsTrigger>
                <TabsTrigger value="blocked">
                  <Shield className="mr-1 h-4 w-4 text-sentinel-success" />
                  Blocked
                </TabsTrigger>
              </TabsList>
              
              <div className="flex items-center space-x-2">
                <div className="relative">
                  <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
                  <Input
                    type="search"
                    placeholder="Search alerts..."
                    className="pl-8"
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                  />
                </div>
                <Button variant="outline" size="icon">
                  <Filter className="h-4 w-4" />
                </Button>
              </div>
            </div>
            
            <div className="flex items-center gap-4">
              <div className="flex items-center gap-2">
                <span className="text-sm font-medium">Severity:</span>
                <Select value={selectedSeverity} onValueChange={setSelectedSeverity}>
                  <SelectTrigger className="w-[100px]">
                    <SelectValue placeholder="All" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All</SelectItem>
                    <SelectItem value="high">High</SelectItem>
                    <SelectItem value="medium">Medium</SelectItem>
                    <SelectItem value="low">Low</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              
              <div className="flex items-center gap-2">
                <span className="text-sm font-medium">Status:</span>
                <Select value={selectedStatus} onValueChange={setSelectedStatus}>
                  <SelectTrigger className="w-[120px]">
                    <SelectValue placeholder="All" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All</SelectItem>
                    <SelectItem value="blocked">Blocked</SelectItem>
                    <SelectItem value="monitoring">Monitoring</SelectItem>
                    <SelectItem value="investigating">Investigating</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>
            
            <TabsContent value="all" className="space-y-4">
              <div className="rounded-md border border-sentinel-light/10">
                <Table>
                  <TableHeader className="bg-background/50">
                    <TableRow>
                      <TableHead>Timestamp</TableHead>
                      <TableHead>Type</TableHead>
                      <TableHead>Source/Destination</TableHead>
                      <TableHead>Severity</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead>Protocol</TableHead>
                      <TableHead className="hidden md:table-cell">Description</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {filteredAlerts.map((alert) => (
                      <TableRow key={alert.id} className="hover:bg-card transition-colors">
                        <TableCell className="font-mono">
                          <div className="flex items-center">
                            <Clock className="mr-2 h-3 w-3 text-muted-foreground" />
                            {format(new Date(alert.timestamp), "yyyy-MM-dd HH:mm")}
                          </div>
                        </TableCell>
                        <TableCell>{alert.type}</TableCell>
                        <TableCell>
                          <div className="flex items-center text-xs font-mono">
                            <span>{alert.source}</span>
                            <ArrowRight className="mx-1 h-3 w-3 text-muted-foreground" />
                            <span>{alert.destination}</span>
                          </div>
                        </TableCell>
                        <TableCell>
                          <Badge className={severityColor(alert.severity)}>
                            {alert.severity}
                          </Badge>
                        </TableCell>
                        <TableCell>
                          <Badge className={statusColor(alert.status)}>
                            {alert.status}
                          </Badge>
                        </TableCell>
                        <TableCell>{alert.protocol}</TableCell>
                        <TableCell className="hidden max-w-[300px] truncate md:table-cell">
                          {alert.description}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            </TabsContent>
            
            <TabsContent value="high" className="space-y-4">
              <div className="rounded-md border border-sentinel-light/10">
                <Table>
                  <TableHeader className="bg-background/50">
                    <TableRow>
                      <TableHead>Timestamp</TableHead>
                      <TableHead>Type</TableHead>
                      <TableHead>Source/Destination</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead>Protocol</TableHead>
                      <TableHead className="hidden md:table-cell">Description</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {alerts
                      .filter((alert) => alert.severity === "high")
                      .map((alert) => (
                        <TableRow key={alert.id} className="hover:bg-card transition-colors">
                          <TableCell className="font-mono">
                            <div className="flex items-center">
                              <Clock className="mr-2 h-3 w-3 text-muted-foreground" />
                              {format(new Date(alert.timestamp), "yyyy-MM-dd HH:mm")}
                            </div>
                          </TableCell>
                          <TableCell>{alert.type}</TableCell>
                          <TableCell>
                            <div className="flex items-center text-xs font-mono">
                              <span>{alert.source}</span>
                              <ArrowRight className="mx-1 h-3 w-3 text-muted-foreground" />
                              <span>{alert.destination}</span>
                            </div>
                          </TableCell>
                          <TableCell>
                            <Badge className={statusColor(alert.status)}>
                              {alert.status}
                            </Badge>
                          </TableCell>
                          <TableCell>{alert.protocol}</TableCell>
                          <TableCell className="hidden max-w-[300px] truncate md:table-cell">
                            {alert.description}
                          </TableCell>
                        </TableRow>
                      ))}
                  </TableBody>
                </Table>
              </div>
            </TabsContent>
            
            <TabsContent value="blocked" className="space-y-4">
              <div className="rounded-md border border-sentinel-light/10">
                <Table>
                  <TableHeader className="bg-background/50">
                    <TableRow>
                      <TableHead>Timestamp</TableHead>
                      <TableHead>Type</TableHead>
                      <TableHead>Source/Destination</TableHead>
                      <TableHead>Severity</TableHead>
                      <TableHead>Protocol</TableHead>
                      <TableHead className="hidden md:table-cell">Description</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {alerts
                      .filter((alert) => alert.status === "blocked")
                      .map((alert) => (
                        <TableRow key={alert.id} className="hover:bg-card transition-colors">
                          <TableCell className="font-mono">
                            <div className="flex items-center">
                              <Clock className="mr-2 h-3 w-3 text-muted-foreground" />
                              {format(new Date(alert.timestamp), "yyyy-MM-dd HH:mm")}
                            </div>
                          </TableCell>
                          <TableCell>{alert.type}</TableCell>
                          <TableCell>
                            <div className="flex items-center text-xs font-mono">
                              <span>{alert.source}</span>
                              <ArrowRight className="mx-1 h-3 w-3 text-muted-foreground" />
                              <span>{alert.destination}</span>
                            </div>
                          </TableCell>
                          <TableCell>
                            <Badge className={severityColor(alert.severity)}>
                              {alert.severity}
                            </Badge>
                          </TableCell>
                          <TableCell>{alert.protocol}</TableCell>
                          <TableCell className="hidden max-w-[300px] truncate md:table-cell">
                            {alert.description}
                          </TableCell>
                        </TableRow>
                      ))}
                  </TableBody>
                </Table>
              </div>
            </TabsContent>
          </Tabs>
        </CardContent>
      </Card>
    </div>
  );
};

export default AlertsPage;
