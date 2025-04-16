
import { useState, useEffect } from "react";
import { Clock, FileText, Database, Download, Filter, RefreshCw, Search, ArrowDown, ArrowUp, X } from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Progress } from "@/components/ui/progress";
import { toast } from "sonner";
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts';

// Mock log data with various types and severity levels
const generateLogs = (count: number) => {
  const types = ["Network", "Security", "System", "Authentication", "Firewall", "Intrusion"];
  const actions = ["Connection", "Block", "Alert", "Login", "Logout", "Access", "Modify", "Delete", "Create"];
  const statuses = ["Success", "Failure", "Warning", "Error", "Info"];
  const severities = ["critical", "high", "medium", "low", "info"];
  const ips = ["192.168.1.45", "10.0.0.12", "203.0.113.42", "198.51.100.74", "192.168.1.22", "10.0.0.35"];
  
  const logs = [];
  
  // Start 24 hours ago
  const startTime = new Date(Date.now() - 24 * 60 * 60 * 1000);
  
  for (let i = 0; i < count; i++) {
    const type = types[Math.floor(Math.random() * types.length)];
    const action = actions[Math.floor(Math.random() * actions.length)];
    const status = statuses[Math.floor(Math.random() * statuses.length)];
    const severity = severities[Math.floor(Math.random() * severities.length)];
    const ip = ips[Math.floor(Math.random() * ips.length)];
    
    // Generate messages based on type and action
    let message = "";
    if (type === "Network") {
      message = `${action} ${status.toLowerCase()} from ${ip}`;
    } else if (type === "Security") {
      message = `Security ${action.toLowerCase()} ${status.toLowerCase()}`;
    } else if (type === "System") {
      message = `System ${action.toLowerCase()} ${status.toLowerCase()}`;
    } else if (type === "Authentication") {
      message = `User ${action.toLowerCase()} ${status.toLowerCase()}`;
    } else if (type === "Firewall") {
      message = `Firewall ${action.toLowerCase()} for ${ip}`;
    } else if (type === "Intrusion") {
      message = `Potential intrusion detected from ${ip}`;
    }
    
    // Random time within the last 24 hours, with more recent logs more likely
    const hoursAgo = Math.pow(Math.random(), 2) * 24;
    const timestamp = new Date(Date.now() - hoursAgo * 60 * 60 * 1000).toISOString();
    
    logs.push({
      id: i + 1,
      timestamp,
      type,
      action,
      status,
      severity,
      source: ip,
      message,
      details: `${type} ${action} event occurred. Status: ${status}. Source: ${ip}.`
    });
  }
  
  // Sort logs by timestamp, newest first
  return logs.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
};

// Initialize logs
const initialLogs = generateLogs(100);

// Generate data for log activity chart
const generateLogActivityData = () => {
  const data = [];
  
  for (let i = 23; i >= 0; i--) {
    const hour = new Date();
    hour.setHours(hour.getHours() - i);
    hour.setMinutes(0);
    hour.setSeconds(0);
    hour.setMilliseconds(0);
    
    // Generate counts for different severity levels
    const critical = Math.floor(Math.random() * 3);
    const high = Math.floor(Math.random() * 5);
    const medium = Math.floor(Math.random() * 10);
    const low = Math.floor(Math.random() * 15);
    const info = Math.floor(Math.random() * 25);
    
    data.push({
      time: hour.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      critical,
      high,
      medium,
      low,
      info,
      total: critical + high + medium + low + info
    });
  }
  
  return data;
};

const Logging = () => {
  const [logs, setLogs] = useState(initialLogs);
  const [filteredLogs, setFilteredLogs] = useState(initialLogs);
  const [filters, setFilters] = useState({
    type: "all",
    severity: "all",
    source: "",
    search: ""
  });
  const [sortField, setSortField] = useState("timestamp");
  const [sortOrder, setSortOrder] = useState("desc");
  const [logStats, setLogStats] = useState({
    total: initialLogs.length,
    critical: initialLogs.filter(log => log.severity === "critical").length,
    high: initialLogs.filter(log => log.severity === "high").length,
    medium: initialLogs.filter(log => log.severity === "medium").length,
    low: initialLogs.filter(log => log.severity === "low").length,
    info: initialLogs.filter(log => log.severity === "info").length
  });
  const [activityData, setActivityData] = useState(generateLogActivityData());
  const [logRetention, setLogRetention] = useState(30);
  const [storageUsed, setStorageUsed] = useState(42);
  const [selectedLog, setSelectedLog] = useState<any>(null);
  const [isExporting, setIsExporting] = useState(false);
  
  // Simulate log ingestion
  useEffect(() => {
    const interval = setInterval(() => {
      // Generate a new log
      const types = ["Network", "Security", "System", "Authentication", "Firewall", "Intrusion"];
      const actions = ["Connection", "Block", "Alert", "Login", "Logout", "Access", "Modify", "Delete", "Create"];
      const statuses = ["Success", "Failure", "Warning", "Error", "Info"];
      const severities = ["critical", "high", "medium", "low", "info"];
      const severityWeights = [0.05, 0.15, 0.25, 0.25, 0.3]; // Weights to make info and low more common
      
      const type = types[Math.floor(Math.random() * types.length)];
      const action = actions[Math.floor(Math.random() * actions.length)];
      const status = statuses[Math.floor(Math.random() * statuses.length)];
      
      // Use weighted random selection for severity
      let randomNum = Math.random();
      let severityIndex = 0;
      let cumulativeWeight = 0;
      
      for (let i = 0; i < severityWeights.length; i++) {
        cumulativeWeight += severityWeights[i];
        if (randomNum <= cumulativeWeight) {
          severityIndex = i;
          break;
        }
      }
      
      const severity = severities[severityIndex];
      const ip = `192.168.1.${Math.floor(Math.random() * 255)}`;
      
      // Generate message based on type and action
      let message = "";
      if (type === "Network") {
        message = `${action} ${status.toLowerCase()} from ${ip}`;
      } else if (type === "Security") {
        message = `Security ${action.toLowerCase()} ${status.toLowerCase()}`;
      } else if (type === "System") {
        message = `System ${action.toLowerCase()} ${status.toLowerCase()}`;
      } else if (type === "Authentication") {
        message = `User ${action.toLowerCase()} ${status.toLowerCase()}`;
      } else if (type === "Firewall") {
        message = `Firewall ${action.toLowerCase()} for ${ip}`;
      } else if (type === "Intrusion") {
        message = `Potential intrusion detected from ${ip}`;
      }
      
      const newLog = {
        id: Date.now(),
        timestamp: new Date().toISOString(),
        type,
        action,
        status,
        severity,
        source: ip,
        message,
        details: `${type} ${action} event occurred. Status: ${status}. Source: ${ip}.`
      };
      
      // Add the new log and update stats
      setLogs(prevLogs => [newLog, ...prevLogs]);
      
      // Show toast for critical and high severity events
      if (severity === "critical" || severity === "high") {
        toast.warning(`${severity.toUpperCase()}: ${message}`, {
          description: newLog.details,
          action: {
            label: "View",
            onClick: () => setSelectedLog(newLog)
          }
        });
      }
      
      // Update log stats
      setLogStats(prev => ({
        ...prev,
        total: prev.total + 1,
        [severity]: prev[severity as keyof typeof prev] + 1
      }));
      
      // Update activity data
      setActivityData(prev => {
        const newData = [...prev];
        const lastItem = newData[newData.length - 1];
        
        lastItem[severity as keyof typeof lastItem] += 1;
        lastItem.total += 1;
        
        return newData;
      });
      
      // Update storage used
      setStorageUsed(prev => Math.min(100, prev + 0.1));
    }, 10000);
    
    return () => clearInterval(interval);
  }, []);
  
  // Apply filters when they change
  useEffect(() => {
    let result = logs;
    
    if (filters.type !== "all") {
      result = result.filter(log => log.type === filters.type);
    }
    
    if (filters.severity !== "all") {
      result = result.filter(log => log.severity === filters.severity);
    }
    
    if (filters.source) {
      result = result.filter(log => log.source.includes(filters.source));
    }
    
    if (filters.search) {
      const searchLower = filters.search.toLowerCase();
      result = result.filter(log => 
        log.message.toLowerCase().includes(searchLower) ||
        log.details.toLowerCase().includes(searchLower) ||
        log.type.toLowerCase().includes(searchLower) ||
        log.action.toLowerCase().includes(searchLower) ||
        log.status.toLowerCase().includes(searchLower)
      );
    }
    
    // Apply sorting
    result = [...result].sort((a, b) => {
      if (sortField === "timestamp") {
        return sortOrder === "asc" 
          ? new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
          : new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime();
      }
      
      if (sortField === "severity") {
        const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
        return sortOrder === "asc"
          ? severityOrder[a.severity as keyof typeof severityOrder] - severityOrder[b.severity as keyof typeof severityOrder]
          : severityOrder[b.severity as keyof typeof severityOrder] - severityOrder[a.severity as keyof typeof severityOrder];
      }
      
      const aValue = a[sortField as keyof typeof a] || "";
      const bValue = b[sortField as keyof typeof b] || "";
      
      return sortOrder === "asc"
        ? aValue.toString().localeCompare(bValue.toString())
        : bValue.toString().localeCompare(aValue.toString());
    });
    
    setFilteredLogs(result);
  }, [logs, filters, sortField, sortOrder]);
  
  const clearFilters = () => {
    setFilters({
      type: "all",
      severity: "all",
      source: "",
      search: ""
    });
  };
  
  const handleSort = (field: string) => {
    if (sortField === field) {
      setSortOrder(sortOrder === "asc" ? "desc" : "asc");
    } else {
      setSortField(field);
      setSortOrder("desc");
    }
  };
  
  const exportLogs = (format: string) => {
    setIsExporting(true);
    
    // Simulate export delay
    setTimeout(() => {
      if (format === "csv") {
        // In a real app, this would export a CSV file
        toast.success("Logs exported as CSV", {
          description: `${filteredLogs.length} log entries exported`
        });
      } else {
        // In a real app, this would export a JSON file
        toast.success("Logs exported as JSON", {
          description: `${filteredLogs.length} log entries exported`
        });
      }
      setIsExporting(false);
    }, 1500);
  };
  
  const formatTimestamp = (timestamp: string) => {
    const date = new Date(timestamp);
    return date.toLocaleTimeString();
  };
  
  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case "critical": return "bg-red-500 text-white";
      case "high": return "bg-orange-500 text-white";
      case "medium": return "bg-yellow-500 text-black";
      case "low": return "bg-blue-500 text-white";
      case "info": return "bg-gray-500 text-white";
      default: return "bg-gray-500 text-white";
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-3xl font-bold tracking-tight">Logging & Audit Trails</h2>
          <p className="text-muted-foreground">
            Comprehensive recording of security events and system actions
          </p>
        </div>
        <div className="flex items-center space-x-2">
          <Button 
            variant="outline"
            onClick={() => exportLogs("csv")}
            disabled={isExporting}
          >
            <Download className={`mr-2 h-4 w-4 ${isExporting ? "animate-spin" : ""}`} />
            Export CSV
          </Button>
          <Button 
            variant="outline"
            onClick={() => exportLogs("json")}
            disabled={isExporting}
          >
            <Download className={`mr-2 h-4 w-4 ${isExporting ? "animate-spin" : ""}`} />
            Export JSON
          </Button>
        </div>
      </div>

      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-5">
        <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium">Total Logs</CardTitle>
            <Database className="h-4 w-4 text-sentinel-accent" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{logStats.total}</div>
            <p className="text-xs text-muted-foreground">
              In the last 24 hours
            </p>
          </CardContent>
        </Card>
        
        <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium">Critical Events</CardTitle>
            <Badge className="bg-red-500 text-white">{logStats.critical}</Badge>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-red-500">{((logStats.critical / logStats.total) * 100).toFixed(1)}%</div>
            <Progress value={(logStats.critical / logStats.total) * 100} className="h-2" />
          </CardContent>
        </Card>
        
        <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium">High Severity</CardTitle>
            <Badge className="bg-orange-500 text-white">{logStats.high}</Badge>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-orange-500">{((logStats.high / logStats.total) * 100).toFixed(1)}%</div>
            <Progress value={(logStats.high / logStats.total) * 100} className="h-2" />
          </CardContent>
        </Card>
        
        <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium">Medium Severity</CardTitle>
            <Badge className="bg-yellow-500 text-black">{logStats.medium}</Badge>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-yellow-500">{((logStats.medium / logStats.total) * 100).toFixed(1)}%</div>
            <Progress value={(logStats.medium / logStats.total) * 100} className="h-2" />
          </CardContent>
        </Card>
        
        <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium">Low & Info</CardTitle>
            <Badge className="bg-blue-500 text-white">{logStats.low + logStats.info}</Badge>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-blue-500">{(((logStats.low + logStats.info) / logStats.total) * 100).toFixed(1)}%</div>
            <Progress value={((logStats.low + logStats.info) / logStats.total) * 100} className="h-2" />
          </CardContent>
        </Card>
      </div>

      <div className="grid gap-4 md:grid-cols-3">
        <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm md:col-span-2">
          <CardHeader>
            <CardTitle>Log Activity</CardTitle>
            <CardDescription>
              Event frequency over time by severity
            </CardDescription>
          </CardHeader>
          <CardContent className="h-[300px]">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={activityData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#2D3748" />
                <XAxis 
                  dataKey="time" 
                  stroke="#A0AEC0"
                  tick={{ fill: '#A0AEC0' }}
                />
                <YAxis 
                  stroke="#A0AEC0" 
                  tick={{ fill: '#A0AEC0' }}
                />
                <Tooltip 
                  contentStyle={{ 
                    backgroundColor: 'rgba(23, 42, 69, 0.9)', 
                    borderColor: '#64FFDA',
                    borderRadius: '6px', 
                    color: '#fff'
                  }}
                />
                <Legend />
                <Line 
                  type="monotone" 
                  dataKey="critical" 
                  stroke="#f56565" 
                  strokeWidth={2}
                  dot={false}
                  name="Critical"
                />
                <Line 
                  type="monotone" 
                  dataKey="high" 
                  stroke="#ed8936" 
                  strokeWidth={2}
                  dot={false}
                  name="High"
                />
                <Line 
                  type="monotone" 
                  dataKey="medium" 
                  stroke="#ecc94b" 
                  strokeWidth={2}
                  dot={false}
                  name="Medium"
                />
                <Line 
                  type="monotone" 
                  dataKey="low" 
                  stroke="#4299e1" 
                  strokeWidth={2}
                  dot={false}
                  name="Low"
                />
                <Line 
                  type="monotone" 
                  dataKey="info" 
                  stroke="#a0aec0" 
                  strokeWidth={2}
                  dot={false}
                  name="Info"
                />
              </LineChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>
        
        <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm">
          <CardHeader>
            <CardTitle>Log Storage</CardTitle>
            <CardDescription>
              Storage utilization and retention policy
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-6">
            <div className="space-y-2">
              <div className="flex items-center justify-between text-sm">
                <span>Storage Used</span>
                <span className="font-bold">{storageUsed}%</span>
              </div>
              <Progress value={storageUsed} className="h-2" />
              <p className="text-xs text-muted-foreground">
                {Math.floor(storageUsed * 0.1 * 10) / 10} GB of 10 GB allocated
              </p>
            </div>
            
            <div className="space-y-2">
              <div className="flex items-center justify-between text-sm">
                <span>Retention Period</span>
                <span className="font-bold">{logRetention} days</span>
              </div>
              <div className="flex items-center space-x-2">
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setLogRetention(Math.max(7, logRetention - 7))}
                >
                  -7
                </Button>
                <Progress value={(logRetention / 90) * 100} className="h-2 flex-1" />
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setLogRetention(Math.min(90, logRetention + 7))}
                >
                  +7
                </Button>
              </div>
              <p className="text-xs text-muted-foreground">
                Logs are automatically purged after {logRetention} days
              </p>
            </div>
            
            <div className="grid grid-cols-2 gap-2">
              <div className="bg-sentinel-dark/50 p-3 rounded-md text-center">
                <div className="text-2xl font-bold">{logStats.total}</div>
                <p className="text-xs text-muted-foreground">Total Logs</p>
              </div>
              <div className="bg-sentinel-dark/50 p-3 rounded-md text-center">
                <div className="text-2xl font-bold">{Math.round(logStats.total / 24)}/hr</div>
                <p className="text-xs text-muted-foreground">Average Rate</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm">
        <CardHeader>
          <div className="flex justify-between items-center">
            <div>
              <CardTitle>Event Logs</CardTitle>
              <CardDescription>
                Security events and system actions
              </CardDescription>
            </div>
            <Button 
              variant="outline"
              size="sm"
              onClick={clearFilters}
              disabled={filters.type === "all" && filters.severity === "all" && !filters.source && !filters.search}
            >
              <X className="mr-2 h-4 w-4" />
              Clear Filters
            </Button>
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex flex-col md:flex-row gap-4">
            <div className="w-full md:w-1/4">
              <Label htmlFor="filter-type">Event Type</Label>
              <select
                id="filter-type"
                className="flex h-10 w-full rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2"
                value={filters.type}
                onChange={(e) => setFilters({...filters, type: e.target.value})}
              >
                <option value="all">All Types</option>
                <option value="Network">Network</option>
                <option value="Security">Security</option>
                <option value="System">System</option>
                <option value="Authentication">Authentication</option>
                <option value="Firewall">Firewall</option>
                <option value="Intrusion">Intrusion</option>
              </select>
            </div>
            
            <div className="w-full md:w-1/4">
              <Label htmlFor="filter-severity">Severity</Label>
              <select
                id="filter-severity"
                className="flex h-10 w-full rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2"
                value={filters.severity}
                onChange={(e) => setFilters({...filters, severity: e.target.value})}
              >
                <option value="all">All Severities</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
                <option value="info">Info</option>
              </select>
            </div>
            
            <div className="w-full md:w-1/4">
              <Label htmlFor="filter-source">Source IP</Label>
              <Input
                id="filter-source"
                placeholder="192.168.1.1"
                value={filters.source}
                onChange={(e) => setFilters({...filters, source: e.target.value})}
              />
            </div>
            
            <div className="w-full md:w-1/4">
              <Label htmlFor="filter-search">Search</Label>
              <div className="relative">
                <Search className="absolute left-2 top-3 h-4 w-4 text-muted-foreground" />
                <Input
                  id="filter-search"
                  placeholder="Search in logs..."
                  className="pl-8"
                  value={filters.search}
                  onChange={(e) => setFilters({...filters, search: e.target.value})}
                />
              </div>
            </div>
          </div>
          
          <div className="rounded-md border border-sentinel-light/10">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-[140px] cursor-pointer" onClick={() => handleSort("timestamp")}>
                    <div className="flex items-center">
                      Time
                      {sortField === "timestamp" && (
                        sortOrder === "asc" ? <ArrowUp className="ml-1 h-4 w-4" /> : <ArrowDown className="ml-1 h-4 w-4" />
                      )}
                    </div>
                  </TableHead>
                  <TableHead className="cursor-pointer" onClick={() => handleSort("type")}>
                    <div className="flex items-center">
                      Type
                      {sortField === "type" && (
                        sortOrder === "asc" ? <ArrowUp className="ml-1 h-4 w-4" /> : <ArrowDown className="ml-1 h-4 w-4" />
                      )}
                    </div>
                  </TableHead>
                  <TableHead className="hidden md:table-cell cursor-pointer" onClick={() => handleSort("source")}>
                    <div className="flex items-center">
                      Source
                      {sortField === "source" && (
                        sortOrder === "asc" ? <ArrowUp className="ml-1 h-4 w-4" /> : <ArrowDown className="ml-1 h-4 w-4" />
                      )}
                    </div>
                  </TableHead>
                  <TableHead className="cursor-pointer" onClick={() => handleSort("message")}>
                    <div className="flex items-center">
                      Message
                      {sortField === "message" && (
                        sortOrder === "asc" ? <ArrowUp className="ml-1 h-4 w-4" /> : <ArrowDown className="ml-1 h-4 w-4" />
                      )}
                    </div>
                  </TableHead>
                  <TableHead className="cursor-pointer" onClick={() => handleSort("severity")}>
                    <div className="flex items-center">
                      Severity
                      {sortField === "severity" && (
                        sortOrder === "asc" ? <ArrowUp className="ml-1 h-4 w-4" /> : <ArrowDown className="ml-1 h-4 w-4" />
                      )}
                    </div>
                  </TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filteredLogs.slice(0, 20).map((log) => (
                  <TableRow key={log.id} className="animate-fade-in">
                    <TableCell>
                      {formatTimestamp(log.timestamp)}
                    </TableCell>
                    <TableCell>{log.type}</TableCell>
                    <TableCell className="hidden md:table-cell">{log.source}</TableCell>
                    <TableCell className="max-w-[300px] truncate">{log.message}</TableCell>
                    <TableCell>
                      <Badge className={getSeverityColor(log.severity)}>
                        {log.severity}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-right">
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => setSelectedLog(log)}
                      >
                        Details
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
          
          <div className="flex items-center justify-between">
            <div className="text-sm text-muted-foreground">
              Showing {Math.min(20, filteredLogs.length)} of {filteredLogs.length} logs
              {filters.type !== "all" || filters.severity !== "all" || filters.source || filters.search ? " (filtered)" : ""}
            </div>
            <Button variant="outline" size="sm">
              Load More
            </Button>
          </div>
          
          {selectedLog && (
            <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm animate-scale-in">
              <CardHeader>
                <CardTitle className="flex items-center justify-between">
                  <span>Log Details</span>
                  <Badge className={getSeverityColor(selectedLog.severity)}>
                    {selectedLog.severity}
                  </Badge>
                </CardTitle>
                <CardDescription>
                  {new Date(selectedLog.timestamp).toLocaleString()}
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <Label className="text-sm text-muted-foreground">Type</Label>
                    <p>{selectedLog.type}</p>
                  </div>
                  <div>
                    <Label className="text-sm text-muted-foreground">Action</Label>
                    <p>{selectedLog.action}</p>
                  </div>
                  <div>
                    <Label className="text-sm text-muted-foreground">Source</Label>
                    <p>{selectedLog.source}</p>
                  </div>
                  <div>
                    <Label className="text-sm text-muted-foreground">Status</Label>
                    <p>{selectedLog.status}</p>
                  </div>
                </div>
                
                <div>
                  <Label className="text-sm text-muted-foreground">Message</Label>
                  <p>{selectedLog.message}</p>
                </div>
                
                <div>
                  <Label className="text-sm text-muted-foreground">Details</Label>
                  <p>{selectedLog.details}</p>
                </div>
                
                <div className="pt-2 flex justify-between">
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => setSelectedLog(null)}
                  >
                    Close
                  </Button>
                  
                  <div className="space-x-2">
                    <Button
                      variant="outline"
                      size="sm"
                    >
                      Copy
                    </Button>
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
    </div>
  );
};

export default Logging;
