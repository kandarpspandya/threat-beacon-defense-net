import { useState, useEffect } from "react";
import { Network, AlertTriangle, Activity, Server, Database, Layers, Globe } from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { toast } from "sonner";
import { PieChart, Pie, Cell, Legend, ResponsiveContainer, Tooltip } from 'recharts';

// Mock protocol data
const protocolData = [
  { name: "HTTP/HTTPS", value: 45, color: "#64FFDA" },
  { name: "DNS", value: 25, color: "#FFC107" },
  { name: "SMB/CIFS", value: 12, color: "#FF6B6B" },
  { name: "SSH", value: 8, color: "#2196F3" },
  { name: "FTP", value: 5, color: "#9c27b0" },
  { name: "Other", value: 5, color: "#607D8B" }
];

// Mock protocol sessions
const initialSessions = [
  {
    id: 1,
    protocol: "HTTP",
    state: "active",
    client: "192.168.1.45",
    server: "93.184.216.34",
    port: 80,
    duration: "00:15:23",
    bytes: 1453789,
    status: "normal"
  },
  {
    id: 2,
    protocol: "DNS",
    state: "active",
    client: "192.168.1.45",
    server: "8.8.8.8",
    port: 53,
    duration: "00:00:05",
    bytes: 1245,
    status: "normal"
  },
  {
    id: 3,
    protocol: "SSH",
    state: "active",
    client: "203.0.113.42",
    server: "192.168.1.10",
    port: 22,
    duration: "01:45:36",
    bytes: 8567432,
    status: "suspicious"
  },
  {
    id: 4,
    protocol: "FTP",
    state: "closing",
    client: "192.168.1.22",
    server: "192.168.1.50",
    port: 21,
    duration: "00:10:12",
    bytes: 52341879,
    status: "violation"
  },
  {
    id: 5,
    protocol: "HTTPS",
    state: "active",
    client: "192.168.1.45",
    server: "172.217.167.78",
    port: 443,
    duration: "00:03:45",
    bytes: 345621,
    status: "normal"
  }
];

// Mock protocol violations
const initialViolations = [
  {
    id: 1,
    timestamp: new Date(Date.now() - 15 * 60000).toISOString(),
    protocol: "HTTP",
    description: "Invalid HTTP header sequence",
    client: "192.168.1.67",
    server: "203.0.113.25",
    severity: "medium",
    status: "detected"
  },
  {
    id: 2,
    timestamp: new Date(Date.now() - 45 * 60000).toISOString(),
    protocol: "DNS",
    description: "Oversized DNS packet",
    client: "192.168.1.45",
    server: "8.8.8.8",
    severity: "low",
    status: "mitigated"
  },
  {
    id: 3,
    timestamp: new Date(Date.now() - 120 * 60000).toISOString(),
    protocol: "FTP",
    description: "Command injection attempt",
    client: "203.0.113.42",
    server: "192.168.1.50",
    severity: "high",
    status: "detected"
  },
  {
    id: 4,
    timestamp: new Date(Date.now() - 180 * 60000).toISOString(),
    protocol: "SSH",
    description: "Protocol version downgrade attempt",
    client: "203.0.113.15",
    server: "192.168.1.10",
    severity: "high",
    status: "detected"
  }
];

const ProtocolAnalysis = () => {
  const [sessions, setSessions] = useState(initialSessions);
  const [violations, setViolations] = useState(initialViolations);
  const [engineStatus, setEngineStatus] = useState("running");
  const [sessionFilter, setSessionFilter] = useState("all");
  const [violationFilter, setViolationFilter] = useState("all");
  const [inspectedSession, setInspectedSession] = useState<any>(null);
  const [sessionStates, setSessionStates] = useState<{[key: string]: number}>({
    active: 32,
    establishing: 5,
    closing: 3,
    closed: 12
  });

  // Simulate real-time protocol analysis
  useEffect(() => {
    if (engineStatus !== "running") return;
    
    // Update session states and add/update sessions
    const sessionInterval = setInterval(() => {
      // Randomly update session states
      setSessionStates(prev => {
        const newStates = {...prev};
        
        // Randomly adjust counts but keep total roughly the same
        const changeFactor = Math.floor(Math.random() * 3) - 1; // -1, 0, or 1
        
        newStates.active = Math.max(30, prev.active + changeFactor);
        newStates.establishing = Math.max(1, prev.establishing + (Math.random() > 0.7 ? 1 : -1));
        newStates.closing = Math.max(1, prev.closing + (Math.random() > 0.7 ? 1 : -1));
        newStates.closed = Math.max(10, prev.closed + (Math.random() > 0.7 ? 1 : -1));
        
        return newStates;
      });
      
      // Update existing sessions (duration, bytes, etc.)
      setSessions(prev => 
        prev.map(session => {
          // Parse duration and add some seconds
          const [hours, minutes, seconds] = session.duration.split(':').map(Number);
          const durationInSeconds = hours * 3600 + minutes * 60 + seconds + Math.floor(Math.random() * 30);
          const newHours = Math.floor(durationInSeconds / 3600);
          const newMinutes = Math.floor((durationInSeconds % 3600) / 60);
          const newSeconds = durationInSeconds % 60;
          
          // Format with leading zeros
          const formattedDuration = `${newHours.toString().padStart(2, '0')}:${newMinutes.toString().padStart(2, '0')}:${newSeconds.toString().padStart(2, '0')}`;
          
          // Randomly increment bytes
          const newBytes = session.bytes + Math.floor(Math.random() * 50000);
          
          // Occasionally change state
          let newState = session.state;
          if (session.state === "active" && Math.random() > 0.9) {
            newState = "closing";
          } else if (session.state === "closing" && Math.random() > 0.7) {
            newState = "closed";
          }
          
          // If the session is closed, don't update it
          if (session.state === "closed") {
            return session;
          }
          
          return {
            ...session,
            duration: formattedDuration,
            bytes: newBytes,
            state: newState
          };
        })
      );
      
      // Occasionally add a new session
      if (Math.random() > 0.7) {
        const protocols = ["HTTP", "HTTPS", "DNS", "SSH", "FTP", "SMB", "RDP"];
        const randomProtocol = protocols[Math.floor(Math.random() * protocols.length)];
        
        const newSession = {
          id: Math.floor(Math.random() * 10000),
          protocol: randomProtocol,
          state: "establishing",
          client: `192.168.1.${Math.floor(Math.random() * 255)}`,
          server: `203.0.113.${Math.floor(Math.random() * 255)}`,
          port: getDefaultPortForProtocol(randomProtocol),
          duration: "00:00:00",
          bytes: 0,
          status: "normal"
        };
        
        setSessions(prev => [newSession, ...prev.filter(s => s.state !== "closed").slice(0, 8)]);
      }
    }, 10000);
    
    // Occasionally generate protocol violations
    const violationInterval = setInterval(() => {
      if (Math.random() > 0.7) {
        const protocols = ["HTTP", "HTTPS", "DNS", "SSH", "FTP", "SMB", "RDP"];
        const randomProtocol = protocols[Math.floor(Math.random() * protocols.length)];
        
        const violationTypes = {
          "HTTP": ["Header injection", "Invalid request format", "Oversized header", "Method abuse"],
          "HTTPS": ["TLS version downgrade", "Weak cipher usage", "Certificate anomaly"],
          "DNS": ["Oversized packet", "Cache poisoning attempt", "Zone transfer attempt"],
          "SSH": ["Protocol version downgrade", "Authentication bypass attempt", "Brute force attempt"],
          "FTP": ["Command injection", "Directory traversal", "Authentication bypass"],
          "SMB": ["NULL session attempt", "Remote code execution", "Authentication bypass"],
          "RDP": ["BlueKeep exploitation", "Session hijacking", "Authentication bypass"]
        };
        
        const violationDescription = violationTypes[randomProtocol as keyof typeof violationTypes][
          Math.floor(Math.random() * violationTypes[randomProtocol as keyof typeof violationTypes].length)
        ];
        
        const severities = ["low", "medium", "high"];
        const randomSeverity = severities[Math.floor(Math.random() * severities.length)];
        
        const newViolation = {
          id: Math.floor(Math.random() * 10000),
          timestamp: new Date().toISOString(),
          protocol: randomProtocol,
          description: violationDescription,
          client: `192.168.1.${Math.floor(Math.random() * 255)}`,
          server: `203.0.113.${Math.floor(Math.random() * 255)}`,
          severity: randomSeverity,
          status: "detected"
        };
        
        setViolations(prev => [newViolation, ...prev.slice(0, 19)]);
        
        // Show toast notification for new violation
        toast.warning(`Protocol Violation: ${randomProtocol}`, {
          description: violationDescription,
          action: {
            label: "View",
            onClick: () => setViolationFilter("detected")
          }
        });
      }
    }, 60000);

    return () => {
      clearInterval(sessionInterval);
      clearInterval(violationInterval);
    };
  }, [engineStatus]);

  const getDefaultPortForProtocol = (protocol: string) => {
    const portMap: {[key: string]: number} = {
      "HTTP": 80,
      "HTTPS": 443,
      "DNS": 53,
      "SSH": 22,
      "FTP": 21,
      "SMB": 445,
      "RDP": 3389
    };
    return portMap[protocol] || 0;
  };

  const toggleEngineStatus = () => {
    const newStatus = engineStatus === "running" ? "stopped" : "running";
    setEngineStatus(newStatus);
    toast.info(`Protocol analysis engine ${newStatus}`);
  };

  const mitigateViolation = (id: number) => {
    setViolations(
      violations.map(violation => 
        violation.id === id ? { ...violation, status: "mitigated" } : violation
      )
    );
    
    const violation = violations.find(v => v.id === id);
    if (violation) {
      toast.success(`Protocol violation mitigated`, {
        description: violation.description
      });
    }
  };

  const inspectSession = (session: any) => {
    setInspectedSession(session);
  };

  const filteredSessions = sessionFilter === "all" 
    ? sessions 
    : sessions.filter(session => session.status === sessionFilter);

  const filteredViolations = violationFilter === "all" 
    ? violations 
    : violations.filter(violation => violation.status === violationFilter);

  const formatBytes = (bytes: number) => {
    if (bytes < 1024) return bytes + ' B';
    else if (bytes < 1048576) return (bytes / 1024).toFixed(2) + ' KB';
    else if (bytes < 1073741824) return (bytes / 1048576).toFixed(2) + ' MB';
    else return (bytes / 1073741824).toFixed(2) + ' GB';
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-3xl font-bold tracking-tight">Stateful Protocol Analysis</h2>
          <p className="text-muted-foreground">
            Deep inspection of network protocols and state transitions
          </p>
        </div>
        <div className="flex items-center space-x-2">
          <Button 
            variant={engineStatus === "running" ? "destructive" : "default"}
            onClick={toggleEngineStatus}
          >
            {engineStatus === "running" ? "Stop Engine" : "Start Engine"}
          </Button>
        </div>
      </div>

      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium">Analysis Engine</CardTitle>
            <Network className={`h-4 w-4 ${engineStatus === "running" ? "text-sentinel-success" : "text-destructive"}`} />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold capitalize">{engineStatus}</div>
            <p className="text-xs text-muted-foreground">
              {engineStatus === "running" ? "Monitoring protocol states" : "Engine stopped"}
            </p>
          </CardContent>
        </Card>
        
        <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium">Active Sessions</CardTitle>
            <Activity className="h-4 w-4 text-sentinel-info" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{sessionStates.active + sessionStates.establishing}</div>
            <p className="text-xs text-muted-foreground">
              {sessionStates.establishing} establishing, {sessionStates.active} active
            </p>
          </CardContent>
        </Card>
        
        <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium">Protocol Violations</CardTitle>
            <AlertTriangle className="h-4 w-4 text-sentinel-warning" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{violations.filter(v => v.status === "detected").length}</div>
            <p className="text-xs text-muted-foreground">
              {violations.filter(v => v.status === "mitigated").length} mitigated
            </p>
          </CardContent>
        </Card>
        
        <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium">Inspected Protocols</CardTitle>
            <Layers className="h-4 w-4 text-sentinel-accent" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">7</div>
            <p className="text-xs text-muted-foreground">
              HTTP, HTTPS, DNS, SSH, FTP, SMB, RDP
            </p>
          </CardContent>
        </Card>
      </div>

      <div className="grid gap-4 md:grid-cols-3">
        <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm col-span-2">
          <CardHeader>
            <CardTitle>Protocol Distribution</CardTitle>
            <CardDescription>
              Current traffic by protocol
            </CardDescription>
          </CardHeader>
          <CardContent className="h-[300px]">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={protocolData}
                  cx="50%"
                  cy="50%"
                  innerRadius={60}
                  outerRadius={100}
                  paddingAngle={2}
                  dataKey="value"
                  label={({ name, percent }) => `${name} ${(percent * 100).toFixed(1)}%`}
                  labelLine={false}
                >
                  {protocolData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip 
                  contentStyle={{ 
                    backgroundColor: 'rgba(23, 42, 69, 0.9)', 
                    borderColor: '#64FFDA',
                    borderRadius: '6px', 
                    color: '#fff'
                  }}
                  formatter={(value: number) => [`${value}%`, "Percentage"]}
                />
                <Legend 
                  layout="vertical" 
                  verticalAlign="middle" 
                  align="right"
                  wrapperStyle={{
                    paddingLeft: "10px",
                  }}
                />
              </PieChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>
        
        <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm">
          <CardHeader>
            <CardTitle>Session States</CardTitle>
            <CardDescription>
              Current protocol session states
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2">
              <div className="flex items-center justify-between text-sm">
                <div className="flex items-center">
                  <div className="h-3 w-3 rounded-full bg-green-500 mr-2"></div>
                  <span>Active</span>
                </div>
                <span className="font-bold">{sessionStates.active}</span>
              </div>
              <Progress value={(sessionStates.active / (sessionStates.active + sessionStates.establishing + sessionStates.closing + sessionStates.closed)) * 100} className="h-2 bg-gray-800">
                <div className="h-full bg-green-500 rounded-full"></div>
              </Progress>
            </div>
            
            <div className="space-y-2">
              <div className="flex items-center justify-between text-sm">
                <div className="flex items-center">
                  <div className="h-3 w-3 rounded-full bg-blue-500 mr-2"></div>
                  <span>Establishing</span>
                </div>
                <span className="font-bold">{sessionStates.establishing}</span>
              </div>
              <Progress value={(sessionStates.establishing / (sessionStates.active + sessionStates.establishing + sessionStates.closing + sessionStates.closed)) * 100} className="h-2 bg-gray-800">
                <div className="h-full bg-blue-500 rounded-full"></div>
              </Progress>
            </div>
            
            <div className="space-y-2">
              <div className="flex items-center justify-between text-sm">
                <div className="flex items-center">
                  <div className="h-3 w-3 rounded-full bg-yellow-500 mr-2"></div>
                  <span>Closing</span>
                </div>
                <span className="font-bold">{sessionStates.closing}</span>
              </div>
              <Progress value={(sessionStates.closing / (sessionStates.active + sessionStates.establishing + sessionStates.closing + sessionStates.closed)) * 100} className="h-2 bg-gray-800">
                <div className="h-full bg-yellow-500 rounded-full"></div>
              </Progress>
            </div>
            
            <div className="space-y-2">
              <div className="flex items-center justify-between text-sm">
                <div className="flex items-center">
                  <div className="h-3 w-3 rounded-full bg-gray-500 mr-2"></div>
                  <span>Closed</span>
                </div>
                <span className="font-bold">{sessionStates.closed}</span>
              </div>
              <Progress value={(sessionStates.closed / (sessionStates.active + sessionStates.establishing + sessionStates.closing + sessionStates.closed)) * 100} className="h-2 bg-gray-800">
                <div className="h-full bg-gray-500 rounded-full"></div>
              </Progress>
            </div>
          </CardContent>
        </Card>
      </div>

      <Tabs defaultValue="sessions" className="space-y-4">
        <TabsList className="grid grid-cols-2 md:w-[400px] bg-background/50">
          <TabsTrigger value="sessions">Active Sessions</TabsTrigger>
          <TabsTrigger value="violations">Protocol Violations</TabsTrigger>
        </TabsList>
        
        <TabsContent value="sessions" className="space-y-4">
          <div className="flex justify-between items-center">
            <h3 className="text-lg font-semibold">Protocol Sessions</h3>
            <div className="flex space-x-2">
              <Button 
                variant={sessionFilter === "all" ? "default" : "outline"} 
                size="sm"
                onClick={() => setSessionFilter("all")}
              >
                All
              </Button>
              <Button 
                variant={sessionFilter === "normal" ? "default" : "outline"} 
                size="sm"
                className="bg-green-500 text-black hover:bg-green-600"
                onClick={() => setSessionFilter("normal")}
              >
                Normal
              </Button>
              <Button 
                variant={sessionFilter === "suspicious" ? "default" : "outline"} 
                size="sm"
                className="bg-yellow-500 text-black hover:bg-yellow-600"
                onClick={() => setSessionFilter("suspicious")}
              >
                Suspicious
              </Button>
              <Button 
                variant={sessionFilter === "violation" ? "default" : "outline"} 
                size="sm"
                className="bg-red-500 text-white hover:bg-red-600"
                onClick={() => setSessionFilter("violation")}
              >
                Violation
              </Button>
            </div>
          </div>
          
          <div className="rounded-md border border-sentinel-light/10">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Protocol</TableHead>
                  <TableHead>Client</TableHead>
                  <TableHead>Server</TableHead>
                  <TableHead className="hidden md:table-cell">State</TableHead>
                  <TableHead className="hidden md:table-cell">Duration</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filteredSessions.map((session) => (
                  <TableRow key={session.id} className="animate-fade-in">
                    <TableCell className="font-medium">
                      {session.protocol}:{session.port}
                    </TableCell>
                    <TableCell>{session.client}</TableCell>
                    <TableCell>{session.server}</TableCell>
                    <TableCell className="hidden md:table-cell capitalize">{session.state}</TableCell>
                    <TableCell className="hidden md:table-cell">{session.duration}</TableCell>
                    <TableCell>
                      <Badge 
                        className={
                          session.status === "normal" 
                            ? "bg-green-500 text-black" 
                            : session.status === "suspicious"
                              ? "bg-yellow-500 text-black"
                              : "bg-red-500 text-white"
                        }
                      >
                        {session.status}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-right">
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => inspectSession(session)}
                      >
                        Inspect
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>

          {inspectedSession && (
            <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm animate-scale-in">
              <CardHeader>
                <CardTitle className="flex items-center justify-between">
                  <span>{inspectedSession.protocol} Session Details</span>
                  <Badge 
                    className={
                      inspectedSession.status === "normal" 
                        ? "bg-green-500 text-black" 
                        : inspectedSession.status === "suspicious"
                          ? "bg-yellow-500 text-black"
                          : "bg-red-500 text-white"
                    }
                  >
                    {inspectedSession.status}
                  </Badge>
                </CardTitle>
                <CardDescription>
                  Connection between {inspectedSession.client} and {inspectedSession.server}:{inspectedSession.port}
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <h4 className="text-sm font-semibold mb-1">State</h4>
                    <p className="capitalize">{inspectedSession.state}</p>
                  </div>
                  <div>
                    <h4 className="text-sm font-semibold mb-1">Duration</h4>
                    <p>{inspectedSession.duration}</p>
                  </div>
                  <div>
                    <h4 className="text-sm font-semibold mb-1">Bytes Transferred</h4>
                    <p>{formatBytes(inspectedSession.bytes)}</p>
                  </div>
                  <div>
                    <h4 className="text-sm font-semibold mb-1">Protocol</h4>
                    <p>{inspectedSession.protocol}:{inspectedSession.port}</p>
                  </div>
                </div>

                <div>
                  <h4 className="text-sm font-semibold mb-1">Session States History</h4>
                  <div className="flex items-center space-x-2 py-2">
                    <div className="h-8 w-8 rounded-full bg-blue-500 flex items-center justify-center text-xs">
                      init
                    </div>
                    <div className="h-1 w-8 bg-gray-500"></div>
                    <div className="h-8 w-8 rounded-full bg-blue-500 flex items-center justify-center text-xs">
                      est
                    </div>
                    <div className="h-1 w-8 bg-gray-500"></div>
                    <div className={`h-8 w-8 rounded-full ${inspectedSession.state === "active" ? "bg-green-500" : "bg-gray-500"} flex items-center justify-center text-xs`}>
                      active
                    </div>
                    <div className="h-1 w-8 bg-gray-500"></div>
                    <div className={`h-8 w-8 rounded-full ${inspectedSession.state === "closing" ? "bg-yellow-500" : "bg-gray-500"} flex items-center justify-center text-xs`}>
                      close
                    </div>
                    <div className="h-1 w-8 bg-gray-500"></div>
                    <div className={`h-8 w-8 rounded-full ${inspectedSession.state === "closed" ? "bg-red-500" : "bg-gray-500"} flex items-center justify-center text-xs`}>
                      end
                    </div>
                  </div>
                </div>

                <div className="flex justify-between">
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => setInspectedSession(null)}
                  >
                    Close
                  </Button>
                  {inspectedSession.state === "active" && (
                    <Button
                      variant="destructive"
                      size="sm"
                    >
                      Terminate Session
                    </Button>
                  )}
                </div>
              </CardContent>
            </Card>
          )}
        </TabsContent>
        
        <TabsContent value="violations" className="space-y-4">
          <div className="flex justify-between items-center">
            <h3 className="text-lg font-semibold">Protocol Violations</h3>
            <div className="flex space-x-2">
              <Button 
                variant={violationFilter === "all" ? "default" : "outline"} 
                size="sm"
                onClick={() => setViolationFilter("all")}
              >
                All
              </Button>
              <Button 
                variant={violationFilter === "detected" ? "default" : "outline"} 
                size="sm"
                className="bg-red-500 text-white hover:bg-red-600"
                onClick={() => setViolationFilter("detected")}
              >
                Detected
              </Button>
              <Button 
                variant={violationFilter === "mitigated" ? "default" : "outline"} 
                size="sm"
                className="bg-green-500 text-black hover:bg-green-600"
                onClick={() => setViolationFilter("mitigated")}
              >
                Mitigated
              </Button>
            </div>
          </div>
          
          <div className="rounded-md border border-sentinel-light/10">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Time</TableHead>
                  <TableHead>Protocol</TableHead>
                  <TableHead className="hidden md:table-cell">Description</TableHead>
                  <TableHead className="hidden md:table-cell">Client</TableHead>
                  <TableHead>Severity</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filteredViolations.map((violation) => {
                  const violationTime = new Date(violation.timestamp);
                  
                  return (
                    <TableRow key={violation.id} className="animate-fade-in">
                      <TableCell>
                        {violationTime.toLocaleTimeString()}
                      </TableCell>
                      <TableCell className="font-medium">{violation.protocol}</TableCell>
                      <TableCell className="hidden md:table-cell">{violation.description}</TableCell>
                      <TableCell className="hidden md:table-cell">{violation.client}</TableCell>
                      <TableCell>
                        <Badge 
                          className={
                            violation.severity === "low" 
                              ? "bg-blue-500 text-white" 
                              : violation.severity === "medium"
                                ? "bg-yellow-500 text-black"
                                : "bg-red-500 text-white"
                          }
                        >
                          {violation.severity}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-right">
                        {violation.status === "detected" ? (
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => mitigateViolation(violation.id)}
                          >
                            Mitigate
                          </Button>
                        ) : (
                          <Badge className="bg-green-500 text-black">
                            Mitigated
                          </
