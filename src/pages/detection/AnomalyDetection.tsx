import { useState, useEffect } from "react";
import { Brain, AlertTriangle, Activity, BarChart2, RefreshCw, Settings2, Zap } from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Progress } from "@/components/ui/progress";
import { Badge } from "@/components/ui/badge";
import { toast } from "sonner";
import { LineChart, Line, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts';

// Mock training data
const mockTrainingData = [
  { name: "Day 1", value: 1200 },
  { name: "Day 2", value: 1300 },
  { name: "Day 3", value: 1400 },
  { name: "Day 4", value: 1100 },
  { name: "Day 5", value: 1500 },
  { name: "Day 6", value: 1600 },
  { name: "Day 7", value: 1700 }
];

// Mock anomaly events
const initialAnomalies = [
  {
    id: 1,
    timestamp: new Date(Date.now() - 15 * 60000).toISOString(),
    type: "Traffic Spike",
    source: "192.168.1.45",
    destination: "Multiple",
    score: 0.92,
    details: "Unusual traffic volume from internal host",
    status: "investigating"
  },
  {
    id: 2,
    timestamp: new Date(Date.now() - 45 * 60000).toISOString(),
    type: "Port Scanning",
    source: "203.0.113.42",
    destination: "10.0.0.1-255",
    score: 0.88,
    details: "Sequential port scanning activity detected",
    status: "mitigated"
  },
  {
    id: 3,
    timestamp: new Date(Date.now() - 120 * 60000).toISOString(),
    type: "Data Exfiltration",
    source: "10.0.0.35",
    destination: "198.51.100.74",
    score: 0.95,
    details: "Unusual data transfer pattern to external host",
    status: "mitigated"
  },
  {
    id: 4,
    timestamp: new Date(Date.now() - 180 * 60000).toISOString(),
    type: "Beaconing",
    source: "10.0.0.22",
    destination: "203.0.113.15",
    score: 0.76,
    details: "Regular communication pattern indicative of C2 traffic",
    status: "investigating"
  }
];

// Generate realistic traffic data with anomalies
const generateRealisticTrafficData = () => {
  const now = new Date();
  const data = [];
  
  for (let i = 23; i >= 0; i--) {
    const time = new Date(now.getTime() - i * 30 * 60000);
    
    // Base traffic following a diurnal pattern (higher during day, lower at night)
    const hour = time.getHours();
    let baseTraffic = 100 + Math.sin((hour / 24) * Math.PI * 2) * 50;
    baseTraffic = Math.max(50, baseTraffic);
    
    // Add some random noise
    const normalTraffic = baseTraffic + (Math.random() * 20 - 10);
    
    // Add anomalies occasionally
    const hasAnomaly = Math.random() > 0.85;
    const anomalyValue = hasAnomaly ? normalTraffic * (1.5 + Math.random()) : 0;
    
    data.push({
      time: time.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      normal: normalTraffic,
      anomaly: anomalyValue,
      total: normalTraffic + anomalyValue
    });
  }
  
  return data;
};

const AnomalyDetection = () => {
  const [anomalies, setAnomalies] = useState(initialAnomalies);
  const [modelStatus, setModelStatus] = useState("active");
  const [trainingProgress, setTrainingProgress] = useState(0);
  const [isTraining, setIsTraining] = useState(false);
  const [filterStatus, setFilterStatus] = useState("all");
  const [trafficData, setTrafficData] = useState(generateRealisticTrafficData());
  const [sensitivityLevel, setSensitivityLevel] = useState(75);
  const [baselineData, setBaselineData] = useState(mockTrainingData);

  // Simulate real-time anomaly detection
  useEffect(() => {
    // Update traffic data every minute
    const trafficInterval = setInterval(() => {
      if (modelStatus === "active") {
        // Add new data point
        const now = new Date();
        const newData = [...trafficData.slice(1)];
        
        // Base traffic following a diurnal pattern
        const hour = now.getHours();
        let baseTraffic = 100 + Math.sin((hour / 24) * Math.PI * 2) * 50;
        baseTraffic = Math.max(50, baseTraffic);
        
        // Add some random noise
        const normalTraffic = baseTraffic + (Math.random() * 20 - 10);
        
        // Add anomalies occasionally based on sensitivity
        const anomalyThreshold = 1 - (sensitivityLevel / 100);
        const hasAnomaly = Math.random() > (anomalyThreshold * 0.9 + 0.05);
        const anomalyValue = hasAnomaly ? normalTraffic * (1.5 + Math.random()) : 0;
        
        newData.push({
          time: now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
          normal: normalTraffic,
          anomaly: anomalyValue,
          total: normalTraffic + anomalyValue
        });
        
        setTrafficData(newData);
        
        // If anomaly detected, add to list
        if (hasAnomaly && anomalyValue > normalTraffic) {
          const anomalyTypes = ["Traffic Spike", "Port Scanning", "Data Exfiltration", "Beaconing", "Protocol Violation", "DGA Detection"];
          const randomType = anomalyTypes[Math.floor(Math.random() * anomalyTypes.length)];
          
          const newAnomaly = {
            id: Math.floor(Math.random() * 10000),
            timestamp: new Date().toISOString(),
            type: randomType,
            source: `192.168.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
            destination: `203.0.113.${Math.floor(Math.random() * 255)}`,
            score: 0.7 + Math.random() * 0.3,
            details: `Unusual ${randomType.toLowerCase()} pattern detected`,
            status: "investigating"
          };
          
          setAnomalies(prevAnomalies => [newAnomaly, ...prevAnomalies]);
          
          // Show toast notification for new anomaly
          toast.warning(`Anomaly Detected: ${randomType}`, {
            description: `Score: ${newAnomaly.score.toFixed(2)} - ${newAnomaly.details}`,
            action: {
              label: "View",
              onClick: () => setFilterStatus("investigating")
            }
          });
        }
      }
    }, 60000);
    
    // Update anomaly statuses occasionally
    const statusInterval = setInterval(() => {
      setAnomalies(prevAnomalies => 
        prevAnomalies.map(anomaly => {
          if (anomaly.status === "investigating" && Math.random() > 0.7) {
            return { ...anomaly, status: "mitigated" };
          }
          return anomaly;
        })
      );
    }, 120000);

    return () => {
      clearInterval(trafficInterval);
      clearInterval(statusInterval);
    };
  }, [trafficData, modelStatus, sensitivityLevel]);

  const trainModel = () => {
    setIsTraining(true);
    setTrainingProgress(0);
    
    toast.info("Model training started", {
      description: "Establishing new baseline from recent traffic patterns"
    });
    
    // Simulate training progress
    const interval = setInterval(() => {
      setTrainingProgress(prev => {
        if (prev >= 100) {
          clearInterval(interval);
          setIsTraining(false);
          
          // Update baseline data when training completes
          const newBaseline = [...baselineData];
          newBaseline.shift();
          newBaseline.push({ 
            name: `Day ${parseInt(baselineData[baselineData.length - 1].name.split(' ')[1]) + 1}`,
            value: 1000 + Math.floor(Math.random() * 800)
          });
          setBaselineData(newBaseline);
          
          toast.success("Model training complete", {
            description: "New baseline established successfully"
          });
          
          return 100;
        }
        return prev + 5;
      });
    }, 400);
  };

  const toggleModelStatus = () => {
    const newStatus = modelStatus === "active" ? "paused" : "active";
    setModelStatus(newStatus);
    toast.info(`Anomaly detection ${newStatus}`);
  };

  const changeAnomalyStatus = (id: number, newStatus: string) => {
    setAnomalies(
      anomalies.map(anomaly => 
        anomaly.id === id ? { ...anomaly, status: newStatus } : anomaly
      )
    );
    
    const anomaly = anomalies.find(a => a.id === id);
    if (anomaly) {
      toast.success(`Anomaly status updated: ${newStatus}`);
    }
  };

  const filteredAnomalies = filterStatus === "all" 
    ? anomalies 
    : anomalies.filter(anomaly => anomaly.status === filterStatus);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-3xl font-bold tracking-tight">Anomaly-Based Detection</h2>
          <p className="text-muted-foreground">
            Machine learning-powered unusual behavior detection
          </p>
        </div>
        <div className="flex items-center space-x-2">
          <Button 
            variant="outline"
            disabled={isTraining}
            onClick={trainModel}
          >
            <RefreshCw className={`mr-2 h-4 w-4 ${isTraining ? "animate-spin" : ""}`} />
            {isTraining ? "Training..." : "Train Model"}
          </Button>
          <Button 
            variant={modelStatus === "active" ? "destructive" : "default"}
            onClick={toggleModelStatus}
          >
            {modelStatus === "active" ? "Pause Detection" : "Activate Detection"}
          </Button>
        </div>
      </div>

      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium">ML Model Status</CardTitle>
            <Brain className={`h-4 w-4 ${modelStatus === "active" ? "text-sentinel-accent" : "text-gray-400"}`} />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold capitalize">{modelStatus}</div>
            <p className="text-xs text-muted-foreground">
              {modelStatus === "active" ? "Analyzing traffic patterns" : "Detection paused"}
            </p>
          </CardContent>
        </Card>
        
        <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium">Sensitivity Level</CardTitle>
            <Settings2 className="h-4 w-4 text-sentinel-info" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{sensitivityLevel}%</div>
            <input
              type="range"
              min="0"
              max="100"
              value={sensitivityLevel}
              onChange={(e) => setSensitivityLevel(parseInt(e.target.value))}
              className="w-full h-2 bg-sentinel-dark rounded-lg appearance-none cursor-pointer mt-2"
            />
          </CardContent>
        </Card>
        
        <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium">Detected Anomalies</CardTitle>
            <AlertTriangle className="h-4 w-4 text-sentinel-warning" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{anomalies.length}</div>
            <p className="text-xs text-muted-foreground">
              {anomalies.filter(a => a.status === "investigating").length} active investigations
            </p>
          </CardContent>
        </Card>
        
        <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium">Model Training</CardTitle>
            <Activity className="h-4 w-4 text-sentinel-success" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {isTraining ? `${trainingProgress}%` : "Ready"}
            </div>
            {isTraining && (
              <Progress value={trainingProgress} className="h-2 mt-2" />
            )}
          </CardContent>
        </Card>
      </div>

      <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm">
        <CardHeader>
          <CardTitle>Traffic Patterns</CardTitle>
          <CardDescription>
            Real-time network traffic with anomaly overlay
          </CardDescription>
        </CardHeader>
        <CardContent className="h-[300px]">
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={trafficData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#2D3748" />
              <XAxis 
                dataKey="time" 
                stroke="#A0AEC0"
                tick={{ fill: '#A0AEC0' }}
              />
              <YAxis 
                stroke="#A0AEC0" 
                tick={{ fill: '#A0AEC0' }}
                label={{ value: 'Traffic Volume (Mbps)', angle: -90, position: 'insideLeft', fill: '#A0AEC0' }}
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
                dataKey="normal" 
                stroke="#64FFDA" 
                strokeWidth={2}
                dot={false}
                name="Normal Traffic"
              />
              <Line 
                type="monotone" 
                dataKey="anomaly" 
                stroke="#FF6B6B" 
                strokeWidth={2}
                dot={{ fill: '#FF6B6B', r: 4 }}
                activeDot={{ r: 6, fill: '#FF6B6B' }}
                name="Anomalous Traffic"
              />
            </LineChart>
          </ResponsiveContainer>
        </CardContent>
      </Card>

      <div className="grid gap-4 md:grid-cols-5">
        <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm col-span-3">
          <CardHeader>
            <div className="flex justify-between items-center">
              <CardTitle>Detected Anomalies</CardTitle>
              <div className="flex space-x-2">
                <Button 
                  variant={filterStatus === "all" ? "default" : "outline"} 
                  size="sm"
                  onClick={() => setFilterStatus("all")}
                >
                  All
                </Button>
                <Button 
                  variant={filterStatus === "investigating" ? "default" : "outline"} 
                  size="sm"
                  className="bg-sentinel-warning text-black"
                  onClick={() => setFilterStatus("investigating")}
                >
                  Investigating
                </Button>
                <Button 
                  variant={filterStatus === "mitigated" ? "default" : "outline"} 
                  size="sm"
                  className="bg-sentinel-success text-black"
                  onClick={() => setFilterStatus("mitigated")}
                >
                  Mitigated
                </Button>
              </div>
            </div>
          </CardHeader>
          <CardContent>
            <div className="rounded-md border border-sentinel-light/10">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Time</TableHead>
                    <TableHead>Type</TableHead>
                    <TableHead className="hidden md:table-cell">Source</TableHead>
                    <TableHead className="hidden md:table-cell">Score</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead className="text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filteredAnomalies.map((anomaly) => {
                    const anomalyTime = new Date(anomaly.timestamp);
                    
                    return (
                      <TableRow key={anomaly.id} className="animate-fade-in">
                        <TableCell>
                          {anomalyTime.toLocaleTimeString()}
                        </TableCell>
                        <TableCell className="font-medium">{anomaly.type}</TableCell>
                        <TableCell className="hidden md:table-cell">{anomaly.source}</TableCell>
                        <TableCell className="hidden md:table-cell">
                          <div className="flex items-center">
                            <span className="mr-2">{anomaly.score.toFixed(2)}</span>
                            <Progress 
                              value={anomaly.score * 100} 
                              className="h-2 w-16"
                              style={{
                                background: "rgba(255, 107, 107, 0.2)",
                                "--progress-background": "rgba(255, 107, 107, 1)"
                              } as React.CSSProperties}
                            />
                          </div>
                        </TableCell>
                        <TableCell>
                          <Badge 
                            className={
                              anomaly.status === "investigating" 
                                ? "bg-sentinel-warning text-black" 
                                : "bg-sentinel-success text-black"
                            }
                          >
                            {anomaly.status}
                          </Badge>
                        </TableCell>
                        <TableCell className="text-right">
                          {anomaly.status === "investigating" ? (
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => changeAnomalyStatus(anomaly.id, "mitigated")}
                            >
                              Mitigate
                            </Button>
                          ) : (
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => changeAnomalyStatus(anomaly.id, "investigating")}
                            >
                              Reopen
                            </Button>
                          )}
                        </TableCell>
                      </TableRow>
                    );
                  })}
                </TableBody>
              </Table>
            </div>
          </CardContent>
        </Card>
        
        <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm col-span-2">
          <CardHeader>
            <CardTitle>Model Baseline</CardTitle>
            <CardDescription>
              Historical data used for anomaly detection
            </CardDescription>
          </CardHeader>
          <CardContent className="h-[280px]">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={baselineData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#2D3748" />
                <XAxis 
                  dataKey="name" 
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
                <Bar 
                  dataKey="value" 
                  fill="#4FD1C5" 
                  name="Baseline Traffic Volume"
                />
              </BarChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>
      </div>
    </div>
  );
};

export default AnomalyDetection;
