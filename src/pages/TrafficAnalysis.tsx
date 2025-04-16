
import { useState } from "react";
import { LineChart, Line, BarChart, Bar, PieChart, Pie, Cell, AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from "recharts";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Button } from "@/components/ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Upload, Download, FileType, Activity, PieChart as PieChartIcon, BarChart2, Activity as ActivityIcon } from "lucide-react";
import { Progress } from "@/components/ui/progress";

// Mock data for the charts
const trafficByProtocol = [
  { name: "HTTP", value: 42, color: "#64FFDA" },
  { name: "HTTPS", value: 28, color: "#2196F3" },
  { name: "DNS", value: 15, color: "#FFC107" },
  { name: "SSH", value: 10, color: "#FF6B6B" },
  { name: "SMTP", value: 5, color: "#9c27b0" },
];

const trafficBySource = [
  { name: "Internal", value: 65, color: "#64FFDA" },
  { name: "External", value: 35, color: "#FF6B6B" },
];

const trafficOverTime = Array.from({ length: 24 }, (_, i) => ({
  hour: `${i}:00`,
  incoming: Math.floor(Math.random() * 100) + 50,
  outgoing: Math.floor(Math.random() * 80) + 20,
}));

const topDomains = [
  { name: "api.example.com", visits: 1254 },
  { name: "cdn.example.net", visits: 876 },
  { name: "storage.example.org", visits: 621 },
  { name: "mail.example.com", visits: 452 },
  { name: "dashboard.example.io", visits: 348 },
];

const TrafficAnalysis = () => {
  const [timeRange, setTimeRange] = useState("24h");
  const [isUploading, setIsUploading] = useState(false);
  const [uploadProgress, setUploadProgress] = useState(0);

  const handlePcapUpload = () => {
    setIsUploading(true);
    setUploadProgress(0);
    
    // Simulate upload progress
    const interval = setInterval(() => {
      setUploadProgress((prev) => {
        if (prev >= 100) {
          clearInterval(interval);
          setIsUploading(false);
          return 100;
        }
        return prev + 10;
      });
    }, 300);
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-3xl font-bold tracking-tight">Traffic Analysis</h2>
        <div className="flex items-center space-x-2">
          <Select value={timeRange} onValueChange={setTimeRange}>
            <SelectTrigger className="w-[120px]">
              <SelectValue placeholder="Select period" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="1h">Last Hour</SelectItem>
              <SelectItem value="24h">Last 24 Hours</SelectItem>
              <SelectItem value="7d">Last 7 Days</SelectItem>
              <SelectItem value="30d">Last 30 Days</SelectItem>
            </SelectContent>
          </Select>
          
          <Button variant="outline">
            <Download className="mr-2 h-4 w-4" />
            Export Data
          </Button>
        </div>
      </div>

      {/* PCAP File Upload Card */}
      <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm">
        <CardHeader>
          <CardTitle>Network Capture Analysis</CardTitle>
          <CardDescription>
            Upload PCAP files for detailed traffic inspection
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex flex-col items-center justify-center space-y-4 rounded-md border-2 border-dashed border-sentinel-light/20 p-8">
            <FileType className="h-12 w-12 text-sentinel-accent/70" />
            <div className="space-y-1 text-center">
              <p className="text-sm text-muted-foreground">
                Drag and drop PCAP files here, or click to browse
              </p>
              <p className="text-xs text-muted-foreground">
                Maximum file size: 100MB
              </p>
            </div>
            {isUploading ? (
              <div className="w-full max-w-xs space-y-2">
                <div className="flex justify-between text-xs text-muted-foreground">
                  <span>Uploading...</span>
                  <span>{uploadProgress}%</span>
                </div>
                <Progress value={uploadProgress} className="h-2" />
              </div>
            ) : (
              <Button onClick={handlePcapUpload}>
                <Upload className="mr-2 h-4 w-4" />
                Upload PCAP File
              </Button>
            )}
          </div>
        </CardContent>
      </Card>

      {/* Traffic Analysis Tabs */}
      <Tabs defaultValue="overview" className="space-y-4">
        <TabsList className="grid grid-cols-4 md:w-[400px] bg-background/50">
          <TabsTrigger value="overview">
            <Activity className="mr-2 h-4 w-4" />
            Overview
          </TabsTrigger>
          <TabsTrigger value="protocols">
            <PieChartIcon className="mr-2 h-4 w-4" />
            Protocols
          </TabsTrigger>
          <TabsTrigger value="sources">
            <BarChart2 className="mr-2 h-4 w-4" />
            Sources
          </TabsTrigger>
          <TabsTrigger value="trends">
            <ActivityIcon className="mr-2 h-4 w-4" />
            Trends
          </TabsTrigger>
        </TabsList>
        
        {/* Overview Tab */}
        <TabsContent value="overview" className="space-y-4">
          <div className="grid gap-4 md:grid-cols-2">
            {/* Traffic Over Time Chart */}
            <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm md:col-span-2">
              <CardHeader>
                <CardTitle>Traffic Volume Over Time</CardTitle>
                <CardDescription>
                  Incoming and outgoing network traffic
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="h-[300px]">
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart
                      data={trafficOverTime}
                      margin={{
                        top: 10,
                        right: 30,
                        left: 0,
                        bottom: 0,
                      }}
                    >
                      <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.1)" />
                      <XAxis 
                        dataKey="hour" 
                        stroke="rgba(255,255,255,0.5)"
                        tickLine={false}
                      />
                      <YAxis 
                        stroke="rgba(255,255,255,0.5)"
                        tickLine={false}
                        axisLine={false}
                      />
                      <Tooltip 
                        contentStyle={{ 
                          backgroundColor: "rgba(23, 42, 69, 0.9)", 
                          borderColor: "#64FFDA",
                          borderRadius: "6px",
                          color: "#fff"
                        }} 
                      />
                      <Legend />
                      <Area 
                        type="monotone" 
                        dataKey="incoming" 
                        stackId="1"
                        stroke="#2196F3" 
                        fill="#2196F3" 
                        fillOpacity={0.3}
                      />
                      <Area 
                        type="monotone" 
                        dataKey="outgoing" 
                        stackId="1"
                        stroke="#64FFDA" 
                        fill="#64FFDA" 
                        fillOpacity={0.3}
                      />
                    </AreaChart>
                  </ResponsiveContainer>
                </div>
              </CardContent>
            </Card>
            
            {/* Protocol Distribution Chart */}
            <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm">
              <CardHeader>
                <CardTitle>Protocol Distribution</CardTitle>
                <CardDescription>
                  Traffic breakdown by protocol
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="h-[250px]">
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie
                        data={trafficByProtocol}
                        cx="50%"
                        cy="50%"
                        innerRadius={60}
                        outerRadius={80}
                        fill="#8884d8"
                        paddingAngle={3}
                        dataKey="value"
                        label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                        labelLine={false}
                      >
                        {trafficByProtocol.map((entry, index) => (
                          <Cell key={`cell-${index}`} fill={entry.color} />
                        ))}
                      </Pie>
                      <Tooltip 
                        contentStyle={{ 
                          backgroundColor: "rgba(23, 42, 69, 0.9)", 
                          borderColor: "#64FFDA",
                          borderRadius: "6px",
                          color: "#fff"
                        }}
                        formatter={(value: number) => [`${value}%`, "Percentage"]}
                      />
                    </PieChart>
                  </ResponsiveContainer>
                </div>
              </CardContent>
            </Card>
            
            {/* Source Distribution Chart */}
            <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm">
              <CardHeader>
                <CardTitle>Traffic Source</CardTitle>
                <CardDescription>
                  Internal vs. external traffic
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="h-[250px]">
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie
                        data={trafficBySource}
                        cx="50%"
                        cy="50%"
                        outerRadius={80}
                        fill="#8884d8"
                        dataKey="value"
                        label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                      >
                        {trafficBySource.map((entry, index) => (
                          <Cell key={`cell-${index}`} fill={entry.color} />
                        ))}
                      </Pie>
                      <Tooltip 
                        contentStyle={{ 
                          backgroundColor: "rgba(23, 42, 69, 0.9)", 
                          borderColor: "#64FFDA",
                          borderRadius: "6px",
                          color: "#fff"
                        }}
                        formatter={(value: number) => [`${value}%`, "Percentage"]}
                      />
                    </PieChart>
                  </ResponsiveContainer>
                </div>
              </CardContent>
            </Card>
          </div>
          
          {/* Top Domains */}
          <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm">
            <CardHeader>
              <CardTitle>Top Domains</CardTitle>
              <CardDescription>
                Most frequently accessed domains
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="h-[250px]">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart
                    data={topDomains}
                    layout="vertical"
                    margin={{
                      top: 5,
                      right: 30,
                      left: 20,
                      bottom: 5,
                    }}
                  >
                    <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.1)" />
                    <XAxis type="number" stroke="rgba(255,255,255,0.5)" />
                    <YAxis 
                      type="category" 
                      dataKey="name" 
                      stroke="rgba(255,255,255,0.5)"
                      tickLine={false}
                      width={150}
                    />
                    <Tooltip 
                      contentStyle={{ 
                        backgroundColor: "rgba(23, 42, 69, 0.9)", 
                        borderColor: "#64FFDA",
                        borderRadius: "6px",
                        color: "#fff"
                      }}
                    />
                    <Bar dataKey="visits" fill="#64FFDA" radius={[0, 4, 4, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
        
        {/* Protocols Tab */}
        <TabsContent value="protocols">
          <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm">
            <CardHeader>
              <CardTitle>Protocol Analysis</CardTitle>
              <CardDescription>
                Detailed breakdown by network protocol
              </CardDescription>
            </CardHeader>
            <CardContent className="h-[500px]">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={trafficByProtocol}
                    cx="50%"
                    cy="50%"
                    innerRadius={100}
                    outerRadius={140}
                    fill="#8884d8"
                    paddingAngle={3}
                    dataKey="value"
                    label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                  >
                    {trafficByProtocol.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip 
                    contentStyle={{ 
                      backgroundColor: "rgba(23, 42, 69, 0.9)", 
                      borderColor: "#64FFDA",
                      borderRadius: "6px",
                      color: "#fff"
                    }}
                    formatter={(value: number) => [`${value}%`, "Percentage"]}
                  />
                  <Legend layout="vertical" verticalAlign="middle" align="right" />
                </PieChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>
        </TabsContent>
        
        {/* Sources Tab */}
        <TabsContent value="sources">
          <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm">
            <CardHeader>
              <CardTitle>Traffic Sources</CardTitle>
              <CardDescription>
                Analysis of traffic origins and destinations
              </CardDescription>
            </CardHeader>
            <CardContent className="h-[500px]">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart
                  data={[
                    { name: "Internal to Internal", value: 45 },
                    { name: "Internal to External", value: 25 },
                    { name: "External to Internal", value: 20 },
                    { name: "External to External", value: 10 },
                  ]}
                  layout="vertical"
                  margin={{ top: 20, right: 30, left: 20, bottom: 5 }}
                >
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.1)" />
                  <XAxis type="number" stroke="rgba(255,255,255,0.5)" />
                  <YAxis 
                    dataKey="name" 
                    type="category" 
                    stroke="rgba(255,255,255,0.5)"
                    tickLine={false}
                    width={180}
                  />
                  <Tooltip 
                    contentStyle={{ 
                      backgroundColor: "rgba(23, 42, 69, 0.9)", 
                      borderColor: "#64FFDA",
                      borderRadius: "6px",
                      color: "#fff"
                    }}
                  />
                  <Bar dataKey="value" fill="#64FFDA" radius={[0, 4, 4, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>
        </TabsContent>
        
        {/* Trends Tab */}
        <TabsContent value="trends">
          <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm">
            <CardHeader>
              <CardTitle>Traffic Trends</CardTitle>
              <CardDescription>
                Historical traffic patterns and anomalies
              </CardDescription>
            </CardHeader>
            <CardContent className="h-[500px]">
              <ResponsiveContainer width="100%" height="100%">
                <LineChart
                  data={Array.from({ length: 30 }, (_, i) => ({
                    day: i + 1,
                    traffic: Math.floor(Math.random() * 500) + 500 + (i % 7 === 0 ? 200 : 0),
                    baseline: 600,
                  }))}
                  margin={{ top: 20, right: 30, left: 20, bottom: 10 }}
                >
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.1)" />
                  <XAxis dataKey="day" stroke="rgba(255,255,255,0.5)" />
                  <YAxis stroke="rgba(255,255,255,0.5)" />
                  <Tooltip 
                    contentStyle={{ 
                      backgroundColor: "rgba(23, 42, 69, 0.9)", 
                      borderColor: "#64FFDA",
                      borderRadius: "6px",
                      color: "#fff"
                    }}
                  />
                  <Legend />
                  <Line 
                    type="monotone" 
                    dataKey="traffic" 
                    stroke="#64FFDA" 
                    activeDot={{ r: 8 }}
                    strokeWidth={2}
                  />
                  <Line 
                    type="monotone" 
                    dataKey="baseline" 
                    stroke="#ff6b6b" 
                    strokeDasharray="5 5"
                    strokeWidth={2}
                  />
                </LineChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
};

export default TrafficAnalysis;
