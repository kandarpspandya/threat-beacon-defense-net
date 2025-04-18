
import { useState } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Button } from "@/components/ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Download, Upload, FileType, Activity, PieChart as PieChartIcon, BarChart2 } from "lucide-react";
import { Progress } from "@/components/ui/progress";
import { networkService } from "@/services/networkService";

// Import our new real-time components
import { TrafficOverTimeChart } from "@/components/dashboard/TrafficOverTimeChart";
import { ProtocolDistribution } from "@/components/dashboard/ProtocolDistribution";
import { TrafficSourcesChart } from "@/components/dashboard/TrafficSourcesChart";
import { TopDomainsChart } from "@/components/dashboard/TopDomainsChart";
import { RealTimeStatus } from "@/components/dashboard/RealTimeStatus";

const TrafficAnalysis = () => {
  const [timeRange, setTimeRange] = useState("24h");
  const [isUploading, setIsUploading] = useState(false);
  const [uploadProgress, setUploadProgress] = useState(0);
  const [networkStatus, setNetworkStatus] = useState<'connected' | 'connecting' | 'disconnected' | 'error'>(
    networkService.status
  );

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

  // Update network status periodically
  setTimeout(() => {
    setNetworkStatus(networkService.status);
  }, 3000);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-3xl font-bold tracking-tight">Traffic Analysis</h2>
          <div className="flex items-center mt-1">
            <p className="text-muted-foreground mr-2">Network monitoring</p>
            <RealTimeStatus status={networkStatus} />
          </div>
        </div>
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
            <Activity className="mr-2 h-4 w-4" />
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
                <TrafficOverTimeChart />
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
                <ProtocolDistribution />
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
                <TrafficSourcesChart />
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
              <TopDomainsChart />
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
              <ProtocolDistribution />
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
              <TrafficSourcesChart />
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
              <TrafficOverTimeChart />
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
};

export default TrafficAnalysis;
