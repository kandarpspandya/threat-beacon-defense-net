
import { useState, useEffect } from "react";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Button } from "@/components/ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Download, Activity, PieChart as PieChartIcon, BarChart2 } from "lucide-react";
import { networkService } from "@/services/network";
import { RealTimeStatus } from "@/components/dashboard/RealTimeStatus";
import { PcapUploader } from "@/components/traffic/PcapUploader";
import { OverviewTab } from "@/components/traffic/OverviewTab";
import { ProtocolsTab } from "@/components/traffic/ProtocolsTab";
import { SourcesTab } from "@/components/traffic/SourcesTab";
import { TrendsTab } from "@/components/traffic/TrendsTab";

const TrafficAnalysis = () => {
  const [timeRange, setTimeRange] = useState("24h");
  const [networkStatus, setNetworkStatus] = useState<'connected' | 'connecting' | 'disconnected' | 'error'>(
    networkService.status
  );

  // Update network status periodically
  useEffect(() => {
    const statusTimer = setInterval(() => {
      setNetworkStatus(networkService.status);
    }, 3000);
    
    return () => clearInterval(statusTimer);
  }, []);

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
      <PcapUploader />

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
        <TabsContent value="overview">
          <OverviewTab />
        </TabsContent>
        
        {/* Protocols Tab */}
        <TabsContent value="protocols">
          <ProtocolsTab />
        </TabsContent>
        
        {/* Sources Tab */}
        <TabsContent value="sources">
          <SourcesTab />
        </TabsContent>
        
        {/* Trends Tab */}
        <TabsContent value="trends">
          <TrendsTab />
        </TabsContent>
      </Tabs>
    </div>
  );
};

export default TrafficAnalysis;
