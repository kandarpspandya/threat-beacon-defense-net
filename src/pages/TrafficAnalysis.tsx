
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
import { toast } from "sonner";

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

  // Handle data export based on time range
  const handleExportData = () => {
    try {
      // Generate CSV data based on current time range
      const headers = "timestamp,source,destination,protocol,bytes,status\n";
      const rows = [];
      
      // Generate sample rows (in production this would use actual data)
      const numRows = timeRange === "1h" ? 60 : 
                     timeRange === "24h" ? 120 :
                     timeRange === "7d" ? 168 : 200;
                     
      const now = new Date();
      
      for (let i = 0; i < numRows; i++) {
        const timestamp = new Date(now.getTime() - (i * 60000));
        const source = `192.168.1.${Math.floor(Math.random() * 255)}`;
        const commonDomains = ['api.example.com', 'cdn.example.net', 'login.example.com', 'api.google.com'];
        const destination = Math.random() > 0.4 ? 
          commonDomains[Math.floor(Math.random() * commonDomains.length)] : 
          `52.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;
        
        const protocols = ["HTTP", "HTTPS", "DNS", "SSH", "SMTP"];
        const protocol = protocols[Math.floor(Math.random() * protocols.length)];
        
        const bytes = Math.floor(Math.random() * 1000000);
        const status = Math.random() > 0.9 ? "blocked" : "allowed";
        
        rows.push(`${timestamp.toISOString()},${source},${destination},${protocol},${bytes},${status}`);
      }
      
      const csvContent = headers + rows.join("\n");
      
      // Create and download CSV file
      const blob = new Blob([csvContent], { type: 'text/csv' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.setAttribute('hidden', '');
      a.setAttribute('href', url);
      a.setAttribute('download', `network-traffic-${timeRange}-${new Date().toISOString().slice(0,10)}.csv`);
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      
      toast.success(`Network traffic data for ${timeRange} period exported successfully`);
    } catch (error) {
      console.error("Export error:", error);
      toast.error("Error exporting network traffic data");
    }
  };

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
          
          <Button variant="outline" onClick={handleExportData}>
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
