
import { useState, useEffect } from "react";
import { ArrowUpRight, AlertTriangle, Zap } from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Progress } from "@/components/ui/progress";
import { ThreatItem } from "@/components/dashboard/ThreatItem";
import { NetworkActivityChart } from "@/components/dashboard/NetworkActivityChart";
import { ProtocolDistribution } from "@/components/dashboard/ProtocolDistribution";
import { AlertSummary } from "@/components/dashboard/AlertSummary";
import { TopConnections } from "@/components/dashboard/TopConnections";
import { DashboardStats } from "@/components/dashboard/DashboardStats";
import { RealTimeStatus } from "@/components/dashboard/RealTimeStatus";
import { NetworkConsentDialog } from "@/components/consent/NetworkConsentDialog";
import { networkService } from "@/services/network/NetworkService";
import { Globe, Database } from "lucide-react";
import { toast } from "sonner";

const Dashboard = () => {
  const [selectedPeriod, setSelectedPeriod] = useState("24h");
  const [networkStatus, setNetworkStatus] = useState<'connected' | 'connecting' | 'disconnected' | 'error'>(
    'disconnected'
  );
  const [showConsentDialog, setShowConsentDialog] = useState(true);

  const stats = {
    activeThreats: 12,
    blockedAttacks: 487,
    trafficAnalyzed: "2.3 TB",
    systemUptime: "99.98%",
    detectionRate: 87,
    falsePositiveRate: 3,
  };

  const recentThreats = [
    {
      id: 1,
      type: "Ransomware",
      source: "45.123.45.123",
      destination: "192.168.1.5",
      severity: "high" as "high",
      timestamp: "2023-10-10T14:23:45Z",
      status: "blocked" as "blocked",
    },
    {
      id: 2,
      type: "SQL Injection",
      source: "89.234.53.12",
      destination: "192.168.1.20",
      severity: "medium" as "medium",
      timestamp: "2023-10-10T13:42:32Z",
      status: "blocked" as "blocked",
    },
    {
      id: 3,
      type: "Port Scan",
      source: "107.45.67.89",
      destination: "192.168.1.1",
      severity: "low" as "low",
      timestamp: "2023-10-10T12:56:18Z",
      status: "monitoring" as "monitoring",
    },
    {
      id: 4,
      type: "Brute Force",
      source: "91.234.123.45",
      destination: "192.168.1.10",
      severity: "medium" as "medium",
      timestamp: "2023-10-10T11:20:45Z",
      status: "blocked" as "blocked",
    },
  ];

  const handleConsentAccept = async () => {
    console.log('[Dashboard] User accepted consent. Starting permissions and monitoring.'); // Diagnostic log
    try {
      const granted = await networkService.requestPermissions();
      console.log('[Dashboard] Permissions granted?', granted); // Diagnostic log
      if (granted) {
        await networkService.initializeRealMonitoring();
        toast.success("Network monitoring enabled");
      } else {
        toast.error("Unable to enable network monitoring");
      }
    } catch (error) {
      console.error("Error during consent acceptance:", error);
      toast.error("Failed to initialize network monitoring");
    }
    setShowConsentDialog(false);
  };

  useEffect(() => {
    const statusInterval = setInterval(() => {
      setNetworkStatus(networkService.isMonitoring ? 'connected' : 'disconnected');
    }, 3000);
    
    return () => clearInterval(statusInterval);
  }, []);

  return (
    <>
      <NetworkConsentDialog 
        open={showConsentDialog} 
        onOpenChange={setShowConsentDialog}
        onAccept={handleConsentAccept}
      />
      
      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-3xl font-bold tracking-tight">Dashboard</h2>
            <div className="flex items-center mt-1">
              <p className="text-muted-foreground mr-2">Network status</p>
              <RealTimeStatus status={networkStatus} />
            </div>
          </div>
          <div className="flex items-center space-x-2">
            <Button variant="outline" size="sm">
              <ArrowUpRight className="mr-2 h-4 w-4" />
              Export Report
            </Button>
          </div>
        </div>

        <DashboardStats 
          activeThreats={stats.activeThreats}
          blockedAttacks={stats.blockedAttacks}
          trafficAnalyzed={stats.trafficAnalyzed}
          systemUptime={stats.systemUptime}
        />

        <Tabs defaultValue="overview" className="space-y-4">
          <TabsList className="grid grid-cols-4 md:w-[400px] bg-background/50">
            <TabsTrigger value="overview">Overview</TabsTrigger>
            <TabsTrigger value="traffic">Traffic</TabsTrigger>
            <TabsTrigger value="threats">Threats</TabsTrigger>
            <TabsTrigger value="devices">Devices</TabsTrigger>
          </TabsList>
          
          <TabsContent value="overview" className="space-y-4">
            <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm">
              <CardHeader className="flex flex-row items-center justify-between pb-2">
                <div>
                  <CardTitle>Network Activity</CardTitle>
                  <CardDescription>Traffic analysis and threat correlation</CardDescription>
                </div>
                
                <div className="flex space-x-2">
                  <Button 
                    variant={selectedPeriod === "1h" ? "default" : "outline"} 
                    size="sm"
                    onClick={() => setSelectedPeriod("1h")}
                  >
                    1h
                  </Button>
                  <Button 
                    variant={selectedPeriod === "24h" ? "default" : "outline"} 
                    size="sm"
                    onClick={() => setSelectedPeriod("24h")}
                  >
                    24h
                  </Button>
                  <Button 
                    variant={selectedPeriod === "7d" ? "default" : "outline"} 
                    size="sm"
                    onClick={() => setSelectedPeriod("7d")}
                  >
                    7d
                  </Button>
                  <Button 
                    variant={selectedPeriod === "30d" ? "default" : "outline"} 
                    size="sm"
                    onClick={() => setSelectedPeriod("30d")}
                  >
                    30d
                  </Button>
                </div>
              </CardHeader>
              <CardContent className="pl-2">
                <NetworkActivityChart period={selectedPeriod} />
              </CardContent>
            </Card>

            <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-7">
              <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm md:col-span-2 lg:col-span-3">
                <CardHeader>
                  <CardTitle>Threat Detection</CardTitle>
                  <CardDescription>
                    Recent malicious activities detected
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    {recentThreats.map((threat) => (
                      <ThreatItem key={threat.id} threat={threat} />
                    ))}
                  </div>
                </CardContent>
              </Card>

              <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm md:col-span-2 lg:col-span-2">
                <CardHeader>
                  <CardTitle>Protocol Distribution</CardTitle>
                  <CardDescription>
                    Network traffic by protocol
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <ProtocolDistribution />
                </CardContent>
              </Card>

              <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm md:col-span-2 lg:col-span-2">
                <CardHeader>
                  <CardTitle>Detection Performance</CardTitle>
                  <CardDescription>
                    System accuracy metrics
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-8">
                  <div className="space-y-2">
                    <div className="flex items-center justify-between text-sm">
                      <div className="flex items-center">
                        <Zap className="mr-2 h-4 w-4 text-sentinel-accent" />
                        <span>Detection Rate</span>
                      </div>
                      <span className="font-bold">{stats.detectionRate}%</span>
                    </div>
                    <Progress value={stats.detectionRate} className="h-2" />
                  </div>
                  
                  <div className="space-y-2">
                    <div className="flex items-center justify-between text-sm">
                      <div className="flex items-center">
                        <AlertTriangle className="mr-2 h-4 w-4 text-sentinel-warning" />
                        <span>False Positive Rate</span>
                      </div>
                      <span className="font-bold">{stats.falsePositiveRate}%</span>
                    </div>
                    <Progress value={stats.falsePositiveRate} className="h-2" />
                  </div>
                </CardContent>
              </Card>
            </div>

            <div className="grid gap-4 md:grid-cols-2">
              <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm">
                <CardHeader>
                  <CardTitle>Top Connections</CardTitle>
                  <CardDescription>
                    Most active network connections
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <TopConnections />
                </CardContent>
              </Card>
              
              <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm">
                <CardHeader>
                  <CardTitle>Alert Summary</CardTitle>
                  <CardDescription>
                    Alerts by category and severity
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <AlertSummary />
                </CardContent>
              </Card>
            </div>
          </TabsContent>
          
          <TabsContent value="traffic" className="space-y-4">
            <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm">
              <CardHeader>
                <CardTitle>Traffic Analysis</CardTitle>
                <CardDescription>
                  Detailed network traffic insights and patterns
                </CardDescription>
              </CardHeader>
              <CardContent className="h-[400px] flex items-center justify-center">
                <div className="text-center space-y-2">
                  <Globe className="h-12 w-12 mx-auto text-sentinel-accent opacity-50" />
                  <p>Select the Traffic Analysis tab for detailed traffic insights</p>
                  <Button variant="outline" size="sm">
                    View Full Analysis
                  </Button>
                </div>
              </CardContent>
            </Card>
          </TabsContent>
          
          <TabsContent value="threats" className="space-y-4">
            <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm">
              <CardHeader>
                <CardTitle>Threat Intelligence</CardTitle>
                <CardDescription>
                  Comprehensive threat analysis and detection
                </CardDescription>
              </CardHeader>
              <CardContent className="h-[400px] flex items-center justify-center">
                <div className="text-center space-y-2">
                  <AlertTriangle className="h-12 w-12 mx-auto text-sentinel-warning opacity-50" />
                  <p>Select the Alerts page for detailed threat information</p>
                  <Button variant="outline" size="sm">
                    View All Threats
                  </Button>
                </div>
              </CardContent>
            </Card>
          </TabsContent>
          
          <TabsContent value="devices" className="space-y-4">
            <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm">
              <CardHeader>
                <CardTitle>Connected Devices</CardTitle>
                <CardDescription>
                  Inventory of all network devices
                </CardDescription>
              </CardHeader>
              <CardContent className="h-[400px] flex items-center justify-center">
                <div className="text-center space-y-2">
                  <Database className="h-12 w-12 mx-auto text-sentinel-info opacity-50" />
                  <p>Device inventory and management coming soon</p>
                  <Button variant="outline" size="sm" disabled>
                    Manage Devices
                  </Button>
                </div>
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </div>
    </>
  );
};

export default Dashboard;
