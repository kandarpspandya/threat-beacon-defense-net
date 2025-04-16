
import { useState } from "react";
import { Zap, AlertTriangle, FileText, Shield } from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";

const SuricataTool = () => {
  const [activeStatus, setActiveStatus] = useState(true);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-3xl font-bold tracking-tight">Suricata IDS/IPS</h2>
          <p className="text-muted-foreground">
            High performance network IDS, IPS and network security monitoring engine
          </p>
        </div>
        <div className="flex items-center space-x-2">
          <Button 
            variant={activeStatus ? "destructive" : "default"}
            onClick={() => setActiveStatus(!activeStatus)}
          >
            {activeStatus ? "Stop Engine" : "Start Engine"}
          </Button>
        </div>
      </div>

      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium">Engine Status</CardTitle>
            <Shield className={`h-4 w-4 ${activeStatus ? "text-sentinel-success" : "text-destructive"}`} />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold capitalize">{activeStatus ? "Running" : "Stopped"}</div>
            <p className="text-xs text-muted-foreground">
              Multi-threaded engine active
            </p>
          </CardContent>
        </Card>
        
        <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium">Packets Processed</CardTitle>
            <Zap className="h-4 w-4 text-sentinel-info" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">24,573,892</div>
            <p className="text-xs text-muted-foreground">
              4,328 packets/second
            </p>
          </CardContent>
        </Card>
        
        <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium">Alerts Generated</CardTitle>
            <AlertTriangle className="h-4 w-4 text-sentinel-warning" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">187</div>
            <p className="text-xs text-muted-foreground">
              Last 24 hours
            </p>
          </CardContent>
        </Card>
        
        <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium">Active Rules</CardTitle>
            <FileText className="h-4 w-4 text-sentinel-accent" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">12,453</div>
            <p className="text-xs text-muted-foreground">
              Includes ET Open ruleset
            </p>
          </CardContent>
        </Card>
      </div>

      <Tabs defaultValue="overview" className="space-y-4">
        <TabsList className="grid grid-cols-4 md:w-[400px] bg-background/50">
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="rules">Rules</TabsTrigger>
          <TabsTrigger value="alerts">Alerts</TabsTrigger>
          <TabsTrigger value="config">Configuration</TabsTrigger>
        </TabsList>
        
        <TabsContent value="overview">
          <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm">
            <CardHeader>
              <CardTitle>Suricata Overview</CardTitle>
              <CardDescription>
                Key features and capabilities
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <p className="text-muted-foreground">
                Suricata is a high performance Network IDS, IPS and Network Security Monitoring engine. It is open source and owned by a community-run non-profit foundation, the Open Information Security Foundation (OISF).
              </p>
              
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm">
                  <CardHeader className="pb-2">
                    <CardTitle className="text-lg">Multi-Threaded Engine</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <p className="text-sm text-muted-foreground">
                      Utilizes multiple CPU cores for high performance packet processing, capable of handling multi-gigabit traffic.
                    </p>
                  </CardContent>
                </Card>
                
                <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm">
                  <CardHeader className="pb-2">
                    <CardTitle className="text-lg">Protocol Identification</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <p className="text-sm text-muted-foreground">
                      Automatic protocol detection independent of ports, supporting over 30 application layer protocols.
                    </p>
                  </CardContent>
                </Card>
                
                <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm">
                  <CardHeader className="pb-2">
                    <CardTitle className="text-lg">File Extraction</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <p className="text-sm text-muted-foreground">
                      Extracts files from HTTP, SMB, and FTP protocols for offline analysis or scanning with external tools.
                    </p>
                  </CardContent>
                </Card>
                
                <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm">
                  <CardHeader className="pb-2">
                    <CardTitle className="text-lg">TLS Monitoring</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <p className="text-sm text-muted-foreground">
                      TLS certificate validation, JA3 fingerprinting, and SNI extraction for encrypted traffic analysis.
                    </p>
                  </CardContent>
                </Card>
              </div>
              
              <div className="mt-6 text-center">
                <p className="text-muted-foreground mb-4">
                  SentinelNet integrates with Suricata to provide enhanced detection capabilities. Full integration is currently in beta.
                </p>
                <Button>Explore Full Configuration</Button>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
        
        <TabsContent value="rules">
          <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm h-[400px] flex items-center justify-center">
            <div className="text-center p-6">
              <FileText className="h-16 w-16 mx-auto text-sentinel-accent opacity-50 mb-4" />
              <h3 className="text-xl font-semibold mb-2">Rule Management Integration</h3>
              <p className="text-muted-foreground mb-4">
                Suricata rule management integration is currently under development.
              </p>
              <Button variant="outline">Check Back Soon</Button>
            </div>
          </Card>
        </TabsContent>
        
        <TabsContent value="alerts">
          <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm h-[400px] flex items-center justify-center">
            <div className="text-center p-6">
              <AlertTriangle className="h-16 w-16 mx-auto text-sentinel-warning opacity-50 mb-4" />
              <h3 className="text-xl font-semibold mb-2">Alert Monitoring Coming Soon</h3>
              <p className="text-muted-foreground mb-4">
                Unified alert monitoring for Suricata will be available in the next update.
              </p>
              <Button variant="outline">View Roadmap</Button>
            </div>
          </Card>
        </TabsContent>
        
        <TabsContent value="config">
          <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm h-[400px] flex items-center justify-center">
            <div className="text-center p-6">
              <Shield className="h-16 w-16 mx-auto text-sentinel-success opacity-50 mb-4" />
              <h3 className="text-xl font-semibold mb-2">Advanced Configuration</h3>
              <p className="text-muted-foreground mb-4">
                Configure Suricata engine parameters, update rulesets, and tune performance.
              </p>
              <Button variant="outline">Launch Configuration Editor</Button>
            </div>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
};

export default SuricataTool;
