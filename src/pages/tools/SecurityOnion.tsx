
import { Shield, FileText, Database, Terminal } from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";

const SecurityOnion = () => {
  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-3xl font-bold tracking-tight">Security Onion</h2>
          <p className="text-muted-foreground">
            Linux distribution for threat hunting, enterprise security monitoring, and log management
          </p>
        </div>
        <div className="flex items-center space-x-2">
          <Button variant="outline">
            View Documentation
          </Button>
          <Button variant="default">
            Connect
          </Button>
        </div>
      </div>

      <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm">
        <CardHeader>
          <CardTitle>Security Onion Integration</CardTitle>
          <CardDescription>
            Coming Soon in Future Update
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <div className="flex flex-col items-center p-6 text-center space-y-4">
              <Shield className="h-12 w-12 text-sentinel-accent" />
              <h3 className="font-semibold text-lg">Complete Visibility</h3>
              <p className="text-muted-foreground">
                Network Security Monitoring with full packet capture, network-based and host-based intrusion detection.
              </p>
            </div>
            
            <div className="flex flex-col items-center p-6 text-center space-y-4">
              <Database className="h-12 w-12 text-sentinel-info" />
              <h3 className="font-semibold text-lg">Centralized Analysis</h3>
              <p className="text-muted-foreground">
                Elasticsearch, Logstash, and Kibana integration to provide a unified platform for data collection and analysis.
              </p>
            </div>
            
            <div className="flex flex-col items-center p-6 text-center space-y-4">
              <Terminal className="h-12 w-12 text-sentinel-warning" />
              <h3 className="font-semibold text-lg">Powerful Tools</h3>
              <p className="text-muted-foreground">
                Integrated tools including Suricata, Zeek, and Wazuh for comprehensive security monitoring.
              </p>
            </div>
          </div>
          
          <div className="mt-10 p-6 text-center border border-dashed border-sentinel-light/20 rounded-md">
            <h3 className="font-semibold text-lg mb-4">Integration in Progress</h3>
            <p className="text-muted-foreground mb-6">
              We're working on integrating Security Onion with SentinelNet to provide a seamless experience for security analysts. Full integration will be available in the next major update.
            </p>
            <Button>Join Beta Program</Button>
          </div>
        </CardContent>
      </Card>

      <Tabs defaultValue="features" className="space-y-4">
        <TabsList className="grid grid-cols-3 md:w-[400px] bg-background/50">
          <TabsTrigger value="features">Features</TabsTrigger>
          <TabsTrigger value="requirements">Requirements</TabsTrigger>
          <TabsTrigger value="faq">FAQ</TabsTrigger>
        </TabsList>
        
        <TabsContent value="features">
          <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm">
            <CardHeader>
              <CardTitle>Security Onion Features</CardTitle>
              <CardDescription>
                Key capabilities and components
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <ul className="space-y-3">
                <li className="flex items-start">
                  <Shield className="h-5 w-5 mr-2 text-green-500 mt-0.5" />
                  <div>
                    <strong>Network Security Monitoring</strong>
                    <p className="text-muted-foreground text-sm">Full packet capture with tools like Zeek and Suricata</p>
                  </div>
                </li>
                <li className="flex items-start">
                  <Shield className="h-5 w-5 mr-2 text-green-500 mt-0.5" />
                  <div>
                    <strong>Host-based IDS</strong>
                    <p className="text-muted-foreground text-sm">Wazuh integration for endpoint monitoring</p>
                  </div>
                </li>
                <li className="flex items-start">
                  <Shield className="h-5 w-5 mr-2 text-green-500 mt-0.5" />
                  <div>
                    <strong>Data Storage & Analysis</strong>
                    <p className="text-muted-foreground text-sm">Elasticsearch cluster for data storage and analysis</p>
                  </div>
                </li>
                <li className="flex items-start">
                  <Shield className="h-5 w-5 mr-2 text-green-500 mt-0.5" />
                  <div>
                    <strong>Visualization</strong>
                    <p className="text-muted-foreground text-sm">Kibana dashboards for data visualization and threat hunting</p>
                  </div>
                </li>
                <li className="flex items-start">
                  <Shield className="h-5 w-5 mr-2 text-green-500 mt-0.5" />
                  <div>
                    <strong>Distributed Architecture</strong>
                    <p className="text-muted-foreground text-sm">Support for distributed deployments with management, search, and sensor nodes</p>
                  </div>
                </li>
              </ul>
            </CardContent>
          </Card>
        </TabsContent>
        
        <TabsContent value="requirements">
          <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm">
            <CardHeader>
              <CardTitle>System Requirements</CardTitle>
              <CardDescription>
                Hardware and network requirements for Security Onion
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div className="space-y-3">
                  <h3 className="font-semibold">Standalone Deployment</h3>
                  <ul className="space-y-2">
                    <li className="flex items-center">
                      <FileText className="h-4 w-4 mr-2 text-sentinel-accent" />
                      <span>4+ CPU cores</span>
                    </li>
                    <li className="flex items-center">
                      <FileText className="h-4 w-4 mr-2 text-sentinel-accent" />
                      <span>16+ GB RAM</span>
                    </li>
                    <li className="flex items-center">
                      <FileText className="h-4 w-4 mr-2 text-sentinel-accent" />
                      <span>256+ GB storage</span>
                    </li>
                    <li className="flex items-center">
                      <FileText className="h-4 w-4 mr-2 text-sentinel-accent" />
                      <span>2+ network interfaces</span>
                    </li>
                  </ul>
                </div>
                
                <div className="space-y-3">
                  <h3 className="font-semibold">Distributed Deployment</h3>
                  <ul className="space-y-2">
                    <li className="flex items-center">
                      <FileText className="h-4 w-4 mr-2 text-sentinel-warning" />
                      <span>Manager: 8+ CPU cores, 32+ GB RAM</span>
                    </li>
                    <li className="flex items-center">
                      <FileText className="h-4 w-4 mr-2 text-sentinel-warning" />
                      <span>Search Node: 16+ CPU cores, 64+ GB RAM</span>
                    </li>
                    <li className="flex items-center">
                      <FileText className="h-4 w-4 mr-2 text-sentinel-warning" />
                      <span>Sensor: 4+ CPU cores, 16+ GB RAM</span>
                    </li>
                    <li className="flex items-center">
                      <FileText className="h-4 w-4 mr-2 text-sentinel-warning" />
                      <span>Storage: Based on retention needs</span>
                    </li>
                  </ul>
                </div>
              </div>
              
              <div className="mt-6 p-4 bg-sentinel-dark/50 rounded-md">
                <h3 className="font-semibold mb-2">Network Requirements</h3>
                <p className="text-muted-foreground mb-2">
                  Security Onion requires span ports or network taps for traffic collection. The system should have:
                </p>
                <ul className="space-y-1 list-disc pl-5 text-muted-foreground">
                  <li>Management network interface</li>
                  <li>Monitoring network interface(s)</li>
                  <li>Internet connectivity for updates</li>
                  <li>Adequate bandwidth for expected traffic volume</li>
                </ul>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
        
        <TabsContent value="faq">
          <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm">
            <CardHeader>
              <CardTitle>Frequently Asked Questions</CardTitle>
              <CardDescription>
                Common questions about Security Onion integration
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="space-y-2">
                <h3 className="font-semibold">How does SentinelNet integrate with Security Onion?</h3>
                <p className="text-muted-foreground">
                  SentinelNet will connect to Security Onion's API to pull alerts, events, and network metadata for unified analysis and visualization within the SentinelNet interface.
                </p>
              </div>
              
              <div className="space-y-2">
                <h3 className="font-semibold">Can I use existing Security Onion deployments?</h3>
                <p className="text-muted-foreground">
                  Yes, SentinelNet will be able to connect to existing Security Onion installations. The integration module will require API credentials with appropriate permissions.
                </p>
              </div>
              
              <div className="space-y-2">
                <h3 className="font-semibold">When will full integration be available?</h3>
                <p className="text-muted-foreground">
                  The Security Onion integration is currently in beta and scheduled for general availability in the next major release. Beta testers can access preliminary features now.
                </p>
              </div>
              
              <div className="space-y-2">
                <h3 className="font-semibold">What data will be synchronized?</h3>
                <p className="text-muted-foreground">
                  The integration will synchronize alerts from Suricata and Zeek, full PCAP data for selected events, Zeek logs, and relevant host data from Wazuh.
                </p>
              </div>
              
              <div className="mt-6 text-center">
                <p className="text-muted-foreground mb-4">
                  Have more questions about the Security Onion integration?
                </p>
                <Button variant="outline">Contact Support</Button>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
};

export default SecurityOnion;
