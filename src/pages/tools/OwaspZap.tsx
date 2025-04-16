
import { Lock, FileText, Bug, Shield, BarChart2 } from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Progress } from "@/components/ui/progress";

const OwaspZap = () => {
  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-3xl font-bold tracking-tight">OWASP ZAP</h2>
          <p className="text-muted-foreground">
            Open source web application security scanner
          </p>
        </div>
        <div className="flex items-center space-x-2">
          <Button variant="outline">
            Launch Scanner
          </Button>
          <Button variant="default">
            View Documentation
          </Button>
        </div>
      </div>

      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium">Integration Status</CardTitle>
            <Shield className="h-4 w-4 text-sentinel-warning" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">Beta</div>
            <p className="text-xs text-muted-foreground">
              Testing API connectivity
            </p>
          </CardContent>
        </Card>
        
        <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium">Scans Completed</CardTitle>
            <BarChart2 className="h-4 w-4 text-sentinel-info" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">17</div>
            <p className="text-xs text-muted-foreground">
              Last 30 days
            </p>
          </CardContent>
        </Card>
        
        <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium">Vulnerabilities Found</CardTitle>
            <Bug className="h-4 w-4 text-sentinel-danger" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">143</div>
            <p className="text-xs text-muted-foreground">
              42 high, 68 medium, 33 low
            </p>
          </CardContent>
        </Card>
        
        <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium">Scan Rules</CardTitle>
            <FileText className="h-4 w-4 text-sentinel-accent" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">285</div>
            <p className="text-xs text-muted-foreground">
              Active and passive rules
            </p>
          </CardContent>
        </Card>
      </div>

      <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm">
        <CardHeader>
          <CardTitle>OWASP ZAP Integration</CardTitle>
          <CardDescription>
            Web Application Security Testing
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-6">
            <p className="text-muted-foreground">
              OWASP Zed Attack Proxy (ZAP) is one of the world's most popular free security tools and is actively maintained by hundreds of international volunteers. SentinelNet integrates with ZAP to provide web application security testing capabilities.
            </p>
            
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div className="space-y-4">
                <h3 className="font-semibold text-lg">Integration Progress</h3>
                
                <div className="space-y-2">
                  <div className="flex items-center justify-between text-sm">
                    <span>API Connectivity</span>
                    <span className="font-bold">100%</span>
                  </div>
                  <Progress value={100} className="h-2" />
                </div>
                
                <div className="space-y-2">
                  <div className="flex items-center justify-between text-sm">
                    <span>Scan Management</span>
                    <span className="font-bold">80%</span>
                  </div>
                  <Progress value={80} className="h-2" />
                </div>
                
                <div className="space-y-2">
                  <div className="flex items-center justify-between text-sm">
                    <span>Result Processing</span>
                    <span className="font-bold">65%</span>
                  </div>
                  <Progress value={65} className="h-2" />
                </div>
                
                <div className="space-y-2">
                  <div className="flex items-center justify-between text-sm">
                    <span>Vulnerability Management</span>
                    <span className="font-bold">45%</span>
                  </div>
                  <Progress value={45} className="h-2" />
                </div>
                
                <div className="space-y-2">
                  <div className="flex items-center justify-between text-sm">
                    <span>Reporting Integration</span>
                    <span className="font-bold">30%</span>
                  </div>
                  <Progress value={30} className="h-2" />
                </div>
              </div>
              
              <div className="space-y-4">
                <h3 className="font-semibold text-lg">Key Capabilities</h3>
                
                <ul className="space-y-2">
                  <li className="flex items-start">
                    <Lock className="h-5 w-5 mr-2 text-sentinel-accent mt-0.5" />
                    <div>
                      <strong>Intercepting Proxy</strong>
                      <p className="text-muted-foreground text-sm">Inspect and modify traffic between browser and web application</p>
                    </div>
                  </li>
                  
                  <li className="flex items-start">
                    <Lock className="h-5 w-5 mr-2 text-sentinel-accent mt-0.5" />
                    <div>
                      <strong>Automated Scanner</strong>
                      <p className="text-muted-foreground text-sm">Discover vulnerabilities automatically with active and passive scanning</p>
                    </div>
                  </li>
                  
                  <li className="flex items-start">
                    <Lock className="h-5 w-5 mr-2 text-sentinel-accent mt-0.5" />
                    <div>
                      <strong>Spider</strong>
                      <p className="text-muted-foreground text-sm">Crawl web applications to discover content and functionality</p>
                    </div>
                  </li>
                  
                  <li className="flex items-start">
                    <Lock className="h-5 w-5 mr-2 text-sentinel-accent mt-0.5" />
                    <div>
                      <strong>REST API</strong>
                      <p className="text-muted-foreground text-sm">Integrate with automation workflows and CI/CD pipelines</p>
                    </div>
                  </li>
                  
                  <li className="flex items-start">
                    <Lock className="h-5 w-5 mr-2 text-sentinel-accent mt-0.5" />
                    <div>
                      <strong>Report Generation</strong>
                      <p className="text-muted-foreground text-sm">Comprehensive vulnerability reports in multiple formats</p>
                    </div>
                  </li>
                </ul>
              </div>
            </div>
            
            <div className="mt-6 p-6 text-center border border-dashed border-sentinel-light/20 rounded-md">
              <h3 className="font-semibold text-lg mb-4">Begin Testing Web Applications</h3>
              <p className="text-muted-foreground mb-6">
                Set up OWASP ZAP integration to start scanning your web applications for vulnerabilities. Our integration supports both automated scans and manual testing.
              </p>
              <Button>Configure Connection</Button>
            </div>
          </div>
        </CardContent>
      </Card>

      <Tabs defaultValue="recent" className="space-y-4">
        <TabsList className="grid grid-cols-3 md:w-[400px] bg-background/50">
          <TabsTrigger value="recent">Recent Scans</TabsTrigger>
          <TabsTrigger value="targets">Targets</TabsTrigger>
          <TabsTrigger value="config">Configuration</TabsTrigger>
        </TabsList>
        
        <TabsContent value="recent">
          <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm h-[300px] flex items-center justify-center">
            <div className="text-center p-6">
              <FileText className="h-16 w-16 mx-auto text-sentinel-accent opacity-50 mb-4" />
              <h3 className="text-xl font-semibold mb-2">Scan History</h3>
              <p className="text-muted-foreground mb-4">
                Scan history and results will be displayed here once the ZAP integration is fully activated.
              </p>
              <Button variant="outline">Check Integration Status</Button>
            </div>
          </Card>
        </TabsContent>
        
        <TabsContent value="targets">
          <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm h-[300px] flex items-center justify-center">
            <div className="text-center p-6">
              <Globe className="h-16 w-16 mx-auto text-sentinel-info opacity-50 mb-4" />
              <h3 className="text-xl font-semibold mb-2">Web Application Targets</h3>
              <p className="text-muted-foreground mb-4">
                Define targets for web application security scanning with OWASP ZAP.
              </p>
              <Button variant="outline">Add Target</Button>
            </div>
          </Card>
        </TabsContent>
        
        <TabsContent value="config">
          <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm h-[300px] flex items-center justify-center">
            <div className="text-center p-6">
              <Shield className="h-16 w-16 mx-auto text-sentinel-success opacity-50 mb-4" />
              <h3 className="text-xl font-semibold mb-2">ZAP Configuration</h3>
              <p className="text-muted-foreground mb-4">
                Configure connection settings, scan policies, and API access for OWASP ZAP integration.
              </p>
              <Button variant="outline">Open Configuration Panel</Button>
            </div>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
};

export default OwaspZap;

function Globe(props: any) {
  return (
    <svg
      {...props}
      xmlns="http://www.w3.org/2000/svg"
      width="24"
      height="24"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <circle cx="12" cy="12" r="10" />
      <line x1="2" x2="22" y1="12" y2="12" />
      <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z" />
    </svg>
  );
}

function BarChart2(props: any) {
  return (
    <svg
      {...props}
      xmlns="http://www.w3.org/2000/svg"
      width="24"
      height="24"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <line x1="18" x2="18" y1="20" y2="10" />
      <line x1="12" x2="12" y1="20" y2="4" />
      <line x1="6" x2="6" y1="20" y2="14" />
    </svg>
  );
}
