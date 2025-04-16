
import { FilterX, FileText, ArrowUpRight, Shield, BarChart2 } from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts';

// Mock data for API traffic chart
const apiTrafficData = [
  { time: "00:00", normal: 245, malicious: 8 },
  { time: "01:00", normal: 185, malicious: 5 },
  { time: "02:00", normal: 143, malicious: 3 },
  { time: "03:00", normal: 128, malicious: 2 },
  { time: "04:00", normal: 112, malicious: 1 },
  { time: "05:00", normal: 95, malicious: 1 },
  { time: "06:00", normal: 125, malicious: 2 },
  { time: "07:00", normal: 198, malicious: 4 },
  { time: "08:00", normal: 345, malicious: 12 },
  { time: "09:00", normal: 475, malicious: 18 },
  { time: "10:00", normal: 590, malicious: 22 },
  { time: "11:00", normal: 623, malicious: 25 },
  { time: "12:00", normal: 589, malicious: 21 },
  { time: "13:00", normal: 542, malicious: 19 },
  { time: "14:00", normal: 578, malicious: 23 },
  { time: "15:00", normal: 605, malicious: 26 },
  { time: "16:00", normal: 632, malicious: 28 },
  { time: "17:00", normal: 587, malicious: 24 },
  { time: "18:00", normal: 498, malicious: 20 },
  { time: "19:00", normal: 432, malicious: 17 },
  { time: "20:00", normal: 387, malicious: 15 },
  { time: "21:00", normal: 345, malicious: 13 },
  { time: "22:00", normal: 298, malicious: 10 },
  { time: "23:00", normal: 265, malicious: 9 }
];

const RequestShield = () => {
  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-3xl font-bold tracking-tight">RequestShield</h2>
          <p className="text-muted-foreground">
            API security monitoring and protection
          </p>
        </div>
        <div className="flex items-center space-x-2">
          <Button variant="outline">
            <ArrowUpRight className="mr-2 h-4 w-4" />
            View Reports
          </Button>
          <Button variant="default">
            Configure
          </Button>
        </div>
      </div>

      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium">Integration Status</CardTitle>
            <Shield className="h-4 w-4 text-sentinel-success" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">Active</div>
            <p className="text-xs text-muted-foreground">
              Monitoring 12 API endpoints
            </p>
          </CardContent>
        </Card>
        
        <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium">Requests Analyzed</CardTitle>
            <BarChart2 className="h-4 w-4 text-sentinel-info" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">10,567</div>
            <p className="text-xs text-muted-foreground">
              Last 24 hours
            </p>
          </CardContent>
        </Card>
        
        <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium">Threats Blocked</CardTitle>
            <FilterX className="h-4 w-4 text-sentinel-danger" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">327</div>
            <p className="text-xs text-muted-foreground">
              3.1% of total traffic
            </p>
          </CardContent>
        </Card>
        
        <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium">Protection Rules</CardTitle>
            <FileText className="h-4 w-4 text-sentinel-accent" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">48</div>
            <p className="text-xs text-muted-foreground">
              Active API protection rules
            </p>
          </CardContent>
        </Card>
      </div>

      <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm">
        <CardHeader>
          <CardTitle>API Traffic Analysis</CardTitle>
          <CardDescription>
            Legitimate vs. malicious API requests over 24 hours
          </CardDescription>
        </CardHeader>
        <CardContent className="h-[300px]">
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={apiTrafficData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#2D3748" />
              <XAxis 
                dataKey="time" 
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
              <Line 
                type="monotone" 
                dataKey="normal" 
                stroke="#64FFDA" 
                strokeWidth={2}
                name="Legitimate Requests"
              />
              <Line 
                type="monotone" 
                dataKey="malicious" 
                stroke="#FF6B6B" 
                strokeWidth={2}
                name="Malicious Requests"
              />
            </LineChart>
          </ResponsiveContainer>
        </CardContent>
      </Card>

      <Tabs defaultValue="overview" className="space-y-4">
        <TabsList className="grid grid-cols-4 md:w-[400px] bg-background/50">
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="endpoints">Endpoints</TabsTrigger>
          <TabsTrigger value="threats">Threats</TabsTrigger>
          <TabsTrigger value="rules">Rules</TabsTrigger>
        </TabsList>
        
        <TabsContent value="overview">
          <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm">
            <CardHeader>
              <CardTitle>RequestShield Overview</CardTitle>
              <CardDescription>
                API security monitoring and threat prevention
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <p className="text-muted-foreground">
                RequestShield analyzes API traffic to identify and block malicious requests, protecting your APIs from common attack vectors such as injection attacks, authentication bypass, and data exposure.
              </p>
              
              <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm">
                  <CardHeader className="pb-2">
                    <CardTitle className="text-lg">Request Analysis</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <ul className="text-sm text-muted-foreground space-y-2">
                      <li>• Parameter validation</li>
                      <li>• Schema enforcement</li>
                      <li>• Content inspection</li>
                      <li>• Anomaly detection</li>
                      <li>• Request rate monitoring</li>
                    </ul>
                  </CardContent>
                </Card>
                
                <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm">
                  <CardHeader className="pb-2">
                    <CardTitle className="text-lg">Threat Prevention</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <ul className="text-sm text-muted-foreground space-y-2">
                      <li>• SQL/NoSQL injection</li>
                      <li>• Cross-site scripting (XSS)</li>
                      <li>• API parameter tampering</li>
                      <li>• Excessive data exposure</li>
                      <li>• Broken authentication</li>
                    </ul>
                  </CardContent>
                </Card>
                
                <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm">
                  <CardHeader className="pb-2">
                    <CardTitle className="text-lg">Response Actions</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <ul className="text-sm text-muted-foreground space-y-2">
                      <li>• Block malicious requests</li>
                      <li>• Rate limiting enforcement</li>
                      <li>• Real-time alerts</li>
                      <li>• Incident logging</li>
                      <li>• Response sanitization</li>
                    </ul>
                  </CardContent>
                </Card>
              </div>
              
              <div className="mt-6 p-6 text-center border border-dashed border-sentinel-light/20 rounded-md">
                <h3 className="font-semibold text-lg mb-4">API Security Posture Summary</h3>
                <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
                  <div className="bg-sentinel-dark/50 p-3 rounded-md text-center">
                    <div className="text-lg font-bold text-sentinel-success">92%</div>
                    <p className="text-xs text-muted-foreground">Protection Coverage</p>
                  </div>
                  <div className="bg-sentinel-dark/50 p-3 rounded-md text-center">
                    <div className="text-lg font-bold text-sentinel-warning">7</div>
                    <p className="text-xs text-muted-foreground">Endpoints at Risk</p>
                  </div>
                  <div className="bg-sentinel-dark/50 p-3 rounded-md text-center">
                    <div className="text-lg font-bold text-sentinel-danger">12</div>
                    <p className="text-xs text-muted-foreground">Active Attackers</p>
                  </div>
                  <div className="bg-sentinel-dark/50 p-3 rounded-md text-center">
                    <div className="text-lg font-bold text-sentinel-info">98.7%</div>
                    <p className="text-xs text-muted-foreground">Legitimate Traffic</p>
                  </div>
                </div>
                <Button>View Detailed Report</Button>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
        
        <TabsContent value="endpoints">
          <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm h-[300px] flex items-center justify-center">
            <div className="text-center p-6">
              <Globe className="h-16 w-16 mx-auto text-sentinel-info opacity-50 mb-4" />
              <h3 className="text-xl font-semibold mb-2">API Endpoints</h3>
              <p className="text-muted-foreground mb-4">
                View monitored API endpoints, traffic patterns, and security posture.
              </p>
              <Button variant="outline">Configure Endpoints</Button>
            </div>
          </Card>
        </TabsContent>
        
        <TabsContent value="threats">
          <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm h-[300px] flex items-center justify-center">
            <div className="text-center p-6">
              <AlertTriangle className="h-16 w-16 mx-auto text-sentinel-warning opacity-50 mb-4" />
              <h3 className="text-xl font-semibold mb-2">Detected Threats</h3>
              <p className="text-muted-foreground mb-4">
                Analyze blocked malicious requests and attack patterns targeting your APIs.
              </p>
              <Button variant="outline">View Threat Log</Button>
            </div>
          </Card>
        </TabsContent>
        
        <TabsContent value="rules">
          <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm h-[300px] flex items-center justify-center">
            <div className="text-center p-6">
              <FileText className="h-16 w-16 mx-auto text-sentinel-accent opacity-50 mb-4" />
              <h3 className="text-xl font-semibold mb-2">Protection Rules</h3>
              <p className="text-muted-foreground mb-4">
                Configure API protection rules and security policies.
              </p>
              <Button variant="outline">Manage Rules</Button>
            </div>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
};

export default RequestShield;

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

function AlertTriangle(props: any) {
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
      <path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z" />
      <path d="M12 9v4" />
      <path d="M12 17h.01" />
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
