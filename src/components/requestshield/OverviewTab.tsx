
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";

export const OverviewTab = () => {
  return (
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
  );
};
