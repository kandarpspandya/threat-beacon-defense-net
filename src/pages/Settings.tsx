
import { useState } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Slider } from "@/components/ui/slider";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { useToast } from "@/components/ui/use-toast";
import { AlertCircle, Save, Shield, Activity, Network, Lock, User, Bell, Zap } from "lucide-react";

const Settings = () => {
  const { toast } = useToast();
  
  // Detection sensitivity settings
  const [malwareSensitivity, setMalwareSensitivity] = useState(75);
  const [networkSensitivity, setNetworkSensitivity] = useState(70);
  const [anomalySensitivity, setAnomalySensitivity] = useState(65);
  
  // Notification settings
  const [emailAlerts, setEmailAlerts] = useState(true);
  const [smsAlerts, setSmsAlerts] = useState(false);
  const [criticalAlertsOnly, setCriticalAlertsOnly] = useState(true);
  
  // System settings
  const [captureMode, setCaptureMode] = useState("active");
  const [logRetention, setLogRetention] = useState("90");

  // User information
  const [userEmail, setUserEmail] = useState("admin@example.com");
  const [userName, setUserName] = useState("Admin User");
  
  const handleSaveSettings = (section: string) => {
    // In a real application, this would save to the backend
    toast({
      title: "Settings Saved",
      description: `${section} settings have been updated successfully.`,
    });
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-3xl font-bold tracking-tight">Settings</h2>
      </div>

      <Tabs defaultValue="detection" className="space-y-4">
        <TabsList className="grid w-full grid-cols-4 bg-background/50">
          <TabsTrigger value="detection">
            <Shield className="mr-2 h-4 w-4" />
            Detection
          </TabsTrigger>
          <TabsTrigger value="notifications">
            <Bell className="mr-2 h-4 w-4" />
            Notifications
          </TabsTrigger>
          <TabsTrigger value="system">
            <Activity className="mr-2 h-4 w-4" />
            System
          </TabsTrigger>
          <TabsTrigger value="account">
            <User className="mr-2 h-4 w-4" />
            Account
          </TabsTrigger>
        </TabsList>
        
        {/* Detection Settings */}
        <TabsContent value="detection" className="space-y-4">
          <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm">
            <CardHeader>
              <CardTitle>Threat Detection Settings</CardTitle>
              <CardDescription>
                Configure sensitivity levels and detection methods
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="space-y-4">
                <div>
                  <div className="mb-4 flex items-center justify-between">
                    <div className="space-y-0.5">
                      <Label className="text-base">Malware Detection Sensitivity</Label>
                      <p className="text-sm text-muted-foreground">
                        Higher sensitivity may increase false positives
                      </p>
                    </div>
                    <div className="font-bold">{malwareSensitivity}%</div>
                  </div>
                  <Slider
                    value={[malwareSensitivity]}
                    min={0}
                    max={100}
                    step={5}
                    onValueChange={(value) => setMalwareSensitivity(value[0])}
                  />
                </div>
                
                <div>
                  <div className="mb-4 flex items-center justify-between">
                    <div className="space-y-0.5">
                      <Label className="text-base">Network Intrusion Sensitivity</Label>
                      <p className="text-sm text-muted-foreground">
                        Affects port scan and network probe detection
                      </p>
                    </div>
                    <div className="font-bold">{networkSensitivity}%</div>
                  </div>
                  <Slider
                    value={[networkSensitivity]}
                    min={0}
                    max={100}
                    step={5}
                    onValueChange={(value) => setNetworkSensitivity(value[0])}
                  />
                </div>
                
                <div>
                  <div className="mb-4 flex items-center justify-between">
                    <div className="space-y-0.5">
                      <Label className="text-base">Anomaly Detection Sensitivity</Label>
                      <p className="text-sm text-muted-foreground">
                        Controls machine learning pattern detection
                      </p>
                    </div>
                    <div className="font-bold">{anomalySensitivity}%</div>
                  </div>
                  <Slider
                    value={[anomalySensitivity]}
                    min={0}
                    max={100}
                    step={5}
                    onValueChange={(value) => setAnomalySensitivity(value[0])}
                  />
                </div>
              </div>
              
              <div className="space-y-4">
                <div className="flex items-center justify-between space-y-2">
                  <div className="flex flex-col space-y-1">
                    <Label htmlFor="auto-block" className="text-base">Automatic Threat Blocking</Label>
                    <p className="text-sm text-muted-foreground">
                      Automatically block detected threats
                    </p>
                  </div>
                  <Switch id="auto-block" defaultChecked />
                </div>
                
                <div className="flex items-center justify-between space-y-2">
                  <div className="flex flex-col space-y-1">
                    <Label htmlFor="deep-scan" className="text-base">Deep Packet Inspection</Label>
                    <p className="text-sm text-muted-foreground">
                      Analyze packet contents for threats (CPU intensive)
                    </p>
                  </div>
                  <Switch id="deep-scan" defaultChecked />
                </div>
                
                <div className="flex items-center justify-between space-y-2">
                  <div className="flex flex-col space-y-1">
                    <Label htmlFor="ml-enable" className="text-base">ML-Based Detection</Label>
                    <p className="text-sm text-muted-foreground">
                      Use machine learning to identify novel threats
                    </p>
                  </div>
                  <Switch id="ml-enable" defaultChecked />
                </div>
              </div>
              
              <div className="pt-4">
                <Button onClick={() => handleSaveSettings("Detection")}>
                  <Save className="mr-2 h-4 w-4" />
                  Save Detection Settings
                </Button>
              </div>
            </CardContent>
          </Card>
          
          <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm">
            <CardHeader>
              <CardTitle>Custom Rules</CardTitle>
              <CardDescription>
                Define custom detection rules and signatures
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex items-center justify-between rounded-md border p-4 border-sentinel-light/10">
                <div className="space-y-1">
                  <p className="font-medium">Suricata/Snort Compatible Rules</p>
                  <p className="text-sm text-muted-foreground">
                    Enter IDS/IPS rules in Suricata/Snort format
                  </p>
                </div>
                <Button variant="outline">Import Rules</Button>
              </div>
              
              <div className="space-y-2">
                <Label htmlFor="custom-rules">Custom Rules</Label>
                <Textarea 
                  id="custom-rules"
                  placeholder="Enter rules in Suricata/Snort format..."
                  className="font-mono text-xs min-h-[150px]"
                  defaultValue="alert tcp any any -> $HOME_NET 22 (msg:'Potential SSH Brute Force Attempt'; flow:to_server; threshold:type threshold, track by_src, count 5, seconds 60; classtype:attempted-admin; sid:1000001; rev:1;)"
                />
                <p className="text-xs text-muted-foreground">
                  <AlertCircle className="inline h-3 w-3 mr-1" />
                  Incorrect rule syntax may cause detection issues
                </p>
              </div>
              
              <div className="pt-4">
                <Button onClick={() => handleSaveSettings("Custom Rules")}>
                  <Save className="mr-2 h-4 w-4" />
                  Save Rules
                </Button>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
        
        {/* Notification Settings */}
        <TabsContent value="notifications" className="space-y-4">
          <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm">
            <CardHeader>
              <CardTitle>Alert Notifications</CardTitle>
              <CardDescription>
                Configure how and when you receive alerts
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="space-y-4">
                <div className="flex items-center justify-between space-y-2">
                  <div className="flex flex-col space-y-1">
                    <Label htmlFor="email-alerts" className="text-base">Email Alerts</Label>
                    <p className="text-sm text-muted-foreground">
                      Receive threat alerts via email
                    </p>
                  </div>
                  <Switch 
                    id="email-alerts" 
                    checked={emailAlerts}
                    onCheckedChange={setEmailAlerts}
                  />
                </div>
                
                {emailAlerts && (
                  <div className="ml-6 space-y-2">
                    <Label htmlFor="alert-email">Alert Email Address</Label>
                    <Input 
                      id="alert-email" 
                      placeholder="alerts@example.com" 
                      defaultValue="admin@example.com"
                    />
                  </div>
                )}
                
                <div className="flex items-center justify-between space-y-2">
                  <div className="flex flex-col space-y-1">
                    <Label htmlFor="sms-alerts" className="text-base">SMS Alerts</Label>
                    <p className="text-sm text-muted-foreground">
                      Receive critical alerts via SMS
                    </p>
                  </div>
                  <Switch 
                    id="sms-alerts" 
                    checked={smsAlerts}
                    onCheckedChange={setSmsAlerts}
                  />
                </div>
                
                {smsAlerts && (
                  <div className="ml-6 space-y-2">
                    <Label htmlFor="alert-phone">Phone Number</Label>
                    <Input 
                      id="alert-phone" 
                      placeholder="+1 (555) 123-4567" 
                    />
                  </div>
                )}
                
                <div className="flex items-center justify-between space-y-2">
                  <div className="flex flex-col space-y-1">
                    <Label htmlFor="critical-only" className="text-base">Critical Alerts Only</Label>
                    <p className="text-sm text-muted-foreground">
                      Only send alerts for high severity threats
                    </p>
                  </div>
                  <Switch 
                    id="critical-only" 
                    checked={criticalAlertsOnly}
                    onCheckedChange={setCriticalAlertsOnly}
                  />
                </div>
              </div>
              
              <div className="space-y-4">
                <Label className="text-base">Alert Frequency</Label>
                <Select defaultValue="realtime">
                  <SelectTrigger>
                    <SelectValue placeholder="Select frequency" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="realtime">Real-time</SelectItem>
                    <SelectItem value="hourly">Hourly digest</SelectItem>
                    <SelectItem value="daily">Daily summary</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              
              <div className="pt-4">
                <Button onClick={() => handleSaveSettings("Notification")}>
                  <Save className="mr-2 h-4 w-4" />
                  Save Notification Settings
                </Button>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
        
        {/* System Settings */}
        <TabsContent value="system" className="space-y-4">
          <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm">
            <CardHeader>
              <CardTitle>System Configuration</CardTitle>
              <CardDescription>
                Configure core system behavior and performance options
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="capture-mode">Network Capture Mode</Label>
                  <Select value={captureMode} onValueChange={setCaptureMode}>
                    <SelectTrigger id="capture-mode">
                      <SelectValue placeholder="Select mode" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="active">Active (Real-time analysis)</SelectItem>
                      <SelectItem value="passive">Passive (Monitor only)</SelectItem>
                      <SelectItem value="scheduled">Scheduled (Periodic scans)</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                
                <div className="space-y-2">
                  <Label htmlFor="log-retention">Log Retention Period (Days)</Label>
                  <Select value={logRetention} onValueChange={setLogRetention}>
                    <SelectTrigger id="log-retention">
                      <SelectValue placeholder="Select period" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="30">30 days</SelectItem>
                      <SelectItem value="60">60 days</SelectItem>
                      <SelectItem value="90">90 days</SelectItem>
                      <SelectItem value="180">180 days</SelectItem>
                      <SelectItem value="365">365 days</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                
                <div className="space-y-2">
                  <Label htmlFor="interfaces">Network Interfaces</Label>
                  <div className="rounded-md border p-4 border-sentinel-light/10">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center space-x-2">
                        <Network className="h-4 w-4 text-sentinel-info" />
                        <span>eth0 (Primary)</span>
                      </div>
                      <Switch id="eth0-monitor" defaultChecked />
                    </div>
                  </div>
                </div>
              </div>
              
              <div className="space-y-4">
                <div className="flex items-center justify-between space-y-2">
                  <div className="flex flex-col space-y-1">
                    <Label htmlFor="auto-update" className="text-base">Automatic Updates</Label>
                    <p className="text-sm text-muted-foreground">
                      Keep threat signatures and detection rules updated
                    </p>
                  </div>
                  <Switch id="auto-update" defaultChecked />
                </div>
                
                <div className="flex items-center justify-between space-y-2">
                  <div className="flex flex-col space-y-1">
                    <Label htmlFor="telemetry" className="text-base">Anonymous Telemetry</Label>
                    <p className="text-sm text-muted-foreground">
                      Send anonymous usage data to improve the system
                    </p>
                  </div>
                  <Switch id="telemetry" defaultChecked />
                </div>
              </div>
              
              <div className="space-y-2">
                <Label htmlFor="api-key">API Key</Label>
                <div className="flex space-x-2">
                  <Input 
                    id="api-key" 
                    type="password" 
                    value="••••••••••••••••••••••••••••••"
                    readOnly
                  />
                  <Button variant="outline">Regenerate</Button>
                </div>
                <p className="text-xs text-muted-foreground">
                  <Lock className="inline h-3 w-3 mr-1" />
                  This key grants access to the SentinelNet API
                </p>
              </div>
              
              <div className="pt-4">
                <Button onClick={() => handleSaveSettings("System")}>
                  <Save className="mr-2 h-4 w-4" />
                  Save System Settings
                </Button>
              </div>
            </CardContent>
          </Card>
          
          <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm">
            <CardHeader>
              <CardTitle>Performance Tuning</CardTitle>
              <CardDescription>
                Optimize resource allocation for detection processes
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div>
                <div className="mb-4 flex items-center justify-between">
                  <div className="space-y-0.5">
                    <Label className="text-base">CPU Usage Limit</Label>
                    <p className="text-sm text-muted-foreground">
                      Maximum CPU allocation for detection engine
                    </p>
                  </div>
                  <div className="font-bold">70%</div>
                </div>
                <Slider
                  defaultValue={[70]}
                  max={100}
                  step={5}
                />
              </div>
              
              <div>
                <div className="mb-4 flex items-center justify-between">
                  <div className="space-y-0.5">
                    <Label className="text-base">Memory Usage Limit</Label>
                    <p className="text-sm text-muted-foreground">
                      Maximum memory allocation for detection engine
                    </p>
                  </div>
                  <div className="font-bold">60%</div>
                </div>
                <Slider
                  defaultValue={[60]}
                  max={100}
                  step={5}
                />
              </div>
              
              <div className="pt-4">
                <Button onClick={() => handleSaveSettings("Performance")}>
                  <Zap className="mr-2 h-4 w-4" />
                  Save Performance Settings
                </Button>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
        
        {/* Account Settings */}
        <TabsContent value="account" className="space-y-4">
          <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm">
            <CardHeader>
              <CardTitle>User Account</CardTitle>
              <CardDescription>
                Manage your account information and security settings
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="full-name">Full Name</Label>
                  <Input 
                    id="full-name" 
                    value={userName}
                    onChange={(e) => setUserName(e.target.value)}
                  />
                </div>
                
                <div className="space-y-2">
                  <Label htmlFor="email">Email Address</Label>
                  <Input 
                    id="email" 
                    type="email"
                    value={userEmail}
                    onChange={(e) => setUserEmail(e.target.value)}
                  />
                </div>
              </div>
              
              <div className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="change-password">Change Password</Label>
                  <div className="grid gap-2">
                    <Input id="current-password" type="password" placeholder="Current password" />
                    <Input id="new-password" type="password" placeholder="New password" />
                    <Input id="confirm-password" type="password" placeholder="Confirm new password" />
                  </div>
                </div>
              </div>
              
              <div className="space-y-4">
                <div className="flex items-center justify-between space-y-2">
                  <div className="flex flex-col space-y-1">
                    <Label htmlFor="two-factor" className="text-base">Two-Factor Authentication</Label>
                    <p className="text-sm text-muted-foreground">
                      Add an extra layer of security to your account
                    </p>
                  </div>
                  <Switch id="two-factor" />
                </div>
              </div>
              
              <div className="pt-4">
                <Button onClick={() => handleSaveSettings("Account")}>
                  <Save className="mr-2 h-4 w-4" />
                  Save Account Settings
                </Button>
              </div>
            </CardContent>
          </Card>
          
          <Card className="border-destructive/20 bg-destructive/5 backdrop-blur-sm">
            <CardHeader>
              <CardTitle className="text-destructive">Danger Zone</CardTitle>
              <CardDescription>
                Irreversible account operations
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="rounded-md border border-destructive/30 p-4">
                <h3 className="text-lg font-medium text-destructive">Delete Account</h3>
                <p className="mt-1 text-sm text-muted-foreground">
                  This will permanently delete your account and all associated data.
                </p>
                <div className="mt-4">
                  <Button variant="destructive">Delete Account</Button>
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
};

export default Settings;
