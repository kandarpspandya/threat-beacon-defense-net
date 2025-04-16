
import { useState } from "react";
import { 
  Bell, 
  Mail, 
  MessageSquare, 
  Smartphone, 
  Check, 
  X, 
  Sliders, 
  Plus, 
  Trash2,
  Save,
  BellRing
} from "lucide-react";
import { 
  Card, 
  CardContent, 
  CardDescription, 
  CardFooter, 
  CardHeader, 
  CardTitle 
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Switch } from "@/components/ui/switch";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { toast } from "sonner";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import { 
  Table, 
  TableBody, 
  TableCaption, 
  TableCell, 
  TableHead, 
  TableHeader, 
  TableRow 
} from "@/components/ui/table";

// Mock notification channels data
const mockNotificationChannels = [
  { id: 1, name: "Security Team", type: "email", value: "security@company.com", enabled: true },
  { id: 2, name: "SOC Slack Channel", type: "webhook", value: "https://hooks.slack.com/services/T00000/B00000/XXXXXXXXXX", enabled: true },
  { id: 3, name: "On-Call SMS", type: "sms", value: "+11234567890", enabled: false },
  { id: 4, name: "IT Department", type: "email", value: "it@company.com", enabled: true },
  { id: 5, name: "SIEM Integration", type: "webhook", value: "https://siem.internal/api/alerts", enabled: true },
];

// Mock notification policies
const mockNotificationPolicies = [
  { 
    id: 1, 
    name: "Critical Threats", 
    description: "Immediate notification for critical security threats",
    severity: "critical", 
    channels: [1, 2, 3],
    enabled: true 
  },
  { 
    id: 2, 
    name: "Data Exfiltration", 
    description: "Alert when suspicious outbound traffic is detected",
    severity: "high", 
    channels: [1, 4],
    enabled: true 
  },
  { 
    id: 3, 
    name: "Failed Authentication", 
    description: "Multiple failed login attempts",
    severity: "medium", 
    channels: [1, 5],
    enabled: true 
  },
  { 
    id: 4, 
    name: "Network Scans", 
    description: "Detection of port scanning or network reconnaissance",
    severity: "low", 
    channels: [5],
    enabled: false 
  },
];

// Mock notification history
const mockNotificationHistory = [
  { 
    id: 1, 
    timestamp: "2025-04-16T10:23:45", 
    policy: "Critical Threats", 
    message: "Potential ransomware activity detected",
    severity: "critical",
    sentTo: ["Security Team", "SOC Slack Channel", "On-Call SMS"],
    status: "delivered" 
  },
  { 
    id: 2, 
    timestamp: "2025-04-16T09:12:33", 
    policy: "Data Exfiltration", 
    message: "Unusual outbound data transfer (2.3GB) to unknown IP",
    severity: "high",
    sentTo: ["Security Team", "IT Department"],
    status: "delivered" 
  },
  { 
    id: 3, 
    timestamp: "2025-04-16T08:45:19", 
    policy: "Failed Authentication", 
    message: "10+ failed login attempts for admin user",
    severity: "medium",
    sentTo: ["Security Team", "SIEM Integration"],
    status: "delivered" 
  },
  { 
    id: 4, 
    timestamp: "2025-04-15T23:34:56", 
    policy: "Critical Threats", 
    message: "Unauthorized access to financial database",
    severity: "critical",
    sentTo: ["Security Team", "SOC Slack Channel"],
    status: "partial" 
  },
  { 
    id: 5, 
    timestamp: "2025-04-15T18:23:12", 
    policy: "Network Scans", 
    message: "Port scan detected from internal IP 192.168.1.45",
    severity: "low",
    sentTo: ["SIEM Integration"],
    status: "failed" 
  },
];

const AlertManagement = () => {
  const [channels, setChannels] = useState(mockNotificationChannels);
  const [policies, setPolicies] = useState(mockNotificationPolicies);
  const [history] = useState(mockNotificationHistory);
  const [newChannel, setNewChannel] = useState({ name: "", type: "email", value: "", enabled: true });
  const [newPolicy, setNewPolicy] = useState({ 
    name: "", 
    description: "",
    severity: "medium", 
    channels: [],
    enabled: true 
  });
  const [selectedChannels, setSelectedChannels] = useState<number[]>([]);

  // Handler for toggling channel enabled status
  const toggleChannelStatus = (id: number) => {
    setChannels(channels.map(channel => 
      channel.id === id ? { ...channel, enabled: !channel.enabled } : channel
    ));
    toast.success(`Channel ${channels.find(c => c.id === id)?.enabled ? "disabled" : "enabled"}`);
  };

  // Handler for toggling policy enabled status
  const togglePolicyStatus = (id: number) => {
    setPolicies(policies.map(policy => 
      policy.id === id ? { ...policy, enabled: !policy.enabled } : policy
    ));
    toast.success(`Policy ${policies.find(p => p.id === id)?.enabled ? "disabled" : "enabled"}`);
  };

  // Handler for adding a new notification channel
  const addChannel = () => {
    if (!newChannel.name || !newChannel.value) {
      toast.error("Please provide both name and value for the channel");
      return;
    }
    
    const id = Math.max(0, ...channels.map(c => c.id)) + 1;
    setChannels([...channels, { ...newChannel, id }]);
    setNewChannel({ name: "", type: "email", value: "", enabled: true });
    toast.success("Notification channel added successfully");
  };

  // Handler for adding a new notification policy
  const addPolicy = () => {
    if (!newPolicy.name || selectedChannels.length === 0) {
      toast.error("Please provide a name and select at least one channel");
      return;
    }
    
    const id = Math.max(0, ...policies.map(p => p.id)) + 1;
    setPolicies([...policies, { ...newPolicy, channels: selectedChannels, id }]);
    setNewPolicy({ name: "", description: "", severity: "medium", channels: [], enabled: true });
    setSelectedChannels([]);
    toast.success("Alert policy added successfully");
  };

  // Handler for removing a channel
  const removeChannel = (id: number) => {
    setChannels(channels.filter(channel => channel.id !== id));
    toast.success("Channel removed successfully");
  };

  // Handler for removing a policy
  const removePolicy = (id: number) => {
    setPolicies(policies.filter(policy => policy.id !== id));
    toast.success("Policy removed successfully");
  };

  // Helper to get severity badge color
  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case "critical": return "bg-red-500 hover:bg-red-600";
      case "high": return "bg-orange-500 hover:bg-orange-600";
      case "medium": return "bg-yellow-500 hover:bg-yellow-600";
      case "low": return "bg-blue-500 hover:bg-blue-600";
      default: return "bg-slate-500 hover:bg-slate-600";
    }
  };

  // Helper to get status badge color
  const getStatusColor = (status: string) => {
    switch (status) {
      case "delivered": return "bg-green-500 hover:bg-green-600";
      case "partial": return "bg-yellow-500 hover:bg-yellow-600";
      case "failed": return "bg-red-500 hover:bg-red-600";
      default: return "bg-slate-500 hover:bg-slate-600";
    }
  };

  // Handler for test alert
  const sendTestAlert = () => {
    toast.success("Test alert sent successfully", {
      description: "Check your configured notification channels",
      action: {
        label: "View",
        onClick: () => console.log("Viewed test alert")
      }
    });
  };

  return (
    <div className="container mx-auto p-4 space-y-6">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Alert Management</h1>
          <p className="text-muted-foreground">Configure and manage notification policies and channels</p>
        </div>
        <Button onClick={sendTestAlert} className="flex items-center gap-2">
          <BellRing className="h-4 w-4" />
          Send Test Alert
        </Button>
      </div>

      <Tabs defaultValue="policies" className="w-full">
        <TabsList className="grid grid-cols-3 w-full max-w-md">
          <TabsTrigger value="policies">Alert Policies</TabsTrigger>
          <TabsTrigger value="channels">Notification Channels</TabsTrigger>
          <TabsTrigger value="history">Alert History</TabsTrigger>
        </TabsList>
        
        {/* Alert Policies Tab */}
        <TabsContent value="policies" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Create New Alert Policy</CardTitle>
              <CardDescription>Define when and how alerts are triggered and distributed</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label htmlFor="policy-name">Policy Name</Label>
                  <Input 
                    id="policy-name" 
                    placeholder="e.g., Critical Infrastructure Alerts" 
                    value={newPolicy.name}
                    onChange={(e) => setNewPolicy({...newPolicy, name: e.target.value})}
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="policy-severity">Severity Level</Label>
                  <Select 
                    value={newPolicy.severity}
                    onValueChange={(value) => setNewPolicy({...newPolicy, severity: value})}
                  >
                    <SelectTrigger>
                      <SelectValue placeholder="Select severity" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="critical">Critical</SelectItem>
                      <SelectItem value="high">High</SelectItem>
                      <SelectItem value="medium">Medium</SelectItem>
                      <SelectItem value="low">Low</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>
              
              <div className="space-y-2">
                <Label htmlFor="policy-description">Description</Label>
                <Input 
                  id="policy-description" 
                  placeholder="Describe when this policy should trigger alerts"
                  value={newPolicy.description}
                  onChange={(e) => setNewPolicy({...newPolicy, description: e.target.value})}
                />
              </div>
              
              <div className="space-y-2">
                <Label>Notification Channels</Label>
                <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-2">
                  {channels.map((channel) => (
                    <div key={channel.id} className="flex items-center space-x-2">
                      <input
                        type="checkbox"
                        id={`channel-${channel.id}`}
                        checked={selectedChannels.includes(channel.id)}
                        onChange={() => {
                          if (selectedChannels.includes(channel.id)) {
                            setSelectedChannels(selectedChannels.filter(id => id !== channel.id));
                          } else {
                            setSelectedChannels([...selectedChannels, channel.id]);
                          }
                        }}
                        className="rounded border-gray-300 text-primary focus:ring-primary"
                      />
                      <Label htmlFor={`channel-${channel.id}`} className="text-sm cursor-pointer">
                        {channel.name}
                      </Label>
                    </div>
                  ))}
                </div>
              </div>
              
              <div className="flex items-center space-x-2">
                <Switch 
                  checked={newPolicy.enabled}
                  onCheckedChange={(checked) => setNewPolicy({...newPolicy, enabled: checked})}
                  id="policy-enabled" 
                />
                <Label htmlFor="policy-enabled">Enable this policy</Label>
              </div>
            </CardContent>
            <CardFooter>
              <Button 
                onClick={addPolicy} 
                className="flex items-center gap-2"
              >
                <Plus className="h-4 w-4" />
                Create Policy
              </Button>
            </CardFooter>
          </Card>
          
          <Card>
            <CardHeader>
              <CardTitle>Alert Policies</CardTitle>
              <CardDescription>Manage your configured alert policies</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {policies.map((policy) => (
                  <div key={policy.id} className="flex flex-col md:flex-row justify-between items-start md:items-center p-4 border rounded-md">
                    <div className="space-y-1 mb-3 md:mb-0">
                      <div className="flex items-center gap-2">
                        <h3 className="font-medium">{policy.name}</h3>
                        <Badge className={getSeverityColor(policy.severity)}>
                          {policy.severity.charAt(0).toUpperCase() + policy.severity.slice(1)}
                        </Badge>
                        {policy.enabled ? (
                          <Badge variant="outline" className="bg-green-50 text-green-700 border-green-200">
                            Active
                          </Badge>
                        ) : (
                          <Badge variant="outline" className="bg-gray-50 text-gray-500 border-gray-200">
                            Disabled
                          </Badge>
                        )}
                      </div>
                      <p className="text-sm text-muted-foreground">{policy.description}</p>
                      <div className="flex flex-wrap gap-1 mt-1">
                        {policy.channels.map((channelId) => {
                          const channel = channels.find(c => c.id === channelId);
                          if (!channel) return null;
                          return (
                            <Badge key={channelId} variant="outline" className="text-xs">
                              {channel.name}
                            </Badge>
                          );
                        })}
                      </div>
                    </div>
                    <div className="flex items-center gap-2 self-end md:self-center">
                      <Button 
                        variant="outline" 
                        size="sm" 
                        onClick={() => togglePolicyStatus(policy.id)}
                      >
                        {policy.enabled ? (
                          <>
                            <X className="h-4 w-4 mr-1" />
                            Disable
                          </>
                        ) : (
                          <>
                            <Check className="h-4 w-4 mr-1" />
                            Enable
                          </>
                        )}
                      </Button>
                      <Button 
                        variant="destructive" 
                        size="sm"
                        onClick={() => removePolicy(policy.id)}
                      >
                        <Trash2 className="h-4 w-4" />
                      </Button>
                    </div>
                  </div>
                ))}
                {policies.length === 0 && (
                  <div className="text-center py-4 text-muted-foreground">
                    No alert policies configured. Create your first policy above.
                  </div>
                )}
              </div>
            </CardContent>
          </Card>
        </TabsContent>
        
        {/* Notification Channels Tab */}
        <TabsContent value="channels" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Add Notification Channel</CardTitle>
              <CardDescription>Create channels to deliver alerts through various communication methods</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label htmlFor="channel-name">Channel Name</Label>
                  <Input 
                    id="channel-name" 
                    placeholder="e.g., Security Team Email" 
                    value={newChannel.name}
                    onChange={(e) => setNewChannel({...newChannel, name: e.target.value})}
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="channel-type">Channel Type</Label>
                  <Select 
                    value={newChannel.type}
                    onValueChange={(value) => setNewChannel({...newChannel, type: value})}
                  >
                    <SelectTrigger>
                      <SelectValue placeholder="Select type" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="email">Email</SelectItem>
                      <SelectItem value="sms">SMS</SelectItem>
                      <SelectItem value="webhook">Webhook/API</SelectItem>
                      <SelectItem value="app">Mobile App</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>
              
              <div className="space-y-2">
                <Label htmlFor="channel-value">
                  {newChannel.type === "email" && "Email Address"}
                  {newChannel.type === "sms" && "Phone Number"}
                  {newChannel.type === "webhook" && "Webhook URL"}
                  {newChannel.type === "app" && "Device ID"}
                </Label>
                <Input 
                  id="channel-value" 
                  placeholder={
                    newChannel.type === "email" ? "security@example.com" :
                    newChannel.type === "sms" ? "+1 (555) 123-4567" :
                    newChannel.type === "webhook" ? "https://api.example.com/webhooks/alerts" :
                    "device-id-123"
                  }
                  value={newChannel.value}
                  onChange={(e) => setNewChannel({...newChannel, value: e.target.value})}
                />
              </div>
              
              <div className="flex items-center space-x-2">
                <Switch 
                  checked={newChannel.enabled}
                  onCheckedChange={(checked) => setNewChannel({...newChannel, enabled: checked})}
                  id="channel-enabled" 
                />
                <Label htmlFor="channel-enabled">Enable this channel</Label>
              </div>
            </CardContent>
            <CardFooter>
              <Button 
                onClick={addChannel} 
                className="flex items-center gap-2"
              >
                <Plus className="h-4 w-4" />
                Add Channel
              </Button>
            </CardFooter>
          </Card>
          
          <Card>
            <CardHeader>
              <CardTitle>Notification Channels</CardTitle>
              <CardDescription>Manage your notification delivery methods</CardDescription>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Name</TableHead>
                    <TableHead>Type</TableHead>
                    <TableHead>Destination</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead className="text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {channels.map((channel) => (
                    <TableRow key={channel.id}>
                      <TableCell className="font-medium">{channel.name}</TableCell>
                      <TableCell>
                        {channel.type === "email" && <Mail className="h-4 w-4 inline mr-1" />}
                        {channel.type === "sms" && <Smartphone className="h-4 w-4 inline mr-1" />}
                        {channel.type === "webhook" && <MessageSquare className="h-4 w-4 inline mr-1" />}
                        {channel.type === "app" && <Bell className="h-4 w-4 inline mr-1" />}
                        {channel.type.charAt(0).toUpperCase() + channel.type.slice(1)}
                      </TableCell>
                      <TableCell className="font-mono text-xs">{channel.value}</TableCell>
                      <TableCell>
                        {channel.enabled ? (
                          <Badge variant="default" className="bg-green-500 hover:bg-green-600">Active</Badge>
                        ) : (
                          <Badge variant="secondary">Disabled</Badge>
                        )}
                      </TableCell>
                      <TableCell className="text-right">
                        <div className="flex justify-end gap-2">
                          <Button 
                            variant="outline" 
                            size="sm" 
                            onClick={() => toggleChannelStatus(channel.id)}
                          >
                            {channel.enabled ? (
                              <>
                                <X className="h-3 w-3 mr-1" />
                                Disable
                              </>
                            ) : (
                              <>
                                <Check className="h-3 w-3 mr-1" />
                                Enable
                              </>
                            )}
                          </Button>
                          <Button 
                            variant="destructive" 
                            size="sm"
                            onClick={() => removeChannel(channel.id)}
                          >
                            <Trash2 className="h-3 w-3" />
                          </Button>
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
                  {channels.length === 0 && (
                    <TableRow>
                      <TableCell colSpan={5} className="text-center py-4 text-muted-foreground">
                        No notification channels configured
                      </TableCell>
                    </TableRow>
                  )}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>
        
        {/* Alert History Tab */}
        <TabsContent value="history" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Alert History</CardTitle>
              <CardDescription>Review previously sent notifications and their status</CardDescription>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Timestamp</TableHead>
                    <TableHead>Policy</TableHead>
                    <TableHead>Message</TableHead>
                    <TableHead>Severity</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>Recipients</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {history.map((alert) => (
                    <TableRow key={alert.id}>
                      <TableCell className="whitespace-nowrap text-xs">
                        {new Date(alert.timestamp).toLocaleString()}
                      </TableCell>
                      <TableCell>{alert.policy}</TableCell>
                      <TableCell className="max-w-xs truncate" title={alert.message}>
                        {alert.message}
                      </TableCell>
                      <TableCell>
                        <Badge className={getSeverityColor(alert.severity)}>
                          {alert.severity.charAt(0).toUpperCase() + alert.severity.slice(1)}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <Badge className={getStatusColor(alert.status)}>
                          {alert.status.charAt(0).toUpperCase() + alert.status.slice(1)}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <div className="flex flex-wrap gap-1">
                          {alert.sentTo.map((recipient, index) => (
                            <Badge key={index} variant="outline" className="text-xs">
                              {recipient}
                            </Badge>
                          ))}
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </CardContent>
            <CardFooter className="flex justify-between">
              <Button variant="outline" size="sm" disabled>Previous</Button>
              <div className="text-sm text-muted-foreground">Showing 5 of 5 alerts</div>
              <Button variant="outline" size="sm" disabled>Next</Button>
            </CardFooter>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
};

export default AlertManagement;
