import { useState } from "react";
import { FileText, Shield, Eye, RefreshCw, Upload, ArrowUpDown, Check, X, Filter, Download, Code, Info } from "lucide-react";
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Badge } from "@/components/ui/badge";
import { Switch } from "@/components/ui/switch";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { toast } from "sonner";
import { Table, TableBody, TableCaption, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Textarea } from "@/components/ui/textarea";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";

// Mock data for Snort rules
const snortRulesMock = [
  {
    id: 1,
    sid: 1000001,
    name: "SQL Injection Attempt",
    description: "Detects common SQL injection patterns in HTTP requests",
    content: 'alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"SQL Injection Attempt"; flow:to_server,established; content:"SELECT"; nocase; content:"FROM"; distance:0; nocase; content:"WHERE"; distance:0; nocase; classtype:web-application-attack; sid:1000001; rev:1;)',
    enabled: true,
    category: "web-application-attack",
    reference: "CVE-1999-0001",
    updated: "2025-03-15T14:30:00.000Z"
  },
  {
    id: 2,
    sid: 1000002,
    name: "Potential XSS Attack",
    description: "Detects cross-site scripting attempts in URI parameters",
    content: 'alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"Potential XSS Attack"; flow:to_server,established; content:"<script>"; nocase; pcre:"/<script.*?>.*?<\/script>/i"; classtype:web-application-attack; sid:1000002; rev:2;)',
    enabled: true,
    category: "web-application-attack",
    reference: "CVE-2007-5243",
    updated: "2025-03-18T11:20:00.000Z"
  },
  {
    id: 3,
    sid: 1000003,
    name: "Suspicious PowerShell Command",
    description: "Detects obfuscated or suspicious PowerShell commands",
    content: 'alert tcp $HOME_NET any -> $HOME_NET any (msg:"Suspicious PowerShell Command"; content:"powershell"; nocase; content:"-enc"; distance:0; nocase; content:"-exec"; distance:0; nocase; classtype:trojan-activity; sid:1000003; rev:1;)',
    enabled: true,
    category: "trojan-activity",
    reference: "",
    updated: "2025-03-22T09:45:00.000Z"
  },
  {
    id: 4,
    sid: 1000004,
    name: "SMB Remote Code Execution Attempt",
    description: "Detects attempts to exploit SMB vulnerabilities for RCE",
    content: 'alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"SMB Remote Code Execution Attempt"; content:"|FF|SMB"; depth:4; pcre:"/.*\\\\IPC\\$/"; classtype:attempted-admin; sid:1000004; rev:3;)',
    enabled: true,
    category: "attempted-admin",
    reference: "CVE-2017-0144",
    updated: "2025-02-28T16:15:00.000Z"
  },
  {
    id: 5,
    sid: 1000005,
    name: "DNS Zone Transfer",
    description: "Detects DNS zone transfer attempts (AXFR)",
    content: 'alert udp $EXTERNAL_NET any -> $HOME_NET 53 (msg:"DNS Zone Transfer Attempt"; content:"|00 00 FC|"; offset:14; depth:3; classtype:attempted-recon; sid:1000005; rev:1;)',
    enabled: false,
    category: "attempted-recon",
    reference: "CVE-1999-0532",
    updated: "2025-03-05T13:30:00.000Z"
  }
];

const SignatureDetection = () => {
  const [rules, setRules] = useState(snortRulesMock);
  const [searchTerm, setSearchTerm] = useState("");

  // Filter function for rules based on search
  const filteredRules = rules.filter(rule => {
    return (
      searchTerm === "" || 
      rule.name.toLowerCase().includes(searchTerm.toLowerCase()) || 
      rule.description.toLowerCase().includes(searchTerm.toLowerCase()) ||
      rule.content.toLowerCase().includes(searchTerm.toLowerCase()) ||
      rule.sid.toString().includes(searchTerm)
    );
  });

  // Handler for toggling rule enabled status
  const toggleRuleStatus = (id: number) => {
    setRules(
      rules.map(rule => 
        rule.id === id ? { ...rule, enabled: !rule.enabled } : rule
      )
    );
    
    const rule = rules.find(r => r.id === id);
    toast.success(`Rule ${!rule?.enabled ? "enabled" : "disabled"}`, {
      description: `${rule?.name} has been ${!rule?.enabled ? "enabled" : "disabled"}`
    });
  };

  return (
    <div className="container mx-auto p-4 space-y-6">
      <div className="flex flex-col md:flex-row justify-between md:items-center gap-4">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Signature Detection</h1>
          <p className="text-muted-foreground">
            Manage and monitor Snort network intrusion detection rules
          </p>
        </div>
      </div>

      {/* Search and Filters */}
      <div className="flex flex-col sm:flex-row gap-4">
        <div className="relative flex-1">
          <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
          <Input
            type="search"
            placeholder="Search rules, alerts, or IP addresses..."
            className="pl-8"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
          />
        </div>
      </div>
      
      <Card>
        <CardHeader>
          <CardTitle>Snort Rules</CardTitle>
          <CardDescription>
            Security rules for signature-based detection
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="w-[80px]">SID</TableHead>
                <TableHead>Rule Name</TableHead>
                <TableHead>Category</TableHead>
                <TableHead>Reference</TableHead>
                <TableHead>Updated</TableHead>
                <TableHead>Status</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {filteredRules.map((rule) => (
                <TableRow key={rule.id}>
                  <TableCell className="font-mono text-xs">{rule.sid}</TableCell>
                  <TableCell>
                    <div className="font-medium">{rule.name}</div>
                    <div className="text-xs text-muted-foreground">{rule.description}</div>
                  </TableCell>
                  <TableCell>
                    <Badge variant="outline" className="capitalize">
                      {rule.category.replace(/-/g, ' ')}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    {rule.reference ? (
                      <span className="text-xs font-mono">{rule.reference}</span>
                    ) : (
                      <span className="text-xs text-muted-foreground">-</span>
                    )}
                  </TableCell>
                  <TableCell className="text-sm">
                    {new Date(rule.updated).toLocaleDateString()}
                  </TableCell>
                  <TableCell>
                    {rule.enabled ? (
                      <Badge className="bg-green-500 hover:bg-green-600">Enabled</Badge>
                    ) : (
                      <Badge variant="outline">Disabled</Badge>
                    )}
                  </TableCell>
                  <TableCell className="text-right">
                    <div className="flex justify-end gap-2">
                      <Button 
                        variant="ghost" 
                        size="sm"
                        onClick={() => {
                          toast.info("Rule Content", {
                            description: <div className="font-mono text-xs break-all">{rule.content}</div>
                          });
                        }}
                      >
                        <Code className="h-4 w-4" />
                      </Button>
                      <Button 
                        variant={rule.enabled ? "destructive" : "default"}
                        size="sm"
                        onClick={() => toggleRuleStatus(rule.id)}
                      >
                        {rule.enabled ? (
                          <X className="h-4 w-4" />
                        ) : (
                          <Check className="h-4 w-4" />
                        )}
                      </Button>
                    </div>
                  </TableCell>
                </TableRow>
              ))}
              {filteredRules.length === 0 && (
                <TableRow>
                  <TableCell colSpan={7} className="text-center py-6 text-muted-foreground">
                    No rules match your search criteria
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  );
};

export default SignatureDetection;

function Search(props: any) {
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
      <circle cx="11" cy="11" r="8" />
      <line x1="21" x2="16.65" y1="21" y2="16.65" />
    </svg>
  );
}
