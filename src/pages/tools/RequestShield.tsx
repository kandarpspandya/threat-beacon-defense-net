
import { FileText, ArrowUpRight, Shield, Globe, AlertTriangle } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { StatsCards } from "@/components/requestshield/StatsCards";
import { ApiTrafficChart } from "@/components/requestshield/ApiTrafficChart";
import { OverviewTab } from "@/components/requestshield/OverviewTab";
import { PlaceholderTab } from "@/components/requestshield/PlaceholderTab";

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

      <StatsCards />
      <ApiTrafficChart />

      <Tabs defaultValue="overview" className="space-y-4">
        <TabsList className="grid grid-cols-4 md:w-[400px] bg-background/50">
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="endpoints">Endpoints</TabsTrigger>
          <TabsTrigger value="threats">Threats</TabsTrigger>
          <TabsTrigger value="rules">Rules</TabsTrigger>
        </TabsList>
        
        <TabsContent value="overview">
          <OverviewTab />
        </TabsContent>
        
        <TabsContent value="endpoints">
          <PlaceholderTab 
            title="API Endpoints"
            description="View monitored API endpoints, traffic patterns, and security posture."
            icon={<Globe />}
            buttonLabel="Configure Endpoints"
          />
        </TabsContent>
        
        <TabsContent value="threats">
          <PlaceholderTab 
            title="Detected Threats"
            description="Analyze blocked malicious requests and attack patterns targeting your APIs."
            icon={<AlertTriangle />}
            buttonLabel="View Threat Log"
          />
        </TabsContent>
        
        <TabsContent value="rules">
          <PlaceholderTab 
            title="Protection Rules"
            description="Configure API protection rules and security policies."
            icon={<FileText />}
            buttonLabel="Manage Rules"
          />
        </TabsContent>
      </Tabs>
    </div>
  );
};

export default RequestShield;
