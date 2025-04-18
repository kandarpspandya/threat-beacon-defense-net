
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { FilterX, FileText, Shield, BarChart2 } from "lucide-react";

export const StatsCards = () => {
  return (
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
  );
};
