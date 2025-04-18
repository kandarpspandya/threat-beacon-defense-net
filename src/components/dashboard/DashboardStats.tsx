
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { AlertTriangle, Shield, Activity, Server } from "lucide-react";

interface StatsProps {
  activeThreats: number;
  blockedAttacks: number;
  trafficAnalyzed: string;
  systemUptime: string;
}

export const DashboardStats = ({ activeThreats, blockedAttacks, trafficAnalyzed, systemUptime }: StatsProps) => {
  return (
    <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
      <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm">
        <CardHeader className="flex flex-row items-center justify-between pb-2">
          <CardTitle className="text-sm font-medium">Active Threats</CardTitle>
          <AlertTriangle className="h-4 w-4 text-sentinel-danger" />
        </CardHeader>
        <CardContent>
          <div className="text-2xl font-bold text-sentinel-danger">{activeThreats}</div>
          <p className="text-xs text-muted-foreground">
            +2 in the last 24 hours
          </p>
        </CardContent>
      </Card>
      
      <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm">
        <CardHeader className="flex flex-row items-center justify-between pb-2">
          <CardTitle className="text-sm font-medium">Blocked Attacks</CardTitle>
          <Shield className="h-4 w-4 text-sentinel-success" />
        </CardHeader>
        <CardContent>
          <div className="text-2xl font-bold">{blockedAttacks}</div>
          <p className="text-xs text-muted-foreground">
            +43 in the last 24 hours
          </p>
        </CardContent>
      </Card>
      
      <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm">
        <CardHeader className="flex flex-row items-center justify-between pb-2">
          <CardTitle className="text-sm font-medium">Traffic Analyzed</CardTitle>
          <Activity className="h-4 w-4 text-sentinel-info" />
        </CardHeader>
        <CardContent>
          <div className="text-2xl font-bold">{trafficAnalyzed}</div>
          <p className="text-xs text-muted-foreground">
            In the last 24 hours
          </p>
        </CardContent>
      </Card>
      
      <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm">
        <CardHeader className="flex flex-row items-center justify-between pb-2">
          <CardTitle className="text-sm font-medium">System Uptime</CardTitle>
          <Server className="h-4 w-4 text-sentinel-accent" />
        </CardHeader>
        <CardContent>
          <div className="text-2xl font-bold">{systemUptime}</div>
          <p className="text-xs text-muted-foreground">
            30-day average
          </p>
        </CardContent>
      </Card>
    </div>
  );
};
