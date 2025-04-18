
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { TrafficOverTimeChart } from "@/components/dashboard/TrafficOverTimeChart";
import { ProtocolDistribution } from "@/components/dashboard/ProtocolDistribution";
import { TrafficSourcesChart } from "@/components/dashboard/TrafficSourcesChart";
import { TopDomainsChart } from "@/components/dashboard/TopDomainsChart";

export const OverviewTab = () => {
  return (
    <div className="space-y-4">
      <div className="grid gap-4 md:grid-cols-2">
        {/* Traffic Over Time Chart */}
        <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm md:col-span-2">
          <CardHeader>
            <CardTitle>Traffic Volume Over Time</CardTitle>
            <CardDescription>
              Incoming and outgoing network traffic
            </CardDescription>
          </CardHeader>
          <CardContent>
            <TrafficOverTimeChart />
          </CardContent>
        </Card>
        
        {/* Protocol Distribution Chart */}
        <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm">
          <CardHeader>
            <CardTitle>Protocol Distribution</CardTitle>
            <CardDescription>
              Traffic breakdown by protocol
            </CardDescription>
          </CardHeader>
          <CardContent>
            <ProtocolDistribution />
          </CardContent>
        </Card>
        
        {/* Source Distribution Chart */}
        <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm">
          <CardHeader>
            <CardTitle>Traffic Source</CardTitle>
            <CardDescription>
              Internal vs. external traffic
            </CardDescription>
          </CardHeader>
          <CardContent>
            <TrafficSourcesChart />
          </CardContent>
        </Card>
      </div>
      
      {/* Top Domains */}
      <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm">
        <CardHeader>
          <CardTitle>Top Domains</CardTitle>
          <CardDescription>
            Most frequently accessed domains
          </CardDescription>
        </CardHeader>
        <CardContent>
          <TopDomainsChart />
        </CardContent>
      </Card>
    </div>
  );
};
