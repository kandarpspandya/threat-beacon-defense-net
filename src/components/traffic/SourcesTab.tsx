
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { TrafficSourcesChart } from "@/components/dashboard/TrafficSourcesChart";

export const SourcesTab = () => {
  return (
    <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm">
      <CardHeader>
        <CardTitle>Traffic Sources</CardTitle>
        <CardDescription>
          Analysis of traffic origins and destinations
        </CardDescription>
      </CardHeader>
      <CardContent className="h-[500px]">
        <TrafficSourcesChart />
      </CardContent>
    </Card>
  );
};
