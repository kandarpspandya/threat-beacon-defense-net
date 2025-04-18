
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { TrafficOverTimeChart } from "@/components/dashboard/TrafficOverTimeChart";

export const TrendsTab = () => {
  return (
    <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm">
      <CardHeader>
        <CardTitle>Traffic Trends</CardTitle>
        <CardDescription>
          Historical traffic patterns and anomalies
        </CardDescription>
      </CardHeader>
      <CardContent className="h-[500px]">
        <TrafficOverTimeChart />
      </CardContent>
    </Card>
  );
};
