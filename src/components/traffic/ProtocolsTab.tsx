
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { ProtocolDistribution } from "@/components/dashboard/ProtocolDistribution";

export const ProtocolsTab = () => {
  return (
    <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm">
      <CardHeader>
        <CardTitle>Protocol Analysis</CardTitle>
        <CardDescription>
          Detailed breakdown by network protocol
        </CardDescription>
      </CardHeader>
      <CardContent className="h-[500px] flex items-center justify-center">
        <div className="w-full max-w-2xl mx-auto">
          <ProtocolDistribution />
        </div>
      </CardContent>
    </Card>
  );
};
