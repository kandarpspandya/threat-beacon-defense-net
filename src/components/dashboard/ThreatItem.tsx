
import { Clock, ArrowRight, Shield } from "lucide-react";
import { cn } from "@/lib/utils";
import { format } from "date-fns";

interface Threat {
  id: number;
  type: string;
  source: string;
  destination: string;
  severity: "high" | "medium" | "low";
  timestamp: string;
  status: "blocked" | "monitoring" | "investigating";
}

interface ThreatItemProps {
  threat: Threat;
}

export function ThreatItem({ threat }: ThreatItemProps) {
  const getSeverityColor = (severity: Threat["severity"]) => {
    switch (severity) {
      case "high":
        return "bg-sentinel-danger/10 text-sentinel-danger border-sentinel-danger/30";
      case "medium":
        return "bg-sentinel-warning/10 text-sentinel-warning border-sentinel-warning/30";
      case "low":
        return "bg-sentinel-info/10 text-sentinel-info border-sentinel-info/30";
      default:
        return "bg-muted text-muted-foreground";
    }
  };

  const getStatusColor = (status: Threat["status"]) => {
    switch (status) {
      case "blocked":
        return "text-sentinel-success";
      case "monitoring":
        return "text-sentinel-info";
      case "investigating":
        return "text-sentinel-warning";
      default:
        return "text-muted-foreground";
    }
  };

  // Format the timestamp
  const formattedTime = format(new Date(threat.timestamp), "h:mm a");

  return (
    <div className="rounded-lg border border-sentinel-light/10 p-3 bg-card/30 hover:bg-card/50 transition-colors">
      <div className="flex flex-col space-y-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center">
            <span
              className={cn(
                "mr-2 rounded-md px-2 py-1 text-xs font-medium",
                getSeverityColor(threat.severity)
              )}
            >
              {threat.type}
            </span>
          </div>
          <div className="flex items-center text-xs text-muted-foreground">
            <Clock className="mr-1 h-3 w-3" />
            {formattedTime}
          </div>
        </div>
        
        <div className="flex items-center justify-between">
          <div className="flex items-center text-sm">
            <span className="font-mono">{threat.source}</span>
            <ArrowRight className="mx-2 h-3 w-3" />
            <span className="font-mono">{threat.destination}</span>
          </div>
          <div className={cn("flex items-center text-xs", getStatusColor(threat.status))}>
            {threat.status === "blocked" && <Shield className="mr-1 h-3 w-3" />}
            <span className="capitalize">
              {threat.status}
            </span>
          </div>
        </div>
      </div>
    </div>
  );
}
