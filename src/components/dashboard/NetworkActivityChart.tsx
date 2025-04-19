
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend } from "recharts";
import { useNetworkData } from "@/hooks/useNetworkData";
import { Skeleton } from "@/components/ui/skeleton";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { AlertTriangle, Signal, Wifi, WifiOff, Info } from "lucide-react";
import { Badge } from "@/components/ui/badge";

interface NetworkActivityChartProps {
  period: string;
}

export function NetworkActivityChart({ period }: NetworkActivityChartProps) {
  const { data, error, isConnected, connectionStatus } = useNetworkData(period);

  // Display connection status
  const renderConnectionStatus = () => {
    if (connectionStatus === 'connecting') {
      return (
        <Badge variant="outline" className="ml-2 bg-yellow-500/10 text-yellow-500 border-yellow-500/20">
          <Signal className="w-3 h-3 mr-1 animate-pulse" />
          Connecting...
        </Badge>
      );
    } else if (connectionStatus === 'connected') {
      return (
        <Badge variant="outline" className="ml-2 bg-green-500/10 text-green-500 border-green-500/20">
          <Wifi className="w-3 h-3 mr-1" />
          Live
        </Badge>
      );
    } else if (connectionStatus === 'error') {
      return (
        <Badge variant="outline" className="ml-2 bg-red-500/10 text-red-500 border-red-500/20">
          <WifiOff className="w-3 h-3 mr-1" />
          Error
        </Badge>
      );
    } else {
      return (
        <Badge variant="outline" className="ml-2 bg-gray-500/10 text-gray-500 border-gray-500/20">
          <WifiOff className="w-3 h-3 mr-1" />
          Disconnected
        </Badge>
      );
    }
  };

  if (error) {
    return (
      <Alert variant="destructive">
        <AlertTriangle className="h-4 w-4" />
        <AlertTitle className="flex items-center">
          Connection Error {renderConnectionStatus()}
        </AlertTitle>
        <AlertDescription className="space-y-2">
          <p>{error}</p>
          <p className="text-xs">
            <Info className="inline-block h-3 w-3 mr-1" />
            Using simulated data. In production, you can enable system permissions to use TShark 
            or other native packet capture tools for real network analysis.
          </p>
        </AlertDescription>
      </Alert>
    );
  }

  if (!data.length) {
    return (
      <div className="relative h-[300px] w-full">
        <div className="absolute top-2 right-2 z-10">
          {renderConnectionStatus()}
        </div>
        <Skeleton className="w-full h-full" />
      </div>
    );
  }

  return (
    <div className="relative h-[300px] w-full">
      <div className="absolute top-2 right-2 z-10">
        {renderConnectionStatus()}
      </div>
      <ResponsiveContainer width="100%" height="100%">
        <AreaChart
          data={data}
          margin={{
            top: 10,
            right: 30,
            left: 0,
            bottom: 0,
          }}
        >
          <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.1)" />
          <XAxis 
            dataKey="name" 
            stroke="rgba(255,255,255,0.5)"
            tickLine={false}
          />
          <YAxis 
            stroke="rgba(255,255,255,0.5)"
            tickLine={false}
            axisLine={false}
          />
          <Tooltip 
            contentStyle={{ 
              backgroundColor: "rgba(23, 42, 69, 0.9)", 
              borderColor: "#64FFDA",
              borderRadius: "6px",
              color: "#fff"
            }} 
          />
          <Legend />
          <Area 
            type="monotone" 
            dataKey="Normal Traffic" 
            stackId="1"
            stroke="#2196F3" 
            fill="#2196F3" 
            fillOpacity={0.3}
          />
          <Area 
            type="monotone" 
            dataKey="Suspicious Activity" 
            stackId="1"
            stroke="#FFC107" 
            fill="#FFC107" 
            fillOpacity={0.3}
          />
          <Area 
            type="monotone" 
            dataKey="Blocked Threats" 
            stackId="1"
            stroke="#FF6B6B" 
            fill="#FF6B6B" 
            fillOpacity={0.3}
          />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}
