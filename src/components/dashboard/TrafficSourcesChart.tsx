
import { useState, useEffect } from "react";
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from "recharts";
import { networkService } from "@/services/networkService";
import { NetworkEvent, TrafficSource } from "@/types/network";
import { Skeleton } from "@/components/ui/skeleton";
import { RealTimeStatus } from "./RealTimeStatus";

export function TrafficSourcesChart() {
  const [data, setData] = useState<TrafficSource[]>([
    { name: "Internal", value: 65, color: "#64FFDA" },
    { name: "External", value: 35, color: "#FF6B6B" },
  ]);
  
  const [loading, setLoading] = useState(true);
  const [status, setStatus] = useState<'connected' | 'connecting' | 'disconnected' | 'error'>(
    networkService.status
  );

  useEffect(() => {
    // Traffic source counters
    let internalCount = 0;
    let externalCount = 0;
    
    // Handle incoming network events
    const handleNetworkEvent = (event: NetworkEvent) => {
      // Determine if traffic is internal or external
      // Simple heuristic: 10.x.x.x, 172.16-31.x.x, and 192.168.x.x are internal
      const ip = event.ip;
      const isInternal = 
        ip.startsWith('10.') || 
        ip.startsWith('192.168.') || 
        (ip.startsWith('172.') && 
         parseInt(ip.split('.')[1], 10) >= 16 && 
         parseInt(ip.split('.')[1], 10) <= 31);
      
      if (isInternal) {
        internalCount++;
      } else {
        externalCount++;
      }
      
      // Update the chart data
      updateChartData(internalCount, externalCount);
    };
    
    // Convert raw counts to percentage-based data for the pie chart
    const updateChartData = (internal: number, external: number) => {
      const total = internal + external;
      
      if (total === 0) return;
      
      // Calculate percentages and create chart data
      const newData: TrafficSource[] = [
        { 
          name: "Internal", 
          value: Math.round((internal / total) * 100), 
          color: "#64FFDA" 
        },
        { 
          name: "External", 
          value: Math.round((external / total) * 100), 
          color: "#FF6B6B" 
        }
      ];
      
      setData(newData);
      if (loading) {
        setLoading(false);
      }
    };
    
    // Subscribe to network events
    const unsubscribe = networkService.subscribe(handleNetworkEvent);
    
    // Check connection status periodically
    const statusInterval = setInterval(() => {
      setStatus(networkService.status);
    }, 3000);
    
    // Set a timeout to show initial data even without events
    const timeout = setTimeout(() => {
      if (loading) {
        setLoading(false);
      }
    }, 3000);
    
    return () => {
      unsubscribe();
      clearInterval(statusInterval);
      clearTimeout(timeout);
    };
  }, [loading]);

  if (loading) {
    return <Skeleton className="h-[250px] w-full" />;
  }

  return (
    <div className="relative h-[250px] w-full">
      <div className="absolute top-2 right-2 z-10">
        <RealTimeStatus status={status} />
      </div>
      <ResponsiveContainer width="100%" height="100%">
        <PieChart>
          <Pie
            data={data}
            cx="50%"
            cy="50%"
            outerRadius={80}
            fill="#8884d8"
            dataKey="value"
            label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
          >
            {data.map((entry, index) => (
              <Cell key={`cell-${index}`} fill={entry.color} />
            ))}
          </Pie>
          <Tooltip 
            contentStyle={{ 
              backgroundColor: "rgba(23, 42, 69, 0.9)", 
              borderColor: "#64FFDA",
              borderRadius: "6px",
              color: "#fff"
            }}
            formatter={(value: number) => [`${value}%`, "Percentage"]}
          />
        </PieChart>
      </ResponsiveContainer>
    </div>
  );
}
