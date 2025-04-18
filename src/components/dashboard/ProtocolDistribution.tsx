
import { useState, useEffect } from "react";
import { PieChart, Pie, Cell, ResponsiveContainer, Legend, Tooltip } from "recharts";
import { networkService } from "@/services/networkService";
import { NetworkEvent, ProtocolData } from "@/types/network";
import { Skeleton } from "@/components/ui/skeleton";

export function ProtocolDistribution() {
  const [data, setData] = useState<ProtocolData[]>([
    { name: "HTTP/S", value: 42, color: "#64FFDA" },
    { name: "DNS", value: 28, color: "#FFC107" },
    { name: "SSH", value: 15, color: "#FF6B6B" },
    { name: "SMTP", value: 10, color: "#2196F3" },
    { name: "Other", value: 5, color: "#9c27b0" },
  ]);
  
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // Protocol counters
    const protocolCounts: Record<string, number> = {
      'http': 0,
      'https': 0,
      'ssh': 0,
      'dns': 0,
      'smtp': 0,
      'ftp': 0,
      'telnet': 0,
      'other': 0
    };
    
    // Map ports to protocols
    const portToProtocol: Record<number, string> = {
      21: 'ftp',
      22: 'ssh',
      23: 'telnet',
      25: 'smtp',
      53: 'dns',
      80: 'http',
      110: 'email',
      143: 'email',
      443: 'https',
      465: 'email',
      587: 'email',
      993: 'email',
      995: 'email',
      3306: 'database',
      8080: 'http'
    };
    
    // Handle incoming network events
    const handleNetworkEvent = (event: NetworkEvent) => {
      // Process protocol information from the event
      if (event.tags?.includes('http')) {
        protocolCounts.http += 1;
      } else if (event.tags?.includes('https')) {
        protocolCounts.https += 1;
      } else if (event.tags?.includes('ssh')) {
        protocolCounts.ssh += 1;
      } else if (event.tags?.includes('dns')) {
        protocolCounts.dns += 1;
      } else if (event.tags?.includes('smtp')) {
        protocolCounts.smtp += 1;
      } else if (event.tags?.includes('ftp')) {
        protocolCounts.ftp += 1;
      } else if (event.tags?.includes('telnet')) {
        protocolCounts.telnet += 1;
      } else if (event.ports && event.ports.length > 0) {
        // Try to identify protocol by port
        const knownPort = event.ports.find(port => portToProtocol[port]);
        if (knownPort) {
          const protocol = portToProtocol[knownPort];
          protocolCounts[protocol] = (protocolCounts[protocol] || 0) + 1;
        } else {
          protocolCounts.other += 1;
        }
      } else {
        protocolCounts.other += 1;
      }
      
      // Update the chart data
      updateChartData(protocolCounts);
    };
    
    // Convert raw counts to percentage-based data for the pie chart
    const updateChartData = (counts: Record<string, number>) => {
      const total = Object.values(counts).reduce((sum, count) => sum + count, 0);
      
      if (total === 0) return;
      
      // Calculate percentages and create chart data
      const newData: ProtocolData[] = [
        { 
          name: "HTTP/S", 
          value: Math.round(((counts.http + counts.https) / total) * 100), 
          color: "#64FFDA" 
        },
        { 
          name: "DNS", 
          value: Math.round((counts.dns / total) * 100), 
          color: "#FFC107" 
        },
        { 
          name: "SSH", 
          value: Math.round((counts.ssh / total) * 100), 
          color: "#FF6B6B" 
        },
        { 
          name: "SMTP", 
          value: Math.round((counts.smtp / total) * 100), 
          color: "#2196F3" 
        },
        { 
          name: "Other", 
          value: Math.round(((counts.other + counts.ftp + counts.telnet) / total) * 100), 
          color: "#9c27b0" 
        },
      ];
      
      setData(newData);
      if (loading) {
        setLoading(false);
      }
    };
    
    // Subscribe to network events
    const unsubscribe = networkService.subscribe(handleNetworkEvent);
    
    // Set a timeout to show initial data even without events
    const timeout = setTimeout(() => {
      if (loading) {
        setLoading(false);
      }
    }, 3000);
    
    return () => {
      unsubscribe();
      clearTimeout(timeout);
    };
  }, [loading]);

  if (loading) {
    return <Skeleton className="h-[250px] w-full" />;
  }

  return (
    <div className="h-[250px] w-full">
      <ResponsiveContainer width="100%" height="100%">
        <PieChart>
          <Pie
            data={data}
            cx="50%"
            cy="50%"
            labelLine={false}
            outerRadius={80}
            innerRadius={40}
            paddingAngle={3}
            dataKey="value"
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
          <Legend 
            layout="vertical" 
            verticalAlign="middle" 
            align="right"
            wrapperStyle={{
              paddingLeft: "10px",
            }}
          />
        </PieChart>
      </ResponsiveContainer>
    </div>
  );
}
