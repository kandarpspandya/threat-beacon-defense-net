
import { useState, useEffect } from "react";
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend } from "recharts";
import { networkService } from "@/services/networkService";
import { NetworkEvent } from "@/types/network";
import { Skeleton } from "@/components/ui/skeleton";
import { RealTimeStatus } from "./RealTimeStatus";

interface TrafficData {
  hour: string;
  incoming: number;
  outgoing: number;
}

export function TrafficOverTimeChart() {
  const [data, setData] = useState<TrafficData[]>([]);
  const [loading, setLoading] = useState(true);
  const [status, setStatus] = useState<'connected' | 'connecting' | 'disconnected' | 'error'>(
    networkService.status
  );

  useEffect(() => {
    // Initialize with 24 hours of empty data
    const initialData: TrafficData[] = Array.from({ length: 24 }, (_, i) => ({
      hour: `${i}:00`,
      incoming: 0,
      outgoing: 0
    }));
    
    setData(initialData);
    
    let incomingBuffer = 0;
    let outgoingBuffer = 0;
    let lastUpdateTime = Date.now();
    const UPDATE_INTERVAL = 10000; // Update chart every 10 seconds
    
    // Handle incoming network events
    const handleNetworkEvent = (event: NetworkEvent) => {
      const currentHour = new Date().getHours();
      
      // Determine if traffic is incoming or outgoing
      // Simple simulation for demo purposes
      const isOutgoing = Math.random() > 0.6; // 40% outgoing, 60% incoming
      
      if (isOutgoing) {
        outgoingBuffer++;
      } else {
        incomingBuffer++;
      }
      
      // Update the chart periodically rather than on every event
      const now = Date.now();
      if (now - lastUpdateTime > UPDATE_INTERVAL) {
        updateChartData(currentHour, incomingBuffer, outgoingBuffer);
        incomingBuffer = 0;
        outgoingBuffer = 0;
        lastUpdateTime = now;
      }
    };
    
    // Update the chart data with traffic counts
    const updateChartData = (currentHour: number, incoming: number, outgoing: number) => {
      setData(prevData => {
        const newData = [...prevData];
        const hourIndex = newData.findIndex(item => item.hour === `${currentHour}:00`);
        
        if (hourIndex !== -1) {
          newData[hourIndex] = {
            ...newData[hourIndex],
            incoming: newData[hourIndex].incoming + incoming,
            outgoing: newData[hourIndex].outgoing + outgoing
          };
        }
        
        if (loading) {
          setLoading(false);
        }
        
        return newData;
      });
    };
    
    // Pre-populate with some initial data
    setData(
      Array.from({ length: 24 }, (_, i) => {
        // More activity during work hours (9-17)
        const hourFactor = (i >= 9 && i <= 17) ? 4 : (i >= 22 || i <= 5) ? 0.5 : 1;
        return {
          hour: `${i}:00`,
          incoming: Math.floor(Math.random() * 300 * hourFactor) + 50,
          outgoing: Math.floor(Math.random() * 200 * hourFactor) + 20
        };
      })
    );
    
    setLoading(false);
    
    // Subscribe to network events
    const unsubscribe = networkService.subscribe(handleNetworkEvent);
    
    // Check connection status periodically
    const statusInterval = setInterval(() => {
      setStatus(networkService.status);
    }, 3000);
    
    return () => {
      unsubscribe();
      clearInterval(statusInterval);
    };
  }, [loading]);

  if (loading) {
    return <Skeleton className="h-[300px] w-full" />;
  }

  return (
    <div className="relative h-[300px] w-full">
      <div className="absolute top-2 right-2 z-10">
        <RealTimeStatus status={status} />
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
            dataKey="hour" 
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
            dataKey="incoming" 
            stackId="1"
            stroke="#2196F3" 
            fill="#2196F3" 
            fillOpacity={0.3}
          />
          <Area 
            type="monotone" 
            dataKey="outgoing" 
            stackId="1"
            stroke="#64FFDA" 
            fill="#64FFDA" 
            fillOpacity={0.3}
          />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}
