
import { useEffect, useState } from "react";
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend } from "recharts";
import { Card } from "@/components/ui/card";

// Mock data generation
const generateChartData = (period: string) => {
  // Different data sets based on the time period
  const periods: Record<string, number> = {
    "1h": 12,
    "24h": 24,
    "7d": 7,
    "30d": 30
  };

  const dataPoints = periods[period] || 24;
  const multiplier = period === "1h" ? 5 : period === "7d" ? 0.25 : period === "30d" ? 0.1 : 1;
  
  return Array.from({ length: dataPoints }, (_, i) => {
    const baseTraffic = 100 + Math.random() * 50;
    const baseMalicious = Math.max(5 + Math.random() * 20, 0);
    const baseBlocked = Math.max(baseMalicious * 0.8, 0);
    
    return {
      name: period === "1h" ? `${i * 5}m` : 
            period === "7d" ? `Day ${i + 1}` : 
            period === "30d" ? `Day ${i + 1}` : 
            `${i}h`,
      "Normal Traffic": Math.round(baseTraffic * multiplier),
      "Suspicious Activity": Math.round((baseMalicious + (i % 3 === 0 ? 15 : 0)) * multiplier),
      "Blocked Threats": Math.round(baseBlocked * multiplier),
    };
  });
};

interface NetworkActivityChartProps {
  period: string;
}

export function NetworkActivityChart({ period }: NetworkActivityChartProps) {
  const [data, setData] = useState(generateChartData(period));

  useEffect(() => {
    setData(generateChartData(period));
  }, [period]);

  return (
    <div className="h-[300px] w-full">
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
            activeDot={{ r: 6 }}
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
