
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend } from "recharts";
import { useNetworkData } from "@/hooks/useNetworkData";
import { Skeleton } from "@/components/ui/skeleton";

interface NetworkActivityChartProps {
  period: string;
}

export function NetworkActivityChart({ period }: NetworkActivityChartProps) {
  const { data, error } = useNetworkData(period);

  if (error) {
    return (
      <div className="h-[300px] w-full flex items-center justify-center text-destructive">
        {error}
      </div>
    );
  }

  if (!data.length) {
    return (
      <div className="h-[300px] w-full">
        <Skeleton className="w-full h-full" />
      </div>
    );
  }

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
