
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend } from "recharts";

const data = [
  {
    name: "Malware",
    high: 12,
    medium: 15,
    low: 8,
  },
  {
    name: "Network",
    high: 5,
    medium: 18,
    low: 22,
  },
  {
    name: "Web",
    high: 9,
    medium: 12,
    low: 14,
  },
  {
    name: "Auth",
    high: 7,
    medium: 10,
    low: 12,
  },
];

export function AlertSummary() {
  return (
    <div className="h-[250px] w-full">
      <ResponsiveContainer width="100%" height="100%">
        <BarChart
          data={data}
          layout="vertical"
          margin={{
            top: 20,
            right: 30,
            left: 20,
            bottom: 5,
          }}
        >
          <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.1)" />
          <XAxis type="number" stroke="rgba(255,255,255,0.5)" />
          <YAxis 
            dataKey="name" 
            type="category" 
            stroke="rgba(255,255,255,0.5)"
            tickLine={false}
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
          <Bar dataKey="high" stackId="a" fill="#FF6B6B" name="High Severity" />
          <Bar dataKey="medium" stackId="a" fill="#FFC107" name="Medium Severity" />
          <Bar dataKey="low" stackId="a" fill="#2196F3" name="Low Severity" />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}
