
import { PieChart, Pie, Cell, ResponsiveContainer, Legend, Tooltip } from "recharts";

const data = [
  { name: "HTTP/S", value: 42, color: "#64FFDA" },
  { name: "DNS", value: 28, color: "#FFC107" },
  { name: "SSH", value: 15, color: "#FF6B6B" },
  { name: "SMTP", value: 10, color: "#2196F3" },
  { name: "Other", value: 5, color: "#9c27b0" },
];

export function ProtocolDistribution() {
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
