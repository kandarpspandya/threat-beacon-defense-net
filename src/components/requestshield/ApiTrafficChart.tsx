
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts';

// Mock data for API traffic chart
const apiTrafficData = [
  { time: "00:00", normal: 245, malicious: 8 },
  { time: "01:00", normal: 185, malicious: 5 },
  { time: "02:00", normal: 143, malicious: 3 },
  { time: "03:00", normal: 128, malicious: 2 },
  { time: "04:00", normal: 112, malicious: 1 },
  { time: "05:00", normal: 95, malicious: 1 },
  { time: "06:00", normal: 125, malicious: 2 },
  { time: "07:00", normal: 198, malicious: 4 },
  { time: "08:00", normal: 345, malicious: 12 },
  { time: "09:00", normal: 475, malicious: 18 },
  { time: "10:00", normal: 590, malicious: 22 },
  { time: "11:00", normal: 623, malicious: 25 },
  { time: "12:00", normal: 589, malicious: 21 },
  { time: "13:00", normal: 542, malicious: 19 },
  { time: "14:00", normal: 578, malicious: 23 },
  { time: "15:00", normal: 605, malicious: 26 },
  { time: "16:00", normal: 632, malicious: 28 },
  { time: "17:00", normal: 587, malicious: 24 },
  { time: "18:00", normal: 498, malicious: 20 },
  { time: "19:00", normal: 432, malicious: 17 },
  { time: "20:00", normal: 387, malicious: 15 },
  { time: "21:00", normal: 345, malicious: 13 },
  { time: "22:00", normal: 298, malicious: 10 },
  { time: "23:00", normal: 265, malicious: 9 }
];

export const ApiTrafficChart = () => {
  return (
    <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm">
      <CardHeader>
        <CardTitle>API Traffic Analysis</CardTitle>
        <CardDescription>
          Legitimate vs. malicious API requests over 24 hours
        </CardDescription>
      </CardHeader>
      <CardContent className="h-[300px]">
        <ResponsiveContainer width="100%" height="100%">
          <LineChart data={apiTrafficData}>
            <CartesianGrid strokeDasharray="3 3" stroke="#2D3748" />
            <XAxis 
              dataKey="time" 
              stroke="#A0AEC0"
              tick={{ fill: '#A0AEC0' }}
            />
            <YAxis 
              stroke="#A0AEC0" 
              tick={{ fill: '#A0AEC0' }}
            />
            <Tooltip 
              contentStyle={{ 
                backgroundColor: 'rgba(23, 42, 69, 0.9)', 
                borderColor: '#64FFDA',
                borderRadius: '6px', 
                color: '#fff'
              }}
            />
            <Legend />
            <Line 
              type="monotone" 
              dataKey="normal" 
              stroke="#64FFDA" 
              strokeWidth={2}
              name="Legitimate Requests"
            />
            <Line 
              type="monotone" 
              dataKey="malicious" 
              stroke="#FF6B6B" 
              strokeWidth={2}
              name="Malicious Requests"
            />
          </LineChart>
        </ResponsiveContainer>
      </CardContent>
    </Card>
  );
};
