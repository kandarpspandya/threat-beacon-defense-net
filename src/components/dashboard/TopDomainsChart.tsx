
import { useState, useEffect } from "react";
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from "recharts";
import { networkService } from "@/services/networkService";
import { NetworkEvent } from "@/types/network";
import { Skeleton } from "@/components/ui/skeleton";
import { RealTimeStatus } from "./RealTimeStatus";

interface DomainData {
  name: string;
  visits: number;
}

export function TopDomainsChart() {
  const [data, setData] = useState<DomainData[]>([]);
  const [loading, setLoading] = useState(true);
  const [status, setStatus] = useState<'connected' | 'connecting' | 'disconnected' | 'error'>(
    networkService.status
  );

  useEffect(() => {
    // Domain counter
    const domainCounts: Record<string, number> = {};
    
    // List of common domains to simulate with
    const commonDomains = [
      'api.example.com',
      'cdn.example.net',
      'storage.example.org',
      'mail.example.com',
      'dashboard.example.io',
      'api.google.com',
      'api.microsoft.com',
      'cdn.akamai.net',
      'login.microsoftonline.com',
      'github.com',
      'aws.amazon.com',
      'storage.googleapis.com',
      'api.github.com'
    ];
    
    // Handle incoming network events
    const handleNetworkEvent = (event: NetworkEvent) => {
      // In a real implementation, you would extract domain from HTTP headers
      // Here we'll simulate by randomly selecting domains
      if (event.tags?.includes('http') || event.tags?.includes('https')) {
        const domainIndex = Math.floor(Math.random() * commonDomains.length);
        const domain = commonDomains[domainIndex];
        
        domainCounts[domain] = (domainCounts[domain] || 0) + 1;
        updateChartData(domainCounts);
      }
    };
    
    // Update the chart data with the top domains
    const updateChartData = (counts: Record<string, number>) => {
      // Sort domains by visit count and take top 5
      const topDomains = Object.entries(counts)
        .sort(([, countA], [, countB]) => countB - countA)
        .slice(0, 5)
        .map(([domain, count]) => ({
          name: domain,
          visits: count
        }));
      
      if (topDomains.length > 0) {
        setData(topDomains);
        if (loading) {
          setLoading(false);
        }
      }
    };
    
    // Subscribe to network events
    const unsubscribe = networkService.subscribe(handleNetworkEvent);
    
    // Check connection status periodically
    const statusInterval = setInterval(() => {
      setStatus(networkService.status);
    }, 3000);
    
    // Pre-populate with some initial data
    const initialDomains = commonDomains.slice(0, 5).map((domain, index) => ({
      name: domain,
      visits: Math.floor(Math.random() * 800) + 200 - (index * 100)
    }));
    
    setData(initialDomains);
    setLoading(false);
    
    return () => {
      unsubscribe();
      clearInterval(statusInterval);
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
        <BarChart
          data={data}
          layout="vertical"
          margin={{
            top: 5,
            right: 30,
            left: 20,
            bottom: 5,
          }}
        >
          <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.1)" />
          <XAxis type="number" stroke="rgba(255,255,255,0.5)" />
          <YAxis 
            type="category" 
            dataKey="name" 
            stroke="rgba(255,255,255,0.5)"
            tickLine={false}
            width={150}
          />
          <Tooltip 
            contentStyle={{ 
              backgroundColor: "rgba(23, 42, 69, 0.9)", 
              borderColor: "#64FFDA",
              borderRadius: "6px",
              color: "#fff"
            }}
          />
          <Bar dataKey="visits" fill="#64FFDA" radius={[0, 4, 4, 0]} />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}
