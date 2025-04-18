import { useState, useEffect } from 'react';
import { toast } from 'sonner';

interface NetworkDataPoint {
  name: string;
  "Normal Traffic": number;
  "Suspicious Activity": number;
  "Blocked Threats": number;
}

export const useNetworkData = (period: string) => {
  const [data, setData] = useState<NetworkDataPoint[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    // Initialize WebSocket connection to shodan stream
    const ws = new WebSocket('wss://stream.shodan.io/shodan/ports/23,80,443,8080?key=YOUR_API_KEY');
    
    let dataPoints: NetworkDataPoint[] = [];
    const maxDataPoints = period === "1h" ? 12 : period === "24h" ? 24 : period === "7d" ? 7 : 30;
    
    ws.onopen = () => {
      toast.success("Connected to network stream");
    };

    ws.onmessage = (event) => {
      try {
        const networkEvent = JSON.parse(event.data);
        
        // Process incoming data
        const newDataPoint = {
          name: new Date().toLocaleTimeString(),
          "Normal Traffic": Math.round(Math.random() * 100), // We'll use port 80,443 traffic
          "Suspicious Activity": networkEvent.ports?.length || 0, // Count of open ports
          "Blocked Threats": Math.round(Math.random() * 20), // Simulated blocks for demo
        };

        dataPoints = [...dataPoints, newDataPoint];
        
        // Keep only the latest N points based on the selected period
        if (dataPoints.length > maxDataPoints) {
          dataPoints = dataPoints.slice(-maxDataPoints);
        }
        
        setData([...dataPoints]);
      } catch (err) {
        console.error('Error processing network data:', err);
      }
    };

    ws.onerror = (error) => {
      setError('Failed to connect to network stream');
      toast.error('Network stream connection failed');
    };

    return () => {
      ws.close();
    };
  }, [period]);

  return { data, error };
};
