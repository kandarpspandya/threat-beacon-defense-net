
import { useState, useEffect } from 'react';
import { toast } from 'sonner';
import { NetworkDataPoint, NetworkEvent } from '@/types/network';
import { networkService } from '@/services/networkService';

export const useNetworkData = (period: string) => {
  const [data, setData] = useState<NetworkDataPoint[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [isConnected, setIsConnected] = useState(false);

  useEffect(() => {
    let dataPoints: NetworkDataPoint[] = [];
    const maxDataPoints = period === "1h" ? 12 : period === "24h" ? 24 : period === "7d" ? 7 : 30;
    
    const handleNetworkEvent = (event: NetworkEvent) => {
      try {
        const newDataPoint = {
          name: new Date().toLocaleTimeString(),
          "Normal Traffic": event.classification === "benign" ? 1 : 0,
          "Suspicious Activity": event.tags?.length || 0,
          "Blocked Threats": event.classification === "malicious" ? 1 : 0,
        };

        dataPoints = [...dataPoints, newDataPoint];
        
        if (dataPoints.length > maxDataPoints) {
          dataPoints = dataPoints.slice(-maxDataPoints);
        }
        
        setData([...dataPoints]);
        
        if (!isConnected) {
          setIsConnected(true);
          toast.success("Connected to network stream");
        }
      } catch (err) {
        console.error('Error processing network data:', err);
        toast.error('Error processing network data');
        setError('Error processing network data');
      }
    };

    const unsubscribe = networkService.subscribe(handleNetworkEvent);
    networkService.connect();

    return () => {
      unsubscribe();
      networkService.disconnect();
    };
  }, [period, isConnected]);

  return { data, error, isConnected };
};
