import { useState, useEffect, useCallback } from 'react';
import { toast } from 'sonner';
import { NetworkDataPoint, NetworkEvent } from '@/types/network';
import { networkService } from '@/services/networkService';

export const useNetworkData = (period: string) => {
  const [data, setData] = useState<NetworkDataPoint[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [isConnected, setIsConnected] = useState(false);
  const [connectionStatus, setConnectionStatus] = useState<'connected' | 'connecting' | 'disconnected' | 'error'>(
    networkService.status
  );

  const getMaxDataPoints = useCallback(() => {
    switch (period) {
      case "1h": return 60;  // 1 point per minute
      case "24h": return 144; // 1 point every 10 minutes
      case "7d": return 168;  // 1 point per hour for 7 days
      case "30d": return 180; // 1 point every 4 hours for 30 days
      default: return 60;
    }
  }, [period]);

  const processNetworkEvent = useCallback((event: NetworkEvent, dataPoints: NetworkDataPoint[]) => {
    try {
      const maxDataPoints = getMaxDataPoints();
      
      let timeLabel = new Date().toLocaleTimeString();
      if (period === "7d" || period === "30d") {
        timeLabel = new Date().toLocaleDateString();
      }
      
      const existingPointIndex = dataPoints.findIndex(point => point.name === timeLabel);
      
      if (existingPointIndex >= 0) {
        const updatedDataPoints = [...dataPoints];
        const point = updatedDataPoints[existingPointIndex];
        
        if (event.classification === "benign") {
          point["Normal Traffic"] += 1;
        } else if (event.classification === "malicious") {
          point["Blocked Threats"] += 1;
        }
        
        if (event.tags && event.tags.length > 0) {
          point["Suspicious Activity"] += event.tags.length;
        }
        
        setData(updatedDataPoints);
      } else {
        const newDataPoint = {
          name: timeLabel,
          "Normal Traffic": event.classification === "benign" ? 1 : 0,
          "Suspicious Activity": event.tags?.length || 0,
          "Blocked Threats": event.classification === "malicious" ? 1 : 0,
        };
        
        const newDataPoints = [...dataPoints, newDataPoint];
        
        if (newDataPoints.length > maxDataPoints) {
          newDataPoints.splice(0, newDataPoints.length - maxDataPoints);
        }
        
        setData(newDataPoints);
      }
      
      if (networkService.status !== connectionStatus) {
        setConnectionStatus(networkService.status);
      }
      
      if (!isConnected && networkService.status === 'connected') {
        setIsConnected(true);
        setError(null);
      }
    } catch (err) {
      console.error('Error processing network data:', err);
      toast.error('Error processing network data');
      setError('Error processing network data');
    }
  }, [period, connectionStatus, isConnected, getMaxDataPoints]);

  useEffect(() => {
    setData([]);
    
    let dataPoints: NetworkDataPoint[] = [];
    
    const handleNetworkEvent = (event: NetworkEvent) => {
      processNetworkEvent(event, dataPoints);
    };

    const unsubscribe = networkService.subscribe(handleNetworkEvent);
    
    const statusInterval = setInterval(() => {
      const currentStatus = networkService.status;
      if (currentStatus !== connectionStatus) {
        setConnectionStatus(currentStatus);
        
        if (currentStatus === 'connected' && !isConnected) {
          setIsConnected(true);
          setError(null);
        } else if (currentStatus !== 'connected' && isConnected) {
          setIsConnected(false);
          setError('Network data connection lost');
        }
      }
    }, 5000);

    return () => {
      unsubscribe();
      clearInterval(statusInterval);
    };
  }, [period, processNetworkEvent, connectionStatus, isConnected]);

  return { 
    data, 
    error, 
    isConnected,
    connectionStatus
  };
};
