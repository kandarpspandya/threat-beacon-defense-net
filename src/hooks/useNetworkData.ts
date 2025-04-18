
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

  // Calculate max data points based on time period
  const getMaxDataPoints = useCallback(() => {
    switch (period) {
      case "1h": return 60;  // 1 point per minute
      case "24h": return 144; // 1 point every 10 minutes
      case "7d": return 168;  // 1 point per hour for 7 days
      case "30d": return 180; // 1 point every 4 hours for 30 days
      default: return 60;
    }
  }, [period]);

  // Process network events into time-aggregated data points
  const processNetworkEvent = useCallback((event: NetworkEvent, dataPoints: NetworkDataPoint[]) => {
    try {
      const maxDataPoints = getMaxDataPoints();
      
      // Create timestamp based on the period granularity
      let timeLabel = new Date().toLocaleTimeString();
      if (period === "7d" || period === "30d") {
        timeLabel = new Date().toLocaleDateString();
      }
      
      // Find if there's an existing data point for this time slot
      const existingPointIndex = dataPoints.findIndex(point => point.name === timeLabel);
      
      if (existingPointIndex >= 0) {
        // Update existing data point
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
        // Add new data point
        const newDataPoint = {
          name: timeLabel,
          "Normal Traffic": event.classification === "benign" ? 1 : 0,
          "Suspicious Activity": event.tags?.length || 0,
          "Blocked Threats": event.classification === "malicious" ? 1 : 0,
        };
        
        const newDataPoints = [...dataPoints, newDataPoint];
        
        // Trim data points if exceeding max
        if (newDataPoints.length > maxDataPoints) {
          newDataPoints.splice(0, newDataPoints.length - maxDataPoints);
        }
        
        setData(newDataPoints);
      }
      
      // Update connection status based on network service status
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
    // Start with empty data when period changes
    setData([]);
    
    // Create a closure for the current data state
    let dataPoints: NetworkDataPoint[] = [];
    
    const handleNetworkEvent = (event: NetworkEvent) => {
      processNetworkEvent(event, dataPoints);
    };

    // Subscribe to network events
    const unsubscribe = networkService.subscribe(handleNetworkEvent);
    
    // Check connection status every 5 seconds
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
