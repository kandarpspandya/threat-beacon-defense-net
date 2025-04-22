
import { useState, useEffect, useCallback } from 'react';
import { toast } from 'sonner';
import { NetworkDataPoint, NetworkEvent } from '@/types/network';
import { networkService } from '@/services/network/NetworkService';

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
      
      // Format time label based on period
      let timeLabel: string;
      if (period === "1h") {
        const now = new Date();
        timeLabel = `${now.getHours().toString().padStart(2, '0')}:${now.getMinutes().toString().padStart(2, '0')}`;
      } else if (period === "24h") {
        const now = new Date();
        timeLabel = `${now.getHours().toString().padStart(2, '0')}:00`;
      } else if (period === "7d") {
        const now = new Date();
        const days = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
        timeLabel = days[now.getDay()];
      } else {
        // 30d
        const now = new Date();
        timeLabel = `${now.getMonth() + 1}/${now.getDate()}`;
      }
      
      const existingPointIndex = dataPoints.findIndex(point => point.name === timeLabel);
      
      if (existingPointIndex >= 0) {
        const updatedDataPoints = [...dataPoints];
        const point = updatedDataPoints[existingPointIndex];
        
        if (event.classification === "benign") {
          // Convert to number explicitly
          const currentValue = typeof point["Normal Traffic"] === 'number' ? point["Normal Traffic"] : 0;
          point["Normal Traffic"] = currentValue + 1;
        } else if (event.classification === "malicious") {
          // Convert to number explicitly
          const currentValue = typeof point["Blocked Threats"] === 'number' ? point["Blocked Threats"] : 0;
          point["Blocked Threats"] = currentValue + 1;
        }
        
        if (event.tags && event.tags.length > 0) {
          // Count suspicious tags like 'scanner', 'crawler', etc.
          const suspiciousTags = event.tags.filter(tag => 
            ['scanner', 'crawler', 'proxy', 'vpn', 'backdoor', 'exploit', 'malware', 'ransomware', 'trojan', 'unknown'].includes(tag)
          );
          
          // Convert to number explicitly
          const currentValue = typeof point["Suspicious Activity"] === 'number' ? point["Suspicious Activity"] : 0;
          point["Suspicious Activity"] = currentValue + suspiciousTags.length;
        }
        
        setData(updatedDataPoints);
      } else {
        // Create a new data point
        const newDataPoint: NetworkDataPoint = {
          name: timeLabel,
          "Normal Traffic": event.classification === "benign" ? 1 : 0,
          "Suspicious Activity": (event.tags?.filter(tag => 
            ['scanner', 'crawler', 'proxy', 'vpn', 'backdoor', 'exploit', 'malware', 'ransomware', 'trojan', 'unknown'].includes(tag)
          ).length || 0),
          "Blocked Threats": event.classification === "malicious" ? 1 : 0,
        };
        
        const newDataPoints = [...dataPoints, newDataPoint];
        
        // Maintain maximum data points
        if (newDataPoints.length > maxDataPoints) {
          newDataPoints.splice(0, newDataPoints.length - maxDataPoints);
        }
        
        setData(newDataPoints);
      }
      
      // Update connection status
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
    // Reset data when period changes
    setData([]);
    
    // Initialize with some data points based on period
    const initialDataPoints: NetworkDataPoint[] = [];
    const maxPoints = getMaxDataPoints();
    
    if (period === "1h") {
      // Initialize with hours and minutes for 1h view
      const now = new Date();
      for (let i = 0; i < 60; i++) {
        const minute = (now.getMinutes() - i + 60) % 60;
        const hour = (now.getHours() - (minute > now.getMinutes() ? 1 : 0) + 24) % 24;
        initialDataPoints.unshift({
          name: `${hour.toString().padStart(2, '0')}:${minute.toString().padStart(2, '0')}`,
          "Normal Traffic": 0,
          "Suspicious Activity": 0,
          "Blocked Threats": 0
        });
      }
    } else if (period === "24h") {
      // Initialize with hours for 24h view
      const now = new Date();
      for (let i = 0; i < 24; i++) {
        const hour = (now.getHours() - i + 24) % 24;
        initialDataPoints.unshift({
          name: `${hour.toString().padStart(2, '0')}:00`,
          "Normal Traffic": 0,
          "Suspicious Activity": 0,
          "Blocked Threats": 0
        });
      }
    } else if (period === "7d") {
      // Initialize with days for 7d view
      const days = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
      const now = new Date();
      for (let i = 0; i < 7; i++) {
        const day = (now.getDay() - i + 7) % 7;
        initialDataPoints.unshift({
          name: days[day],
          "Normal Traffic": 0,
          "Suspicious Activity": 0,
          "Blocked Threats": 0
        });
      }
    } else if (period === "30d") {
      // Initialize with month/day for 30d view
      const now = new Date();
      for (let i = 0; i < 30; i++) {
        const date = new Date(now);
        date.setDate(date.getDate() - i);
        initialDataPoints.unshift({
          name: `${date.getMonth() + 1}/${date.getDate()}`,
          "Normal Traffic": 0,
          "Suspicious Activity": 0,
          "Blocked Threats": 0
        });
      }
    }
    
    // Ensure we don't exceed max points
    while (initialDataPoints.length > maxPoints) {
      initialDataPoints.shift();
    }
    
    let dataPoints = [...initialDataPoints];
    setData(dataPoints);
    
    // Handle incoming network events
    const handleNetworkEvent = (event: NetworkEvent) => {
      processNetworkEvent(event, dataPoints);
    };

    // Subscribe to network events
    const unsubscribe = networkService.subscribe(handleNetworkEvent);
    
    // Periodically check connection status
    const statusInterval = setInterval(() => {
      const currentStatus = networkService.status;
      if (currentStatus !== connectionStatus) {
        setConnectionStatus(currentStatus);
        
        if (currentStatus === 'connected' && !isConnected) {
          setIsConnected(true);
          setError(null);
          toast.success("Connected to network monitoring");
        } else if (currentStatus !== 'connected' && isConnected) {
          setIsConnected(false);
          setError('Network data connection lost');
          toast.error("Network monitoring connection lost");
        }
      }
    }, 5000);

    return () => {
      unsubscribe();
      clearInterval(statusInterval);
    };
  }, [period, processNetworkEvent, connectionStatus, isConnected, getMaxDataPoints]);

  // If we don't have real data yet, simulate some
  useEffect(() => {
    if (isConnected || data.some(point => {
      const normalTraffic = typeof point["Normal Traffic"] === 'number' ? point["Normal Traffic"] : 0;
      const suspiciousActivity = typeof point["Suspicious Activity"] === 'number' ? point["Suspicious Activity"] : 0; 
      const blockedThreats = typeof point["Blocked Threats"] === 'number' ? point["Blocked Threats"] : 0;
      
      return normalTraffic > 0 || suspiciousActivity > 0 || blockedThreats > 0;
    })) {
      return; // We already have data
    }
    
    // Add some simulated data for better user experience
    setData(prevData => {
      return prevData.map(point => {
        // More activity during work hours
        const hourMatch = point.name.match(/^(\d+):/);
        const hour = hourMatch ? parseInt(hourMatch[1], 10) : 12;
        const isWorkHour = hour >= 9 && hour <= 17;
        const multiplier = isWorkHour ? 2 : 0.5;
        
        return {
          ...point,
          "Normal Traffic": Math.floor(Math.random() * 50 * multiplier) + 10,
          "Suspicious Activity": Math.floor(Math.random() * 15 * multiplier),
          "Blocked Threats": Math.floor(Math.random() * 5 * multiplier)
        };
      });
    });
  }, [data, isConnected]);

  return { 
    data, 
    error, 
    isConnected,
    connectionStatus
  };
};
