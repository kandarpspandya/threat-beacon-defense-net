
import { useState, useEffect } from "react";
import { Server, Globe, ArrowRightCircle } from "lucide-react";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { NetworkConnection } from "@/types/network";
import { networkService } from "@/services/network/NetworkService";

export function TopConnections() {
  const [connections, setConnections] = useState<NetworkConnection[]>([]);
  
  useEffect(() => {
    // Initial realistic connection data
    const initialConnections: NetworkConnection[] = [
      {
        id: 1,
        source: "192.168.1.105",
        destination: "api.example.com",
        protocol: "HTTPS",
        packets: 42563,
        bytes: "3.2 MB",
        isInternal: true,
        isExternal: false,
        timestamp: new Date().toISOString()
      },
      {
        id: 2,
        source: "192.168.1.120",
        destination: "cdn.example.net",
        protocol: "HTTP",
        packets: 31452,
        bytes: "12.7 MB",
        isInternal: true,
        isExternal: false,
        timestamp: new Date().toISOString()
      },
      {
        id: 3,
        source: "75.123.45.67",
        destination: "192.168.1.1",
        protocol: "SSH",
        packets: 12983,
        bytes: "1.3 MB",
        isInternal: false,
        isExternal: true,
        timestamp: new Date().toISOString()
      },
      {
        id: 4,
        source: "192.168.1.110",
        destination: "192.168.1.1",
        protocol: "DNS",
        packets: 8752,
        bytes: "0.6 MB",
        isInternal: true,
        isExternal: true,
        timestamp: new Date().toISOString()
      },
      {
        id: 5,
        source: "192.168.1.115",
        destination: "storage.example.com",
        protocol: "HTTPS",
        packets: 6543,
        bytes: "5.1 MB",
        isInternal: true,
        isExternal: false,
        timestamp: new Date().toISOString()
      },
    ];
    
    setConnections(initialConnections);
    
    // Create realistic dynamic data by listening to network events
    const unsubscribe = networkService.subscribe(event => {
      // Only process a subset of events to avoid flooding
      if (Math.random() > 0.15) return;
      
      // Generate a new connection from the event
      const newConnection = generateConnectionFromEvent(event);
      
      setConnections(prevConnections => {
        // Add new connection at beginning, remove oldest if more than 15
        const updated = [newConnection, ...prevConnections];
        if (updated.length > 15) {
          return updated.slice(0, 15);
        }
        return updated;
      });
    });
    
    // Periodically update existing connection metrics
    const updateInterval = setInterval(() => {
      setConnections(prevConnections => {
        return prevConnections.map(conn => {
          // Only update some connections
          if (Math.random() > 0.3) return conn;
          
          // Increase packets and bytes
          const packetIncrease = Math.floor(Math.random() * 500) + 50;
          const newPackets = conn.packets + packetIncrease;
          
          // Format bytes nicely
          let bytes = "";
          if (newPackets > 100000) {
            bytes = `${(newPackets / 1000000 * 0.1).toFixed(1)} MB`;
          } else {
            bytes = `${(newPackets / 1000 * 0.1).toFixed(1)} KB`;
          }
          
          return {
            ...conn,
            packets: newPackets,
            bytes,
            timestamp: new Date().toISOString()
          };
        });
      });
    }, 5000);
    
    return () => {
      unsubscribe();
      clearInterval(updateInterval);
    };
  }, []);
  
  // Generate a new connection from a network event
  const generateConnectionFromEvent = (event: any): NetworkConnection => {
    // Determine if source is internal or external
    const isSourceInternal = Math.random() > 0.7;
    const source = isSourceInternal 
      ? `192.168.${Math.floor(Math.random() * 255) + 1}.${Math.floor(Math.random() * 255) + 1}`
      : event.ip;
    
    // Determine if destination is internal or external
    const isDestInternal = Math.random() > 0.5;
    
    // Get realistic destination
    const commonDomains = [
      'api.example.com', 'cdn.example.net', 'storage.example.org',
      'api.google.com', 'github.com', 'aws.amazon.com', 
      'login.microsoftonline.com', 'cdn.cloudflare.com',
      'drive.google.com', 'accounts.spotify.com'
    ];
    
    const destination = isDestInternal
      ? `192.168.${Math.floor(Math.random() * 255) + 1}.${Math.floor(Math.random() * 255) + 1}`
      : (Math.random() > 0.7 
          ? event.ip.replace(/\./g, '-') + '.example.com'
          : commonDomains[Math.floor(Math.random() * commonDomains.length)]);
    
    // Determine protocol from ports or randomly
    let protocol = "HTTP";
    if (event.ports && event.ports.length > 0) {
      const port = event.ports[0];
      if (port === 443) protocol = "HTTPS";
      else if (port === 22) protocol = "SSH";
      else if (port === 53) protocol = "DNS";
      else if (port === 21) protocol = "FTP";
      else if (port === 25) protocol = "SMTP";
    } else {
      const protocols = ["HTTP", "HTTPS", "DNS", "SMTP", "SSH", "FTP", "TELNET"];
      protocol = protocols[Math.floor(Math.random() * protocols.length)];
    }
    
    // Generate packet count based on protocol and randomness
    const packetBase = {
      "HTTP": 5000,
      "HTTPS": 10000,
      "DNS": 500,
      "SMTP": 3000,
      "SSH": 10000,
      "FTP": 20000,
      "TELNET": 2000
    }[protocol] || 5000;
    
    const packets = Math.floor(Math.random() * packetBase) + (packetBase / 2);
    
    // Format bytes nicely
    let bytes = "";
    if (packets > 100000) {
      bytes = `${(packets / 1000000 * 0.1).toFixed(1)} MB`;
    } else {
      bytes = `${(packets / 1000 * 0.1).toFixed(1)} KB`;
    }
    
    return {
      id: Date.now(),
      source,
      destination,
      protocol,
      packets,
      bytes,
      isInternal: isSourceInternal,
      isExternal: isDestInternal,
      timestamp: new Date().toISOString()
    };
  };

  // Sort connections by packets (most active first)
  const sortedConnections = [...connections].sort((a, b) => b.packets - a.packets);

  return (
    <div className="max-h-[250px] overflow-auto">
      <Table>
        <TableHeader className="bg-background/50 sticky top-0">
          <TableRow>
            <TableHead className="w-[100px]">Source</TableHead>
            <TableHead className="w-[50px]"></TableHead>
            <TableHead>Destination</TableHead>
            <TableHead className="text-right">Traffic</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {sortedConnections.map((connection) => (
            <TableRow key={connection.id}>
              <TableCell className="font-mono text-xs">
                <div className="flex items-center">
                  {connection.isInternal ? (
                    <Server className="mr-2 h-3 w-3 text-sentinel-info" />
                  ) : (
                    <Globe className="mr-2 h-3 w-3 text-sentinel-warning" />
                  )}
                  {connection.source}
                </div>
              </TableCell>
              <TableCell>
                <ArrowRightCircle className="h-3 w-3 text-muted-foreground" />
              </TableCell>
              <TableCell className="font-mono text-xs">
                <div className="flex items-center">
                  {connection.isExternal ? (
                    <Globe className="mr-2 h-3 w-3 text-sentinel-info" />
                  ) : (
                    <Server className="mr-2 h-3 w-3 text-sentinel-success" />
                  )}
                  {connection.destination}
                </div>
              </TableCell>
              <TableCell className="text-right font-medium">
                {connection.bytes}
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  );
}
