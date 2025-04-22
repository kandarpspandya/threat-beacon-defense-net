
import { useState, useEffect, useCallback } from "react";
import { Server, Globe, ArrowRightCircle } from "lucide-react";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { NetworkConnection } from "@/types/network";
import { networkService } from "@/services/network/NetworkService";

export function TopConnections() {
  const [connections, setConnections] = useState<NetworkConnection[]>([]);
  
  // Generate more realistic domain names rather than example.com placeholders
  const generateRealisticDomain = useCallback(() => {
    const tlds = ['.com', '.net', '.org', '.io', '.co', '.app', '.cloud', '.tech', '.ai'];
    const commonDomains = [
      // Tech Companies
      'google', 'microsoft', 'apple', 'amazon', 'meta', 'github', 'gitlab', 'atlassian', 'digitalocean', 'cloudflare',
      // Services
      'analytics', 'api', 'cdn', 'storage', 'login', 'auth', 'dashboard', 'app', 'mail', 'drive',
      // Common web services
      'dropbox', 'slack', 'zoom', 'notion', 'netflix', 'spotify', 'youtube', 'twitter', 
      // Cloud Services
      'aws', 'azure', 'gcp', 'firebase', 'vercel', 'netlify', 'heroku'
    ];
    
    const subdomains = ['api', 'cdn', 'login', 'dev', 'stage', 'prod', 'www', 'app', 'mail', 'auth', 'docs', 'admin', 'portal'];
    
    // Generate different types of domains
    const domainType = Math.random();
    
    if (domainType < 0.4) {
      // Basic domain (e.g., microsoft.com)
      const domain = commonDomains[Math.floor(Math.random() * commonDomains.length)];
      const tld = tlds[Math.floor(Math.random() * tlds.length)];
      return `${domain}${tld}`;
    } else if (domainType < 0.7) {
      // Subdomain (e.g., api.stripe.com)
      const subdomain = subdomains[Math.floor(Math.random() * subdomains.length)];
      const domain = commonDomains[Math.floor(Math.random() * commonDomains.length)];
      const tld = tlds[Math.floor(Math.random() * tlds.length)];
      return `${subdomain}.${domain}${tld}`;
    } else {
      // Regional domain (e.g., us-east.compute.amazonaws.com)
      const regions = ['us-east', 'us-west', 'eu-central', 'ap-south', 'sa-east'];
      const services = ['compute', 'storage', 'db', 'analytics', 'auth'];
      const providers = ['aws', 'azure', 'gcp', 'oracle', 'ibm'];
      
      const region = regions[Math.floor(Math.random() * regions.length)];
      const service = services[Math.floor(Math.random() * services.length)];
      const provider = providers[Math.floor(Math.random() * providers.length)];
      
      return `${region}.${service}.${provider}.com`;
    }
  }, []);
  
  // Generate more realistic IP addresses
  const generateRealisticIP = useCallback((isInternal: boolean) => {
    if (isInternal) {
      // RFC 1918 private IP ranges
      const privateRanges = [
        { first: '10', second: Math.floor(Math.random() * 255) }, // 10.0.0.0/8
        { first: '172', second: Math.floor(Math.random() * 16) + 16 }, // 172.16.0.0/12
        { first: '192', second: 168 } // 192.168.0.0/16
      ];
      
      const range = privateRanges[Math.floor(Math.random() * privateRanges.length)];
      return `${range.first}.${range.second}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;
    } else {
      // Avoid private ranges for external IPs
      let first = Math.floor(Math.random() * 223) + 1;
      while (first === 10 || first === 172 || first === 192) {
        first = Math.floor(Math.random() * 223) + 1;
      }
      return `${first}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;
    }
  }, []);

  useEffect(() => {
    // Create more realistic initial connections
    const initialConnections: NetworkConnection[] = Array.from({ length: 5 }, (_, index) => {
      const isSourceInternal = Math.random() > 0.3;
      const isDestInternal = !isSourceInternal || Math.random() > 0.7;
      
      const protocols = ["HTTPS", "HTTP", "DNS", "SMTP", "SSH", "FTP", "TELNET", "RDP", "LDAP", "SNMP"];
      const protocol = protocols[Math.floor(Math.random() * protocols.length)];
      
      const packetBase = {
        "HTTP": 5000,
        "HTTPS": 10000,
        "DNS": 500,
        "SMTP": 3000,
        "SSH": 10000,
        "FTP": 20000,
        "TELNET": 2000,
        "RDP": 15000,
        "LDAP": 1000,
        "SNMP": 500
      }[protocol] || 5000;
      
      const packets = Math.floor(Math.random() * packetBase) + (packetBase / 2);
      const bytes = packets > 100000 
        ? `${(packets / 1000000 * 0.1).toFixed(1)} MB` 
        : `${(packets / 1000 * 0.1).toFixed(1)} KB`;
      
      return {
        id: index + 1,
        source: isSourceInternal ? generateRealisticIP(true) : generateRealisticIP(false),
        destination: isDestInternal 
          ? generateRealisticIP(true) 
          : generateRealisticDomain(),
        protocol,
        packets,
        bytes,
        isInternal: isSourceInternal,
        isExternal: !isDestInternal,
        timestamp: new Date().toISOString()
      };
    });
    
    setConnections(initialConnections);
    
    // Create realistic dynamic data by listening to network events
    const unsubscribe = networkService.subscribe(event => {
      // Only process a subset of events to avoid flooding
      if (Math.random() > 0.15) return;
      
      // Determine if source is internal or external
      const isSourceInternal = Math.random() > 0.7;
      const source = isSourceInternal 
        ? generateRealisticIP(true)
        : event.ip;
      
      // Determine if destination is internal or external
      const isDestInternal = Math.random() > 0.5;
      
      // Get realistic destination
      const destination = isDestInternal
        ? generateRealisticIP(true)
        : generateRealisticDomain();
      
      // Determine protocol from ports or randomly
      let protocol = "HTTP";
      if (event.ports && event.ports.length > 0) {
        const port = event.ports[0];
        if (port === 443) protocol = "HTTPS";
        else if (port === 22) protocol = "SSH";
        else if (port === 53) protocol = "DNS";
        else if (port === 21) protocol = "FTP";
        else if (port === 25) protocol = "SMTP";
        else if (port === 3389) protocol = "RDP";
        else if (port === 389) protocol = "LDAP";
        else if (port === 161) protocol = "SNMP";
      } else {
        const protocols = ["HTTP", "HTTPS", "DNS", "SMTP", "SSH", "FTP", "TELNET", "RDP", "LDAP", "SNMP"];
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
        "TELNET": 2000,
        "RDP": 15000,
        "LDAP": 1000,
        "SNMP": 500
      }[protocol] || 5000;
      
      const packets = Math.floor(Math.random() * packetBase) + (packetBase / 2);
      
      // Format bytes nicely
      let bytes = "";
      if (packets > 100000) {
        bytes = `${(packets / 1000000 * 0.1).toFixed(1)} MB`;
      } else {
        bytes = `${(packets / 1000 * 0.1).toFixed(1)} KB`;
      }
      
      const newConnection = {
        id: Date.now(),
        source,
        destination,
        protocol,
        packets,
        bytes,
        isInternal: isSourceInternal,
        isExternal: !isDestInternal,
        timestamp: new Date().toISOString()
      };
      
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
  }, [generateRealisticDomain, generateRealisticIP]);

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
