
import { Server, Globe, ArrowRightCircle } from "lucide-react";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";

const connections = [
  {
    id: 1,
    source: "192.168.1.105",
    destination: "api.example.com",
    protocol: "HTTPS",
    packets: 42563,
    bytes: "3.2 MB",
    isInternal: true,
    isExternal: false,
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
  },
];

export function TopConnections() {
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
          {connections.map((connection) => (
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
