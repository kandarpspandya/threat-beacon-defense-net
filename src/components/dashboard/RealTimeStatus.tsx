
import { Badge } from "@/components/ui/badge";
import { Signal, Wifi, WifiOff } from "lucide-react";

interface RealTimeStatusProps {
  status: 'connected' | 'connecting' | 'disconnected' | 'error';
  className?: string;
}

export function RealTimeStatus({ status, className = "" }: RealTimeStatusProps) {
  if (status === 'connecting') {
    return (
      <Badge variant="outline" className={`bg-yellow-500/10 text-yellow-500 border-yellow-500/20 ${className}`}>
        <Signal className="w-3 h-3 mr-1 animate-pulse" />
        Connecting...
      </Badge>
    );
  } else if (status === 'connected') {
    return (
      <Badge variant="outline" className={`bg-green-500/10 text-green-500 border-green-500/20 ${className}`}>
        <Wifi className="w-3 h-3 mr-1" />
        Live
      </Badge>
    );
  } else if (status === 'error') {
    return (
      <Badge variant="outline" className={`bg-red-500/10 text-red-500 border-red-500/20 ${className}`}>
        <WifiOff className="w-3 h-3 mr-1" />
        Error
      </Badge>
    );
  } else {
    return (
      <Badge variant="outline" className={`bg-gray-500/10 text-gray-500 border-gray-500/20 ${className}`}>
        <WifiOff className="w-3 h-3 mr-1" />
        Disconnected
      </Badge>
    );
  }
}
