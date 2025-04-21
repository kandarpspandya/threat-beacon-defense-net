
// Definition for network event data
export interface NetworkEvent {
  timestamp: string;
  ip: string;
  ports: number[];
  tags?: string[];
  classification: "benign" | "malicious" | "unknown";
  location?: {
    country_code?: string;
    city?: string;
    lat?: number;
    lon?: number;
  };
  user_context?: {
    username?: string;
    device_id?: string;
    session_id?: string;
  };
}

// Definition for protocol data used in charts
export interface ProtocolData {
  name: string;
  value: number;
  color: string;
}

// Definition for network data points in charts
export interface NetworkDataPoint {
  name: string;
  [key: string]: string | number; // To allow for dynamic data properties
}

// Traffic data for time-based charts
export interface TrafficData {
  hour: string;
  incoming: number;
  outgoing: number;
}

// Definition for a security alert or threat
export interface SecurityAlert {
  id: number;
  type: string;
  source: string;
  destination: string;
  severity: "low" | "medium" | "high" | "critical";
  timestamp: string;
  status: "blocked" | "monitoring" | "resolved" | "investigating";
  details?: string;
}
