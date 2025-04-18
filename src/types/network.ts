
export interface NetworkDataPoint {
  name: string;
  "Normal Traffic": number;
  "Suspicious Activity": number;
  "Blocked Threats": number;
}

export interface NetworkEvent {
  timestamp: string;
  ip: string;
  ports?: number[];
  tags?: string[];
  classification?: string;
  country?: string;
  asn?: string;
  organization?: string;
  location?: {
    latitude?: number;
    longitude?: number;
    country_code?: string;
  };
  vulns?: Record<string, any>;
}

export interface ProtocolData {
  name: string;
  value: number;
  color: string;
}

export interface TrafficSource {
  name: string;
  value: number;
  color: string;
}

export interface TopConnection {
  source: string;
  destination: string;
  protocol: string;
  packets: number;
  bytes: number;
}

export interface ThreatData {
  id: number;
  type: string;
  source: string;
  destination: string;
  severity: "low" | "medium" | "high";
  timestamp: string;
  status: "monitoring" | "blocked" | "resolved";
}
