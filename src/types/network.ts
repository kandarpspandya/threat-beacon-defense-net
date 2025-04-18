
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
}
