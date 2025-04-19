import { NetworkEvent } from "@/types/network";

export const eventNormalizer = (event: any): NetworkEvent => {
  // Extract more relevant data from Shodan responses
  const tags = [];
  
  // Add protocol-based tags
  if (event.data && event.data.http) tags.push('http');
  if (event.port === 443) tags.push('https');
  if (event.port === 22) tags.push('ssh');
  if (event.port === 21) tags.push('ftp');
  if (event.port === 23) tags.push('telnet');
  
  // Add geographic data if available
  if (event.location && event.location.country_code) {
    tags.push(`geo:${event.location.country_code.toLowerCase()}`);
  }
  
  // Classify the traffic based on potential threats
  let classification = "benign";
  if (event.vulns && Object.keys(event.vulns).length > 0) {
    classification = "malicious";
    tags.push('vulnerable');
  }
  
  if (event.tags && event.tags.includes('malicious')) {
    classification = "malicious";
  }
  
  // Extract ports
  const ports = event.ports || [event.port] || [];
  
  return {
    timestamp: event.timestamp || new Date().toISOString(),
    ip: event.ip_str || event.ip || "unknown",
    ports: (event.ports || [event.port || []]).filter(Boolean),
    tags: [...new Set([...(event.tags || [])])],
    classification: event.classification || "benign"
  };
};
