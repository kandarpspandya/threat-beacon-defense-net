
export function generateRandomPorts(): number[] {
  const commonPorts = [21, 22, 23, 25, 53, 80, 110, 143, 443, 587, 993, 995, 3306, 3389, 5900, 8080, 8443];
  const numPorts = Math.floor(Math.random() * 3) + 1; // 1-3 ports
  const ports = [];
  
  for (let i = 0; i < numPorts; i++) {
    // 75% chance of common port, 25% chance of random port
    if (Math.random() < 0.75) {
      ports.push(commonPorts[Math.floor(Math.random() * commonPorts.length)]);
    } else {
      ports.push(Math.floor(Math.random() * 65535) + 1);
    }
  }
  
  return [...new Set(ports)]; // Remove duplicates
}

export function generateRandomTags(): string[] {
  const allTags = [
    'http', 'https', 'ssh', 'ftp', 'telnet', 'smtp', 'database', 
    'cdn', 'cloud', 'dns', 'proxy', 'vpn', 'scanner', 'bot', 
    'crawler', 'malware', 'ransomware', 'trojan', 'backdoor', 'exploit'
  ];
  
  const numTags = Math.floor(Math.random() * 3); // 0-2 tags
  if (numTags === 0) return [];
  
  const tags = [];
  for (let i = 0; i < numTags; i++) {
    tags.push(allTags[Math.floor(Math.random() * allTags.length)]);
  }
  
  return [...new Set(tags)]; // Remove duplicates
}
