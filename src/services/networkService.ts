import { NetworkEvent } from "@/types/network";
import { toast } from "sonner";

class NetworkService {
  private shodanWs: WebSocket | null = null;
  private reconnectAttempts = 0;
  private maxReconnectAttempts = 5;
  private reconnectDelay = 2000;
  private reconnectTimer: NodeJS.Timeout | null = null;
  private dataHandlers: ((event: NetworkEvent) => void)[] = [];
  private connectionStatus: 'connected' | 'connecting' | 'disconnected' | 'error' = 'disconnected';

  constructor(private apiKey: string) {}

  get status(): 'connected' | 'connecting' | 'disconnected' | 'error' {
    return this.connectionStatus;
  }

  connect() {
    if (this.connectionStatus === 'connecting' || this.connectionStatus === 'connected') {
      return;
    }

    this.connectionStatus = 'connecting';
    
    try {
      console.log("Attempting to connect to Shodan stream...");
      this.shodanWs = new WebSocket(
        `wss://stream.shodan.io/shodan/ports/23,80,443,8080?key=${this.apiKey}`
      );

      this.shodanWs.onopen = () => {
        console.log("Successfully connected to Shodan stream");
        this.connectionStatus = 'connected';
        this.reconnectAttempts = 0;
        toast.success("Connected to Shodan network stream");
      };

      this.shodanWs.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          this.notifyHandlers(this.normalizeEvent(data));
        } catch (err) {
          console.error("Error processing Shodan data:", err);
        }
      };

      this.shodanWs.onclose = (event) => {
        console.log(`WebSocket closed with code: ${event.code}, reason: ${event.reason}`);
        this.connectionStatus = 'disconnected';
        
        if (this.reconnectAttempts < this.maxReconnectAttempts) {
          this.reconnectTimer = setTimeout(() => this.reconnect(), this.getReconnectDelay());
        } else {
          toast.error("Failed to connect to Shodan after multiple attempts, using fallback data");
          this.fallbackToGreynoise();
        }
      };

      this.shodanWs.onerror = (error) => {
        console.error("WebSocket error:", error);
        this.connectionStatus = 'error';
        toast.error("Error connecting to Shodan network stream");
        
        if (this.shodanWs) {
          this.shodanWs.close();
        }
        
        this.fallbackToGreynoise();
      };

    } catch (err) {
      console.error("Error establishing WebSocket connection:", err);
      this.connectionStatus = 'error';
      toast.error("Failed to connect to Shodan network stream");
      this.fallbackToGreynoise();
    }
  }

  private getReconnectDelay(): number {
    // Exponential backoff with jitter
    const baseDelay = this.reconnectDelay;
    const exponentialDelay = baseDelay * Math.pow(1.5, this.reconnectAttempts);
    const jitter = Math.random() * 0.3 * exponentialDelay;
    return Math.min(exponentialDelay + jitter, 30000); // Cap at 30 seconds
  }

  private async fallbackToGreynoise() {
    try {
      console.log("Falling back to simulated network data...");
      this.connectionStatus = 'connected';
      toast.info("Using simulated network data source");
      
      if (this.reconnectTimer) {
        clearTimeout(this.reconnectTimer);
        this.reconnectTimer = null;
      }
      
      let interval = setInterval(() => {
        const hour = new Date().getHours();
        const activityMultiplier = hour >= 9 && hour <= 17 ? 2.5 : 1;
        const maliciousChance = hour >= 22 || hour <= 5 ? 0.3 : 0.1;
        
        const mockEvent: NetworkEvent = {
          timestamp: new Date().toISOString(),
          ip: `${Math.floor(Math.random() * 223) + 1}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
          ports: this.generateRandomPorts(),
          tags: this.generateRandomTags(),
          classification: Math.random() < maliciousChance ? "malicious" : "benign"
        };
        
        this.notifyHandlers(mockEvent);
      }, 1500 / activityMultiplier);
      
      this.reconnectTimer = interval;
    } catch (err) {
      console.error("Error with data fallback:", err);
      this.connectionStatus = 'error';
      toast.error("Failed to initialize fallback data stream");
    }
  }

  private generateRandomPorts(): number[] {
    const commonPorts = [21, 22, 23, 25, 53, 80, 110, 143, 443, 587, 993, 995, 3306, 3389, 5900, 8080, 8443];
    const numPorts = Math.floor(Math.random() * 3) + 1;
    const ports = [];
    
    for (let i = 0; i < numPorts; i++) {
      if (Math.random() < 0.75) {
        ports.push(commonPorts[Math.floor(Math.random() * commonPorts.length)]);
      } else {
        ports.push(Math.floor(Math.random() * 65535) + 1);
      }
    }
    
    return [...new Set(ports)];
  }

  private generateRandomTags(): string[] {
    const allTags = [
      'http', 'https', 'ssh', 'ftp', 'telnet', 'smtp', 'database', 
      'cdn', 'cloud', 'dns', 'proxy', 'vpn', 'scanner', 'bot', 
      'crawler', 'malware', 'ransomware', 'trojan', 'backdoor', 'exploit'
    ];
    
    const numTags = Math.floor(Math.random() * 3);
    if (numTags === 0) return [];
    
    const tags = [];
    for (let i = 0; i < numTags; i++) {
      tags.push(allTags[Math.floor(Math.random() * allTags.length)]);
    }
    
    return [...new Set(tags)];
  }

  private normalizeEvent(event: any): NetworkEvent {
    const tags = [];
    
    if (event.data && event.data.http) tags.push('http');
    if (event.port === 443) tags.push('https');
    if (event.port === 22) tags.push('ssh');
    if (event.port === 21) tags.push('ftp');
    if (event.port === 23) tags.push('telnet');
    
    if (event.location && event.location.country_code) {
      tags.push(`geo:${event.location.country_code.toLowerCase()}`);
    }
    
    let classification = "benign";
    if (event.vulns && Object.keys(event.vulns).length > 0) {
      classification = "malicious";
      tags.push('vulnerable');
    }
    
    if (event.tags && event.tags.includes('malicious')) {
      classification = "malicious";
    }
    
    const ports = event.ports || [event.port] || [];
    
    return {
      timestamp: event.timestamp || new Date().toISOString(),
      ip: event.ip_str || event.ip || "unknown",
      ports: ports.filter(Boolean),
      tags: [...new Set([...tags, ...(event.tags || [])])],
      classification
    };
  }

  private reconnect() {
    this.reconnectAttempts++;
    console.log(`Attempting to reconnect (${this.reconnectAttempts}/${this.maxReconnectAttempts})...`);
    this.connect();
  }

  subscribe(handler: (event: NetworkEvent) => void) {
    this.dataHandlers.push(handler);
    
    if (this.dataHandlers.length === 1 && this.connectionStatus === 'disconnected') {
      this.connect();
    }
    
    return () => {
      this.dataHandlers = this.dataHandlers.filter(h => h !== handler);
      
      if (this.dataHandlers.length === 0) {
        this.disconnect();
      }
    };
  }

  private notifyHandlers(event: NetworkEvent) {
    this.dataHandlers.forEach(handler => handler(event));
  }

  disconnect() {
    if (this.shodanWs) {
      this.shodanWs.close();
      this.shodanWs = null;
    }
    
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    
    this.reconnectAttempts = 0;
    this.connectionStatus = 'disconnected';
    console.log("NetworkService disconnected");
  }
}

export const networkService = new NetworkService("OIuEKPTuhZ06hzrLaoizV3w2KPlCRUcx");
