
import { NetworkEvent } from "@/types/network";
import { toast } from "sonner";
import { NetworkServiceInterface } from "./types";
import { generateRandomPorts, generateRandomTags } from "./dataGenerators";
import { normalizeEvent } from "./eventNormalizer";

class NetworkService implements NetworkServiceInterface {
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
          this.notifyHandlers(normalizeEvent(data));
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
      
      // Clear any existing interval
      if (this.reconnectTimer) {
        clearTimeout(this.reconnectTimer);
        this.reconnectTimer = null;
      }
      
      // Simulate Greynoise data with more realistic patterns
      let interval = setInterval(() => {
        // Network activity follows daily patterns
        const hour = new Date().getHours();
        // More activity during work hours, less at night
        const activityMultiplier = hour >= 9 && hour <= 17 ? 2.5 : 1; 
        // Random chance for malicious events (higher during non-work hours)
        const maliciousChance = hour >= 22 || hour <= 5 ? 0.3 : 0.1;
        
        const mockEvent: NetworkEvent = {
          timestamp: new Date().toISOString(),
          ip: `${Math.floor(Math.random() * 223) + 1}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
          ports: generateRandomPorts(),
          tags: generateRandomTags(),
          classification: Math.random() < maliciousChance ? "malicious" : "benign"
        };
        
        this.notifyHandlers(mockEvent);
      }, 1500 / activityMultiplier); // Using activityMultiplier to adjust frequency
      
      // Store the interval ID for cleanup
      this.reconnectTimer = interval;
    } catch (err) {
      console.error("Error with data fallback:", err);
      this.connectionStatus = 'error';
      toast.error("Failed to initialize fallback data stream");
    }
  }

  private reconnect() {
    this.reconnectAttempts++;
    console.log(`Attempting to reconnect (${this.reconnectAttempts}/${this.maxReconnectAttempts})...`);
    this.connect();
  }

  subscribe(handler: (event: NetworkEvent) => void) {
    this.dataHandlers.push(handler);
    
    // Auto-connect when the first subscriber is added
    if (this.dataHandlers.length === 1 && this.connectionStatus === 'disconnected') {
      this.connect();
    }
    
    return () => {
      this.dataHandlers = this.dataHandlers.filter(h => h !== handler);
      
      // Auto-disconnect when the last subscriber is removed
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

// Use your Shodan API key from before
export const networkService = new NetworkService("OIuEKPTuhZ06hzrLaoizV3w2KPlCRUcx");
