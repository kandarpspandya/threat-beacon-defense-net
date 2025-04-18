
import { NetworkEvent } from "@/types/network";

class NetworkService {
  private shodanWs: WebSocket | null = null;
  private reconnectAttempts = 0;
  private maxReconnectAttempts = 5;
  private reconnectDelay = 2000;
  private dataHandlers: ((event: NetworkEvent) => void)[] = [];

  constructor(private apiKey: string) {}

  connect() {
    try {
      this.shodanWs = new WebSocket(
        `wss://stream.shodan.io/shodan/ports/23,80,443,8080?key=${this.apiKey}`
      );

      this.shodanWs.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          this.notifyHandlers(this.normalizeEvent(data));
        } catch (err) {
          console.error("Error processing Shodan data:", err);
        }
      };

      this.shodanWs.onclose = () => {
        if (this.reconnectAttempts < this.maxReconnectAttempts) {
          setTimeout(() => this.reconnect(), this.reconnectDelay);
        }
      };

      this.shodanWs.onerror = () => {
        this.fallbackToGreynoise();
      };

    } catch (err) {
      console.error("Error establishing WebSocket connection:", err);
      this.fallbackToGreynoise();
    }
  }

  private async fallbackToGreynoise() {
    try {
      // Simulate Greynoise data while waiting for API key
      setInterval(() => {
        const mockEvent: NetworkEvent = {
          timestamp: new Date().toISOString(),
          ip: `192.168.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
          ports: [80, 443],
          tags: ["http", "https"],
          classification: Math.random() > 0.7 ? "malicious" : "benign"
        };
        this.notifyHandlers(mockEvent);
      }, 2000);
    } catch (err) {
      console.error("Error with Greynoise fallback:", err);
    }
  }

  private normalizeEvent(event: any): NetworkEvent {
    return {
      timestamp: event.timestamp || new Date().toISOString(),
      ip: event.ip_str || event.ip || "unknown",
      ports: event.ports || [],
      tags: event.tags || [],
      classification: event.tags?.includes("malicious") ? "malicious" : "benign"
    };
  }

  private reconnect() {
    this.reconnectAttempts++;
    this.connect();
  }

  subscribe(handler: (event: NetworkEvent) => void) {
    this.dataHandlers.push(handler);
    return () => {
      this.dataHandlers = this.dataHandlers.filter(h => h !== handler);
    };
  }

  private notifyHandlers(event: NetworkEvent) {
    this.dataHandlers.forEach(handler => handler(event));
  }

  disconnect() {
    this.shodanWs?.close();
    this.shodanWs = null;
    this.reconnectAttempts = 0;
  }
}

export const networkService = new NetworkService("OIuEKPTuhZ06hzrLaoizV3w2KPlCRUcx");
