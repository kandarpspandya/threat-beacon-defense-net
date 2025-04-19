
import { NetworkEvent } from "@/types/network";
import { NetworkServiceInterface } from "./types";
import { eventNormalizer } from "./eventNormalizer";
import { generateGreyNoiseData, generateNetworkEvent } from "./dataGenerators";

class NetworkService implements NetworkServiceInterface {
  private handlers: ((event: NetworkEvent) => void)[] = [];
  private eventInterval: number | null = null;
  private reconnectTimeout: number | null = null;
  private _status: 'connected' | 'connecting' | 'disconnected' | 'error' = 'disconnected';
  private eventRate = 1000; // 1 event per second by default
  private simulationActive = false;
  
  constructor() {
    // Initialize with disconnected status
    this._status = 'disconnected';
  }
  
  get status(): 'connected' | 'connecting' | 'disconnected' | 'error' {
    return this._status;
  }
  
  /**
   * Connect to the network monitoring service
   */
  connect(): void {
    if (this._status === 'connected' || this._status === 'connecting') {
      return;
    }
    
    this._status = 'connecting';
    
    // Simulate connection process
    setTimeout(() => {
      this._status = 'connected';
      this.startEventSimulation();
    }, 2000);
  }
  
  /**
   * Disconnect from the network monitoring service
   */
  disconnect(): void {
    this._status = 'disconnected';
    this.stopEventSimulation();
    
    // Clear any pending reconnect attempts
    if (this.reconnectTimeout !== null) {
      window.clearTimeout(this.reconnectTimeout);
      this.reconnectTimeout = null;
    }
  }
  
  /**
   * Subscribe to network events
   * @param handler Function to call when a network event is received
   * @returns Function to unsubscribe
   */
  subscribe(handler: (event: NetworkEvent) => void): () => void {
    // Add the handler to our list
    this.handlers.push(handler);
    
    // If this is the first handler, start the connection
    if (this.handlers.length === 1 && this._status === 'disconnected') {
      this.connect();
    }
    
    // Return a function to unsubscribe
    return () => {
      this.handlers = this.handlers.filter(h => h !== handler);
      
      // If there are no more handlers, disconnect
      if (this.handlers.length === 0) {
        this.disconnect();
      }
    };
  }
  
  /**
   * Simulate network events for testing and demonstration
   */
  private startEventSimulation(): void {
    if (this.simulationActive) return;
    
    this.simulationActive = true;
    this.emitEvents();
  }
  
  private stopEventSimulation(): void {
    this.simulationActive = false;
    
    if (this.eventInterval !== null) {
      window.clearInterval(this.eventInterval);
      this.eventInterval = null;
    }
  }
  
  private emitEvents(): void {
    // Clear any existing interval
    if (this.eventInterval !== null) {
      window.clearInterval(this.eventInterval);
    }
    
    // Generate a random number of events per second (between 1-5)
    const eventsPerSecond = Math.floor(Math.random() * 5) + 1;
    const interval = Math.floor(1000 / eventsPerSecond);
    
    this.eventInterval = window.setInterval(() => {
      if (!this.simulationActive) {
        this.stopEventSimulation();
        return;
      }
      
      try {
        // 20% chance to simulate GreyNoise data integration
        if (Math.random() < 0.2) {
          this.fallbackToGreynoise();
        } else {
          const event = generateNetworkEvent();
          this.broadcast(event);
        }
      } catch (error) {
        console.error("Error generating network event:", error);
        this._status = 'error';
        
        // Attempt to reconnect after a delay
        this.attemptReconnect();
      }
    }, interval);
  }
  
  private fallbackToGreynoise(): void {
    try {
      const activityMultiplier = Math.random() * 2 + 0.5; // Random multiplier between 0.5 and 2.5
      const greynoiseData = generateGreyNoiseData(activityMultiplier);
      const normalizedEvent = eventNormalizer(greynoiseData);
      this.broadcast(normalizedEvent);
    } catch (error) {
      console.error("Error using GreyNoise fallback:", error);
      this._status = 'error';
      this.attemptReconnect();
    }
  }
  
  private broadcast(event: NetworkEvent): void {
    // Clone the handlers array in case handlers are added/removed during iteration
    const currentHandlers = [...this.handlers];
    
    // Notify all subscribers
    for (const handler of currentHandlers) {
      try {
        handler(event);
      } catch (error) {
        console.error("Error in network event handler:", error);
      }
    }
  }
  
  private attemptReconnect(): void {
    // Only attempt to reconnect if we're not already trying
    if (this.reconnectTimeout !== null || this._status === 'connecting') {
      return;
    }
    
    this.stopEventSimulation();
    
    // Wait 5 seconds before reconnecting
    this.reconnectTimeout = window.setTimeout(() => {
      this.reconnectTimeout = null;
      this.connect();
    }, 5000);
  }
}

// Create a singleton instance
export const networkService = new NetworkService();
