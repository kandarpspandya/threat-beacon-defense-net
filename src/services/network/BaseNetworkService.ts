
import { NetworkEvent } from "@/types/network";
import { NetworkServiceInterface } from "./types";
import { ConnectionManager } from "./ConnectionManager";
import { EventProcessor } from "./EventProcessor";

export class BaseNetworkService implements NetworkServiceInterface {
  protected handlers: ((event: NetworkEvent) => void)[] = [];
  protected eventProcessor: EventProcessor;
  protected connectionManager: ConnectionManager;

  constructor() {
    this.eventProcessor = new EventProcessor();
    this.connectionManager = new ConnectionManager();
  }

  get status(): 'connected' | 'connecting' | 'disconnected' | 'error' {
    return this.connectionManager.status;
  }

  connect(): void {
    this.connectionManager.connect(() => this.eventProcessor.startEventSimulation(this.broadcast.bind(this)));
  }

  disconnect(): void {
    this.connectionManager.disconnect();
    this.eventProcessor.stopEventSimulation();
  }

  subscribe(handler: (event: NetworkEvent) => void): () => void {
    this.handlers.push(handler);
    
    if (this.handlers.length === 1 && this.status === 'disconnected') {
      this.connect();
    }
    
    return () => {
      this.handlers = this.handlers.filter(h => h !== handler);
      if (this.handlers.length === 0) {
        this.disconnect();
      }
    };
  }

  protected broadcast(event: NetworkEvent): void {
    const currentHandlers = [...this.handlers];
    for (const handler of currentHandlers) {
      try {
        handler(event);
      } catch (error) {
        console.error("Error in network event handler:", error);
      }
    }
  }
}

