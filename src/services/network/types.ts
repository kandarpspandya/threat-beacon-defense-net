
import { NetworkEvent } from "@/types/network";

export interface NetworkServiceInterface {
  status: 'connected' | 'connecting' | 'disconnected' | 'error';
  connect(): void;
  subscribe(handler: (event: NetworkEvent) => void): () => void;
  disconnect(): void;
}
