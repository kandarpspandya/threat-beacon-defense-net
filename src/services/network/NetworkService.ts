
import { BaseNetworkService } from "./BaseNetworkService";
import { supabase } from "@/lib/supabase";
import { NetworkEvent } from "@/types/network";

class NetworkService extends BaseNetworkService {
  constructor() {
    super();
  }
  
  // Optional: Method to store network events in Supabase
  async storeNetworkEvent(event: NetworkEvent): Promise<void> {
    try {
      const { error } = await supabase
        .from('network_events')
        .insert({
          ip_address: event.sourceIp,
          ports: event.ports,
          country: event.geo?.country,
          classification: event.classification,
          tags: event.tags
        });
        
      if (error) {
        console.error('Error storing network event:', error);
      }
    } catch (err) {
      console.error('Failed to store network event:', err);
    }
  }
}

export const networkService = new NetworkService();
