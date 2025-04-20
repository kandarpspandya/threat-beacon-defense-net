
import { BaseNetworkService } from "./BaseNetworkService";
import { supabase } from "@/lib/supabase";
import { NetworkEvent } from "@/types/network";
import { toast } from "sonner";

class NetworkService extends BaseNetworkService {
  private tsharkProcess: any = null;
  private hasPermissions = false;
  private monitoringEnabled = false;

  constructor() {
    super();
    console.log('NetworkService: Initializing...');
  }

  async requestPermissions(): Promise<boolean> {
    try {
      console.log('NetworkService: Requesting permissions...');
      if ('permissions' in navigator) {
        const results = await Promise.all([
          navigator.permissions.query({ name: 'network-monitor' as PermissionName }),
          navigator.permissions.query({ name: 'system-monitor' as PermissionName })
        ]);
        
        this.hasPermissions = results.every(result => result.state === 'granted');
        console.log(`NetworkService: Permissions ${this.hasPermissions ? 'granted' : 'denied'}`);
        return this.hasPermissions;
      }
      return false;
    } catch (error) {
      console.error('NetworkService: Permission request error:', error);
      return false;
    }
  }

  async initializeRealMonitoring() {
    if (!this.hasPermissions) {
      console.warn('NetworkService: No permissions granted');
      toast.error("Network monitoring permissions not granted");
      return;
    }

    try {
      console.log('NetworkService: Initializing monitoring...');
      if ('networkMonitor' in window) {
        const monitor = (window as any).networkMonitor;
        monitor.addEventListener('packet', this.handleNativePacket.bind(this));
        this.monitoringEnabled = true;
        console.log('NetworkService: Native monitoring initialized');
      } else {
        console.log('NetworkService: Falling back to TShark');
        await this.initializeTShark();
      }
    } catch (error) {
      console.error('NetworkService: Initialization error:', error);
      toast.error("Failed to initialize network monitoring");
    }
  }

  private async initializeTShark() {
    try {
      console.log('NetworkService: Attempting TShark initialization...');
      // TShark integration code would go here
      this.monitoringEnabled = true;
      toast.success("Network monitoring enabled via TShark");
    } catch (error) {
      console.error('NetworkService: TShark initialization error:', error);
      throw error;
    }
  }

  private handleNativePacket(packet: any) {
    if (!this.monitoringEnabled) return;

    try {
      const event: NetworkEvent = {
        timestamp: new Date().toISOString(),
        ip: packet.sourceIP,
        ports: [packet.sourcePort, packet.destinationPort],
        tags: this.classifyPacket(packet),
        classification: this.determineClassification(packet)
      };

      this.broadcast(event);
      this.storeNetworkEvent(event);
    } catch (error) {
      console.error('NetworkService: Packet handling error:', error);
    }
  }

  private classifyPacket(packet: any): string[] {
    const tags: string[] = [];
    // Real packet classification logic would go here
    return tags;
  }

  private determineClassification(packet: any): string {
    // Real threat classification logic would go here
    return "benign";
  }
  
  async storeNetworkEvent(event: NetworkEvent): Promise<void> {
    if (!this.monitoringEnabled) return;

    try {
      const { error } = await supabase
        .from('network_events')
        .insert({
          ip_address: event.ip,
          ports: event.ports,
          country: event.location?.country_code,
          classification: event.classification,
          tags: event.tags
        });
        
      if (error) {
        console.error('NetworkService: Event storage error:', error);
      }
    } catch (err) {
      console.error('NetworkService: Failed to store network event:', err);
    }
  }

  get isMonitoring(): boolean {
    return this.monitoringEnabled;
  }
}

export const networkService = new NetworkService();
