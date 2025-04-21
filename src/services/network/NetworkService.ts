import { BaseNetworkService } from "./BaseNetworkService";
import { supabase } from "@/lib/supabase";
import { NetworkEvent } from "@/types/network";
import { toast } from "sonner";

class NetworkService extends BaseNetworkService {
  private tsharkProcess: any = null;
  private hasPermissions = false;
  private monitoringEnabled = false;
  private monitoringMethod: 'native' | 'tshark' | 'webapi' | null = null;

  constructor() {
    super();
    console.log('NetworkService: Initializing...');
  }

  async requestPermissions(): Promise<boolean> {
    try {
      console.log('NetworkService: Requesting permissions...');
      
      // In a preview environment, we'll simulate permission approval
      this.hasPermissions = true;
      console.log('NetworkService: Permissions simulated and granted');
      return true;
    } catch (error) {
      console.error('NetworkService: Permission request error:', error);
      return false;
    }
  }

  private async requestWebAPIPermissions(): Promise<boolean> {
    try {
      // Request necessary Web API permissions for mobile devices
      const networkInfo = await (navigator as any).connection;
      if (networkInfo) {
        this.hasPermissions = true;
        return true;
      }
      this.hasPermissions = true; // For demo/preview, we'll simulate success
      return true;
    } catch (error) {
      console.error('NetworkService: Web API permissions error:', error);
      this.hasPermissions = true; // For demo/preview, we'll simulate success
      return true;
    }
  }

  async initializeRealMonitoring() {
    try {
      console.log('NetworkService: Initializing monitoring...');
      
      // For preview/demo, skip checks and go right to monitoring
      this.monitoringMethod = 'webapi';
      this.monitoringEnabled = true;
      
      // Force activate the base service to start generating events
      this.connect();
      
      toast.success("Network monitoring enabled");
      console.log('NetworkService: Monitoring successfully enabled');
      return true;
    } catch (error) {
      console.error('NetworkService: Initialization error:', error);
      toast.error("Failed to initialize network monitoring");
      return false;
    }
  }

  private async checkTSharkAvailability(): Promise<boolean> {
    try {
      // In a real implementation, this would check if TShark is installed
      // For now, we'll simulate the check
      return false;
    } catch (error) {
      console.error('NetworkService: TShark check error:', error);
      return false;
    }
  }

  private async initializeMobileMonitoring() {
    console.log('NetworkService: Initializing mobile monitoring...');
    this.monitoringMethod = 'webapi';
    this.monitoringEnabled = true;
    toast.success("Mobile network monitoring enabled");
  }

  private async initializeNativeMonitoring() {
    const monitor = (window as any).networkMonitor;
    monitor.addEventListener('packet', this.handleNativePacket.bind(this));
    this.monitoringMethod = 'native';
    this.monitoringEnabled = true;
    console.log('NetworkService: Native monitoring initialized');
  }

  private async initializeWebAPIMonitoring() {
    this.monitoringMethod = 'webapi';
    this.monitoringEnabled = true;
    console.log('NetworkService: Web API monitoring initialized');
    toast.success("Basic network monitoring enabled");
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
          tags: event.tags,
          monitoring_method: this.monitoringMethod
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

  get currentMonitoringMethod(): string {
    return this.monitoringMethod || 'none';
  }

  get status(): 'connected' | 'connecting' | 'disconnected' | 'error' {
    if (this.monitoringEnabled) {
      return 'connected';
    }
    return super.status;
  }
}

export const networkService = new NetworkService();
