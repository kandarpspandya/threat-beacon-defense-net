
import { NetworkEvent } from "@/types/network";
import { generateGreyNoiseData, generateNetworkEvent } from "./dataGenerators";
import { eventNormalizer } from "./eventNormalizer";

export class EventProcessor {
  private eventInterval: number | null = null;
  private simulationActive = false;

  startEventSimulation(broadcast: (event: NetworkEvent) => void): void {
    if (this.simulationActive) return;
    
    this.simulationActive = true;
    
    if (this.eventInterval !== null) {
      window.clearInterval(this.eventInterval);
    }
    
    const eventsPerSecond = Math.floor(Math.random() * 5) + 1;
    const interval = Math.floor(1000 / eventsPerSecond);
    
    this.eventInterval = window.setInterval(() => {
      if (!this.simulationActive) {
        this.stopEventSimulation();
        return;
      }
      
      try {
        if (Math.random() < 0.2) {
          const hour = new Date().getHours();
          const activityMultiplier = hour >= 9 && hour <= 17 ? 2.5 : 1;
          const greynoiseData = generateGreyNoiseData(activityMultiplier);
          broadcast(eventNormalizer(greynoiseData));
        } else {
          broadcast(generateNetworkEvent());
        }
      } catch (error) {
        console.error("Error generating network event:", error);
        throw error;
      }
    }, interval);
  }

  stopEventSimulation(): void {
    this.simulationActive = false;
    
    if (this.eventInterval !== null) {
      window.clearInterval(this.eventInterval);
      this.eventInterval = null;
    }
  }
}

