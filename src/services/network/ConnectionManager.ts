
export class ConnectionManager {
  private _status: 'connected' | 'connecting' | 'disconnected' | 'error' = 'disconnected';
  private reconnectTimeout: number | null = null;
  private maxReconnectAttempts = 5;
  private reconnectAttempts = 0;
  private reconnectDelay = 2000;

  get status(): 'connected' | 'connecting' | 'disconnected' | 'error' {
    return this._status;
  }

  connect(onConnected: () => void): void {
    if (this._status === 'connected' || this._status === 'connecting') {
      return;
    }
    
    this._status = 'connecting';
    
    setTimeout(() => {
      this._status = 'connected';
      this.reconnectAttempts = 0;
      onConnected();
    }, 2000);
  }

  disconnect(): void {
    this._status = 'disconnected';
    this.clearReconnectTimeout();
    this.reconnectAttempts = 0;
  }

  setError(): void {
    this._status = 'error';
    this.attemptReconnect();
  }

  private attemptReconnect(): void {
    if (this.reconnectTimeout !== null || this._status === 'connecting') {
      return;
    }
    
    if (this.reconnectAttempts < this.maxReconnectAttempts) {
      this.reconnectAttempts++;
      console.log(`Attempting to reconnect (${this.reconnectAttempts}/${this.maxReconnectAttempts})...`);
      
      this.reconnectTimeout = window.setTimeout(() => {
        this.reconnectTimeout = null;
        this.connect(() => {});
      }, this.getReconnectDelay());
    }
  }

  private getReconnectDelay(): number {
    const baseDelay = this.reconnectDelay;
    const exponentialDelay = baseDelay * Math.pow(1.5, this.reconnectAttempts);
    const jitter = Math.random() * 0.3 * exponentialDelay;
    return Math.min(exponentialDelay + jitter, 30000);
  }

  private clearReconnectTimeout(): void {
    if (this.reconnectTimeout !== null) {
      window.clearTimeout(this.reconnectTimeout);
      this.reconnectTimeout = null;
    }
  }
}

