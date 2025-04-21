
import { useState } from "react";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Info } from "lucide-react";

interface NetworkConsentDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onAccept: () => void;
}

export function NetworkConsentDialog({ open, onOpenChange, onAccept }: NetworkConsentDialogProps) {
  const [loading, setLoading] = useState(false);

  const handleAccept = async () => {
    console.log('[ConsentDialog] Enable Monitoring button clicked'); // Diagnostic log
    setLoading(true);
    try {
      onAccept();
    } catch (error) {
      console.error('Error when enabling monitoring:', error);
    } finally {
      setLoading(false);
    }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-[500px]">
        <DialogHeader>
          <DialogTitle>Enable Network Monitoring</DialogTitle>
          <DialogDescription>
            To provide real-time network analysis, <b>IDPS.net</b> needs access to your network traffic data.
          </DialogDescription>
        </DialogHeader>
        
        <div className="space-y-4">
          <Alert>
            <Info className="h-4 w-4" />
            <AlertDescription>
              This will enable:
              <ul className="list-disc pl-4 mt-2 space-y-1">
                <li>Network traffic monitoring</li>
                <li>Protocol analysis</li>
                <li>Threat detection</li>
                <li>Performance metrics</li>
              </ul>
            </AlertDescription>
          </Alert>
          
          <p className="text-sm text-muted-foreground">
            Your data is processed locally on your device. No sensitive information is sent to our servers.
          </p>
        </div>

        <DialogFooter className="flex space-x-2 mt-4">
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button onClick={handleAccept} disabled={loading}>
            {loading ? "Enabling..." : "Enable Monitoring"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
