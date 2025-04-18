
import { useState } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { FileType, Upload } from "lucide-react";
import { Progress } from "@/components/ui/progress";

export const PcapUploader = () => {
  const [isUploading, setIsUploading] = useState(false);
  const [uploadProgress, setUploadProgress] = useState(0);

  const handlePcapUpload = () => {
    setIsUploading(true);
    setUploadProgress(0);
    
    // Simulate upload progress
    const interval = setInterval(() => {
      setUploadProgress((prev) => {
        if (prev >= 100) {
          clearInterval(interval);
          setIsUploading(false);
          return 100;
        }
        return prev + 10;
      });
    }, 300);
  };

  return (
    <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm">
      <CardHeader>
        <CardTitle>Network Capture Analysis</CardTitle>
        <CardDescription>
          Upload PCAP files for detailed traffic inspection
        </CardDescription>
      </CardHeader>
      <CardContent>
        <div className="flex flex-col items-center justify-center space-y-4 rounded-md border-2 border-dashed border-sentinel-light/20 p-8">
          <FileType className="h-12 w-12 text-sentinel-accent/70" />
          <div className="space-y-1 text-center">
            <p className="text-sm text-muted-foreground">
              Drag and drop PCAP files here, or click to browse
            </p>
            <p className="text-xs text-muted-foreground">
              Maximum file size: 100MB
            </p>
          </div>
          {isUploading ? (
            <div className="w-full max-w-xs space-y-2">
              <div className="flex justify-between text-xs text-muted-foreground">
                <span>Uploading...</span>
                <span>{uploadProgress}%</span>
              </div>
              <Progress value={uploadProgress} className="h-2" />
            </div>
          ) : (
            <Button onClick={handlePcapUpload}>
              <Upload className="mr-2 h-4 w-4" />
              Upload PCAP File
            </Button>
          )}
        </div>
      </CardContent>
    </Card>
  );
};
