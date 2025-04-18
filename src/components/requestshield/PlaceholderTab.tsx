
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";

interface PlaceholderTabProps {
  title: string;
  description: string;
  icon: React.ReactNode;
  buttonLabel: string;
}

export const PlaceholderTab = ({ title, description, icon, buttonLabel }: PlaceholderTabProps) => {
  return (
    <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm h-[300px] flex items-center justify-center">
      <div className="text-center p-6">
        <div className="h-16 w-16 mx-auto text-sentinel-info opacity-50 mb-4">
          {icon}
        </div>
        <h3 className="text-xl font-semibold mb-2">{title}</h3>
        <p className="text-muted-foreground mb-4">
          {description}
        </p>
        <Button variant="outline">{buttonLabel}</Button>
      </div>
    </Card>
  );
};
