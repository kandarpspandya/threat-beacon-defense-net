
import { Outlet, Navigate } from "react-router-dom";
import { useEffect, useState } from "react";
import { toast } from "sonner";
import { useAuth } from "@/contexts/AuthContext";

const AuthLayout = () => {
  const [particles, setParticles] = useState<Array<{id: number, size: number, x: number, y: number, speed: number, blinking: boolean}>>([]);
  const { user, isLoading } = useAuth();
  
  useEffect(() => {
    // Add a cybersecurity background effect to auth pages
    document.body.classList.add("grid-pattern");
    
    // Create particles for the background
    const newParticles = Array.from({ length: 30 }, (_, i) => ({
      id: i,
      size: Math.random() * 3 + 1,
      x: Math.random() * 100,
      y: Math.random() * 100,
      speed: Math.random() * 2 + 0.5,
      blinking: Math.random() > 0.7
    }));
    setParticles(newParticles);
    
    // Display a toast message for unauthenticated users
    if (!isLoading && !user) {
      toast.info("Please sign in to access SentinelNet", {
        duration: 4000,
      });
    }
    
    return () => {
      document.body.classList.remove("grid-pattern");
    };
  }, [isLoading, user]);

  // Show loading indicator while auth state is being determined
  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-sentinel-dark">
        <div className="animate-pulse text-sentinel-accent">Loading...</div>
      </div>
    );
  }

  // Redirect to dashboard if already authenticated
  if (user) {
    return <Navigate to="/" replace />;
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-sentinel-dark overflow-hidden relative">
      {/* Animated background elements */}
      <div className="absolute inset-0 overflow-hidden opacity-30 pointer-events-none">
        {particles.map(particle => (
          <div 
            key={particle.id}
            className={`absolute rounded-full ${particle.blinking ? 'animate-pulse' : ''}`}
            style={{
              width: `${particle.size}px`,
              height: `${particle.size}px`,
              backgroundColor: `rgba(100, 255, 218, ${Math.random() * 0.3 + 0.1})`,
              left: `${particle.x}%`,
              top: `${particle.y}%`,
              animationDuration: `${particle.speed}s`,
              boxShadow: `0 0 ${particle.size * 2}px rgba(100, 255, 218, 0.6)`
            }}
          />
        ))}
        <div className="absolute top-0 left-0 w-full h-full bg-gradient-to-br from-sentinel-dark/80 via-sentinel-dark/40 to-sentinel-medium/30"></div>
        <div className="security-signal"></div>
      </div>
      
      <div className="w-full max-w-md p-8 space-y-8 animate-fade-in backdrop-blur-sm bg-sentinel-dark/70 rounded-xl border border-sentinel-light/10 shadow-[0_0_15px_rgba(100,255,218,0.15)] z-10 hover:shadow-[0_0_25px_rgba(100,255,218,0.25)] transition-all duration-500">
        <Outlet />
      </div>
      
      {/* Network connection lines */}
      <svg className="absolute inset-0 w-full h-full z-0 opacity-10" xmlns="http://www.w3.org/2000/svg">
        <defs>
          <filter id="glow">
            <feGaussianBlur result="coloredBlur" stdDeviation="2"></feGaussianBlur>
            <feMerge>
              <feMergeNode in="coloredBlur"></feMergeNode>
              <feMergeNode in="SourceGraphic"></feMergeNode>
            </feMerge>
          </filter>
        </defs>
        <line x1="20%" y1="20%" x2="80%" y2="80%" stroke="#64FFDA" strokeWidth="1" filter="url(#glow)">
          <animate attributeName="opacity" values="0.2;0.5;0.2" dur="4s" repeatCount="indefinite" />
        </line>
        <line x1="80%" y1="20%" x2="20%" y2="80%" stroke="#64FFDA" strokeWidth="1" filter="url(#glow)">
          <animate attributeName="opacity" values="0.3;0.6;0.3" dur="3s" repeatCount="indefinite" />
        </line>
        <line x1="50%" y1="10%" x2="50%" y2="90%" stroke="#64FFDA" strokeWidth="1" filter="url(#glow)">
          <animate attributeName="opacity" values="0.2;0.4;0.2" dur="5s" repeatCount="indefinite" />
        </line>
        <line x1="10%" y1="50%" x2="90%" y2="50%" stroke="#64FFDA" strokeWidth="1" filter="url(#glow)">
          <animate attributeName="opacity" values="0.1;0.3;0.1" dur="6s" repeatCount="indefinite" />
        </line>
      </svg>
    </div>
  );
};

export default AuthLayout;
