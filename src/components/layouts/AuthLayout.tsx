
import { Outlet, Navigate } from "react-router-dom";
import { useEffect } from "react";
import { toast } from "sonner";

// Mock authentication check - this would be replaced with real auth logic
const isAuthenticated = () => {
  return localStorage.getItem("sentinel-auth") === "true";
};

const AuthLayout = () => {
  useEffect(() => {
    // Add a cybersecurity background effect to auth pages
    document.body.classList.add("grid-pattern");
    
    // Display a toast message for unauthenticated users
    if (!isAuthenticated()) {
      toast.info("Please sign in to access SentinelNet", {
        duration: 4000,
      });
    }
    
    return () => {
      document.body.classList.remove("grid-pattern");
    };
  }, []);

  // Redirect to dashboard if already authenticated
  if (isAuthenticated()) {
    return <Navigate to="/" replace />;
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-sentinel-dark overflow-hidden relative">
      {/* Animated background elements */}
      <div className="absolute inset-0 overflow-hidden opacity-30 pointer-events-none">
        <div className="security-particle left-[10%] top-[10%]"></div>
        <div className="security-particle left-[30%] top-[35%] delay-300"></div>
        <div className="security-particle left-[70%] top-[15%] delay-700"></div>
        <div className="security-particle left-[80%] top-[60%] delay-1000"></div>
        <div className="security-particle left-[20%] top-[70%] delay-500"></div>
        <div className="security-signal"></div>
      </div>
      
      <div className="w-full max-w-md p-8 space-y-8 animate-fade-in backdrop-blur-sm bg-sentinel-dark/70 rounded-xl border border-sentinel-light/10 shadow-[0_0_15px_rgba(100,255,218,0.15)] z-10">
        <Outlet />
      </div>
    </div>
  );
};

export default AuthLayout;
