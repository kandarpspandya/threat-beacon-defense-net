
import { Outlet, Navigate } from "react-router-dom";
import { useEffect } from "react";

// Mock authentication check - this would be replaced with real auth logic
const isAuthenticated = () => {
  return localStorage.getItem("sentinel-auth") === "true";
};

const AuthLayout = () => {
  useEffect(() => {
    // Add a cybersecurity background effect to auth pages
    document.body.classList.add("grid-pattern");
    return () => {
      document.body.classList.remove("grid-pattern");
    };
  }, []);

  // Redirect to dashboard if already authenticated
  if (isAuthenticated()) {
    return <Navigate to="/" replace />;
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-sentinel-dark">
      <div className="w-full max-w-md p-8 space-y-8 animate-fade-in">
        <Outlet />
      </div>
    </div>
  );
};

export default AuthLayout;
