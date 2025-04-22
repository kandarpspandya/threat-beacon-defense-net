
import { useEffect } from "react";
import { useNavigate } from "react-router-dom";

const Index = () => {
  const navigate = useNavigate();
  
  useEffect(() => {
    // Redirect to dashboard without creating an infinite loop
    // by checking if we're already on the home page
    const currentPath = window.location.pathname;
    if (currentPath === "/" || currentPath === "") {
      // We're already on the index route, load the Dashboard component directly
      console.log("Index: Already on root path, loading dashboard");
    } else {
      // Only redirect if we're not already on the home path
      navigate("/");
    }
  }, [navigate]);

  return (
    <div className="min-h-screen flex items-center justify-center bg-sentinel-dark">
      <div className="text-center">
        <h1 className="text-4xl font-bold mb-4 text-sentinel-accent">IDPS.net Loading...</h1>
        <p className="text-xl text-gray-400">Initializing security monitoring system</p>
      </div>
    </div>
  );
};

export default Index;
