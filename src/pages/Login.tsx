
import { useState, useEffect, useRef } from "react";
import { Link, useNavigate } from "react-router-dom";
import { Shield, Mail, Lock, AlertCircle, Eye, EyeOff, User, ArrowRight } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { toast } from "sonner";

const Login = () => {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [showAnimation, setShowAnimation] = useState(false);
  const [particlesVisible, setParticlesVisible] = useState(false);
  const [formPosition, setFormPosition] = useState({ x: 0, y: 0 });
  const navigate = useNavigate();
  
  // Refs for animated elements
  const shieldRef = useRef<HTMLDivElement>(null);
  const particlesRef = useRef<HTMLDivElement[]>([]);
  
  useEffect(() => {
    // Trigger entrance animations sequentially
    const timer1 = setTimeout(() => setShowAnimation(true), 100);
    const timer2 = setTimeout(() => setParticlesVisible(true), 600);
    
    // Shield hover effect
    const interval = setInterval(() => {
      if (shieldRef.current) {
        const randomAngle = Math.random() * 10 - 5;
        shieldRef.current.style.transform = `rotate(${randomAngle}deg) scale(${1 + Math.random() * 0.1})`;
      }
    }, 3000);
    
    // Generate random particles
    particlesRef.current = Array.from({ length: 10 }).map(() => document.createElement('div'));
    
    return () => {
      clearTimeout(timer1);
      clearTimeout(timer2);
      clearInterval(interval);
    };
  }, []);
  
  // Subtle form movement on mouse move
  const handleMouseMove = (e: React.MouseEvent) => {
    const rect = e.currentTarget.getBoundingClientRect();
    const x = ((e.clientX - rect.left) / rect.width - 0.5) * 5;
    const y = ((e.clientY - rect.top) / rect.height - 0.5) * 5;
    setFormPosition({ x, y });
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsLoading(true);
    setError("");

    // Add pulse animation to shield during authentication
    if (shieldRef.current) {
      shieldRef.current.classList.add("animate-pulse");
    }

    // Basic validation
    if (!email || !password) {
      setError("Please enter both email and password");
      setIsLoading(false);
      if (shieldRef.current) {
        shieldRef.current.classList.remove("animate-pulse");
      }
      return;
    }

    // Email format validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      setError("Please enter a valid email address");
      setIsLoading(false);
      if (shieldRef.current) {
        shieldRef.current.classList.remove("animate-pulse");
      }
      return;
    }

    try {
      // In a real app, we would call an authentication API here
      // Mock authentication for demo - simulating API call
      setTimeout(() => {
        // Check if this user is registered (in a real app, this would be handled by the backend)
        const registeredUsers = JSON.parse(localStorage.getItem("registered-users") || "[]");
        const userExists = registeredUsers.some((user: any) => user.email === email);
        
        if (!userExists) {
          setError("Account not found. Please register first.");
          toast.error("Account not found", {
            description: "Please register to create a new account",
            action: {
              label: "Register",
              onClick: () => navigate("/register")
            }
          });
          if (shieldRef.current) {
            shieldRef.current.classList.remove("animate-pulse");
          }
          setIsLoading(false);
          return;
        }
        
        // Success path - set auth state and redirect
        localStorage.setItem("sentinel-auth", "true");
        
        // Create explosion effect before redirect
        if (shieldRef.current) {
          shieldRef.current.classList.add("scale-150", "opacity-0");
          setTimeout(() => {
            toast.success("Login successful", {
              description: "Welcome to SentinelNet"
            });
            navigate("/");
          }, 600);
        } else {
          toast.success("Login successful", {
            description: "Welcome to SentinelNet"
          });
          navigate("/");
        }
        
        setIsLoading(false);
      }, 1500);
    } catch (err) {
      console.error("Login error:", err);
      setError("Authentication failed. Please check your credentials.");
      if (shieldRef.current) {
        shieldRef.current.classList.remove("animate-pulse");
      }
      setIsLoading(false);
    }
  };

  return (
    <div 
      className="w-full max-w-md space-y-8 relative"
      onMouseMove={handleMouseMove}
    >
      {particlesVisible && (
        <div className="absolute inset-0 overflow-hidden pointer-events-none">
          <div className="security-particle left-[10%] top-[10%] animate-float"></div>
          <div className="security-particle left-[30%] top-[35%] delay-300 animate-float"></div>
          <div className="security-particle left-[70%] top-[15%] delay-700 animate-float"></div>
          <div className="security-particle left-[80%] top-[60%] delay-1000 animate-float"></div>
          <div className="security-particle left-[20%] top-[70%] delay-500 animate-float"></div>
        </div>
      )}
      
      <div 
        className={`text-center transition-all duration-700 transform ${showAnimation ? 'translate-y-0 opacity-100' : 'translate-y-10 opacity-0'}`}
        style={{ 
          transform: `translate3d(${formPosition.x}px, ${formPosition.y}px, 0) ${showAnimation ? 'translateY(0)' : 'translateY(10px)'}` 
        }}
      >
        <div 
          ref={shieldRef}
          className="mx-auto h-16 w-16 rounded-full bg-sentinel-dark/50 p-3 backdrop-blur-sm border border-sentinel-accent/30 shadow-[0_0_15px_rgba(100,255,218,0.2)] relative overflow-hidden transition-all duration-300"
        >
          <Shield className="h-full w-full text-sentinel-accent animate-pulse" />
          <div className="absolute inset-0 bg-gradient-to-r from-transparent via-sentinel-accent/20 to-transparent security-scan"></div>
        </div>
        <h2 className="mt-6 text-3xl font-bold text-white animate-text-gradient">SentinelNet</h2>
        <p className="mt-2 text-sm text-gray-400 animate-fade-in-delayed">
          Intelligent Threat Detection & Response
        </p>
      </div>

      {error && (
        <Alert variant="destructive" className="bg-destructive/20 border-destructive/50 animate-shake">
          <AlertCircle className="h-4 w-4" />
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      <form 
        className={`mt-8 space-y-6 transition-all duration-700 delay-300 transform ${showAnimation ? 'translate-y-0 opacity-100' : 'translate-y-10 opacity-0'}`} 
        onSubmit={handleSubmit}
        style={{ 
          transform: `translate3d(${formPosition.x * 0.5}px, ${formPosition.y * 0.5}px, 0) ${showAnimation ? 'translateY(0)' : 'translateY(10px)'}` 
        }}
      >
        <div className="space-y-4 rounded-md">
          <div className="relative group hover:scale-105 transition-transform duration-300">
            <Label htmlFor="email" className="block text-sm font-medium text-gray-200 transition-all duration-300 group-focus-within:text-sentinel-accent group-hover:text-sentinel-accent/80">
              Email
            </Label>
            <div className="mt-1 flex rounded-md shadow-sm">
              <div className="relative flex items-stretch flex-grow">
                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                  <Mail className="h-5 w-5 text-gray-400 transition-colors duration-300 group-focus-within:text-sentinel-accent group-hover:text-sentinel-accent/80" />
                </div>
                <Input
                  id="email"
                  name="email"
                  type="email"
                  autoComplete="email"
                  required
                  className="pl-10 focus:border-sentinel-accent focus:ring-sentinel-accent/50 bg-sentinel-dark/50 transition-all duration-300"
                  placeholder="you@example.com"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                />
              </div>
            </div>
          </div>

          <div className="relative group hover:scale-105 transition-transform duration-300">
            <Label htmlFor="password" className="block text-sm font-medium text-gray-200 transition-all duration-300 group-focus-within:text-sentinel-accent group-hover:text-sentinel-accent/80">
              Password
            </Label>
            <div className="mt-1 flex rounded-md shadow-sm">
              <div className="relative flex items-stretch flex-grow">
                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                  <Lock className="h-5 w-5 text-gray-400 transition-colors duration-300 group-focus-within:text-sentinel-accent group-hover:text-sentinel-accent/80" />
                </div>
                <Input
                  id="password"
                  name="password"
                  type={showPassword ? "text" : "password"}
                  autoComplete="current-password"
                  required
                  className="pl-10 pr-10 focus:border-sentinel-accent focus:ring-sentinel-accent/50 bg-sentinel-dark/50 transition-all duration-300"
                  placeholder="••••••••"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                />
                <button
                  type="button"
                  className="absolute inset-y-0 right-0 pr-3 flex items-center hover:text-sentinel-accent transition-colors"
                  onClick={() => setShowPassword(!showPassword)}
                >
                  {showPassword ? <EyeOff className="h-5 w-5" /> : <Eye className="h-5 w-5" />}
                </button>
              </div>
            </div>
          </div>
        </div>

        <div className="flex items-center justify-between animate-fade-in-delayed-2">
          <div className="text-sm">
            <span className="text-gray-400 mr-1">Don't have an account?</span>
            <Link to="/register" className="font-medium text-sentinel-accent hover:text-sentinel-accent/80 inline-flex items-center group">
              Sign up
              <ArrowRight className="ml-1 h-4 w-4 transform transition-transform group-hover:translate-x-1" />
            </Link>
          </div>
        </div>

        <Button
          type="submit"
          className="w-full bg-sentinel-accent hover:bg-sentinel-accent/90 text-sentinel-dark relative overflow-hidden group"
          disabled={isLoading}
        >
          <span className="relative z-10 flex items-center justify-center">
            {isLoading ? "Authenticating..." : "Sign in"}
          </span>
          <span className="absolute inset-0 translate-y-full group-hover:translate-y-0 bg-gradient-to-r from-cyan-500 to-blue-500 transition-transform duration-300"></span>
        </Button>
      </form>
    </div>
  );
};

export default Login;
