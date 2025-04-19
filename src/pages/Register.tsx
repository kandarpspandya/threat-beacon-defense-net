import { useState, useEffect, useRef } from "react";
import { Link, useNavigate } from "react-router-dom";
import { Shield, Mail, Lock, User, AlertCircle, Eye, EyeOff, ArrowLeft } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { toast } from "sonner";
import { useAuth } from "@/contexts/AuthContext";

const Register = () => {
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [error, setError] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const [showAnimation, setShowAnimation] = useState(false);
  const [formPosition, setFormPosition] = useState({ x: 0, y: 0 });
  const navigate = useNavigate();
  const { signUp } = useAuth();
  
  // Ref for animated shield
  const shieldRef = useRef<HTMLDivElement>(null);
  
  useEffect(() => {
    // Trigger entrance animations
    const timer = setTimeout(() => {
      setShowAnimation(true);
    }, 100);
    
    // Shield pulse animation
    const interval = setInterval(() => {
      if (shieldRef.current) {
        shieldRef.current.classList.add("scale-110");
        setTimeout(() => {
          if (shieldRef.current) {
            shieldRef.current.classList.remove("scale-110");
          }
        }, 300);
      }
    }, 3000);
    
    return () => {
      clearTimeout(timer);
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

    // Add pulse animation to shield during submission
    if (shieldRef.current) {
      shieldRef.current.classList.add("animate-pulse");
    }

    // Basic validation
    if (!name || !email || !password || !confirmPassword) {
      setError("Please fill out all fields");
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

    // Password strength validation
    if (password.length < 8) {
      setError("Password must be at least 8 characters long");
      setIsLoading(false);
      if (shieldRef.current) {
        shieldRef.current.classList.remove("animate-pulse");
      }
      return;
    }

    // Password match validation
    if (password !== confirmPassword) {
      setError("Passwords do not match");
      setIsLoading(false);
      if (shieldRef.current) {
        shieldRef.current.classList.remove("animate-pulse");
      }
      return;
    }

    try {
      const { success, error } = await signUp(email, password, name);
      
      if (!success) {
        setError(error || "Registration failed");
        if (error?.includes("already registered")) {
          toast.error("Account already exists", {
            description: "Please sign in instead",
            action: {
              label: "Sign In",
              onClick: () => navigate("/login")
            }
          });
        }
        if (shieldRef.current) {
          shieldRef.current.classList.remove("animate-pulse");
        }
        setIsLoading(false);
        return;
      }
      
      // Success path
      if (shieldRef.current) {
        shieldRef.current.classList.add("scale-150", "opacity-0");
        setTimeout(() => {
          toast.success("Registration successful", {
            description: `Welcome to SentinelNet, ${name}!`
          });
          navigate("/");
        }, 600);
      } else {
        toast.success("Registration successful", {
          description: `Welcome to SentinelNet, ${name}!`
        });
        navigate("/");
      }
    } catch (err) {
      console.error("Registration error:", err);
      setError("Registration failed. Please try again.");
      if (shieldRef.current) {
        shieldRef.current.classList.remove("animate-pulse");
      }
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div 
      className="w-full max-w-md space-y-8"
      onMouseMove={handleMouseMove}
    >
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
          <Shield className="h-full w-full text-sentinel-accent" />
          <div className="absolute inset-0 bg-gradient-to-r from-transparent via-sentinel-accent/20 to-transparent security-scan"></div>
        </div>
        <h2 className="mt-6 text-3xl font-bold text-white bg-gradient-to-r from-white via-sentinel-accent to-cyan-500 bg-clip-text text-transparent">Create Account</h2>
        <p className="mt-2 text-sm text-gray-400">
          Join SentinelNet and secure your network
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
          <div className="group hover:scale-105 transition-transform duration-300">
            <Label htmlFor="name" className="block text-sm font-medium text-gray-200 transition-all duration-300 group-focus-within:text-sentinel-accent group-hover:text-sentinel-accent/80">
              Full Name
            </Label>
            <div className="mt-1 flex rounded-md shadow-sm">
              <div className="relative flex items-stretch flex-grow">
                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                  <User className="h-5 w-5 text-gray-400 transition-colors duration-300 group-focus-within:text-sentinel-accent group-hover:text-sentinel-accent/80" />
                </div>
                <Input
                  id="name"
                  name="name"
                  type="text"
                  autoComplete="name"
                  required
                  className="pl-10 focus:border-sentinel-accent focus:ring-sentinel-accent/50 bg-sentinel-dark/50"
                  placeholder="John Doe"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                />
              </div>
            </div>
          </div>

          <div className="group hover:scale-105 transition-transform duration-300">
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
                  className="pl-10 focus:border-sentinel-accent focus:ring-sentinel-accent/50 bg-sentinel-dark/50"
                  placeholder="you@example.com"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                />
              </div>
            </div>
          </div>

          <div className="group hover:scale-105 transition-transform duration-300">
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
                  autoComplete="new-password"
                  required
                  className="pl-10 pr-10 focus:border-sentinel-accent focus:ring-sentinel-accent/50 bg-sentinel-dark/50"
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
            <p className="mt-1 text-xs text-gray-400">
              Password must be at least 8 characters long
            </p>
          </div>

          <div className="group hover:scale-105 transition-transform duration-300">
            <Label htmlFor="confirm-password" className="block text-sm font-medium text-gray-200 transition-all duration-300 group-focus-within:text-sentinel-accent group-hover:text-sentinel-accent/80">
              Confirm Password
            </Label>
            <div className="mt-1 flex rounded-md shadow-sm">
              <div className="relative flex items-stretch flex-grow">
                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                  <Lock className="h-5 w-5 text-gray-400 transition-colors duration-300 group-focus-within:text-sentinel-accent group-hover:text-sentinel-accent/80" />
                </div>
                <Input
                  id="confirm-password"
                  name="confirm-password"
                  type={showConfirmPassword ? "text" : "password"}
                  autoComplete="new-password"
                  required
                  className="pl-10 pr-10 focus:border-sentinel-accent focus:ring-sentinel-accent/50 bg-sentinel-dark/50"
                  placeholder="••••••••"
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                />
                <button
                  type="button"
                  className="absolute inset-y-0 right-0 pr-3 flex items-center hover:text-sentinel-accent transition-colors"
                  onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                >
                  {showConfirmPassword ? <EyeOff className="h-5 w-5" /> : <Eye className="h-5 w-5" />}
                </button>
              </div>
            </div>
          </div>
        </div>

        <div className="flex items-center justify-between">
          <div className="text-sm">
            <span className="text-gray-400 mr-1">Already have an account?</span>
            <Link to="/login" className="font-medium text-sentinel-accent hover:text-sentinel-accent/80 inline-flex items-center group">
              <ArrowLeft className="mr-1 h-4 w-4 transform transition-transform group-hover:-translate-x-1" />
              Sign in
            </Link>
          </div>
        </div>

        <Button
          type="submit"
          className="w-full bg-sentinel-accent hover:bg-sentinel-accent/90 text-sentinel-dark relative overflow-hidden group"
          disabled={isLoading}
        >
          <span className="relative z-10 flex items-center justify-center">
            {isLoading ? "Creating account..." : "Create account"}
          </span>
          <span className="absolute inset-0 translate-y-full group-hover:translate-y-0 bg-gradient-to-r from-cyan-500 to-blue-500 transition-transform duration-300"></span>
        </Button>
      </form>
    </div>
  );
};

export default Register;
