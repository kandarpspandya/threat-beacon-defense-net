
import { useState, useEffect } from "react";
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
  const navigate = useNavigate();

  useEffect(() => {
    // Trigger entrance animation
    const timer = setTimeout(() => {
      setShowAnimation(true);
    }, 100);

    return () => clearTimeout(timer);
  }, []);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsLoading(true);
    setError("");

    // Basic validation
    if (!email || !password) {
      setError("Please enter both email and password");
      setIsLoading(false);
      return;
    }

    // Email format validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      setError("Please enter a valid email address");
      setIsLoading(false);
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
          setIsLoading(false);
          return;
        }
        
        // Success path - set auth state and redirect
        localStorage.setItem("sentinel-auth", "true");
        toast.success("Login successful", {
          description: "Welcome to SentinelNet"
        });
        navigate("/");
        setIsLoading(false);
      }, 1500);
    } catch (err) {
      console.error("Login error:", err);
      setError("Authentication failed. Please check your credentials.");
      setIsLoading(false);
    }
  };

  return (
    <div className="w-full max-w-md space-y-8">
      <div className={`text-center transition-all duration-700 transform ${showAnimation ? 'translate-y-0 opacity-100' : 'translate-y-10 opacity-0'}`}>
        <div className="mx-auto h-16 w-16 rounded-full bg-sentinel-dark/50 p-3 backdrop-blur-sm border border-sentinel-accent/30 shadow-[0_0_15px_rgba(100,255,218,0.2)] relative overflow-hidden">
          <Shield className="h-full w-full text-sentinel-accent animate-pulse" />
          <div className="absolute inset-0 bg-gradient-to-r from-transparent via-sentinel-accent/20 to-transparent security-scan"></div>
        </div>
        <h2 className="mt-6 text-3xl font-bold text-white">SentinelNet</h2>
        <p className="mt-2 text-sm text-gray-400">
          Intelligent Threat Detection & Response
        </p>
      </div>

      {error && (
        <Alert variant="destructive" className="bg-destructive/20 border-destructive/50 animate-shake">
          <AlertCircle className="h-4 w-4" />
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      <form className={`mt-8 space-y-6 transition-all duration-700 delay-300 transform ${showAnimation ? 'translate-y-0 opacity-100' : 'translate-y-10 opacity-0'}`} onSubmit={handleSubmit}>
        <div className="space-y-4 rounded-md">
          <div className="relative group">
            <Label htmlFor="email" className="block text-sm font-medium text-gray-200 transition-all duration-300 group-focus-within:text-sentinel-accent">
              Email
            </Label>
            <div className="mt-1 flex rounded-md shadow-sm">
              <div className="relative flex items-stretch flex-grow">
                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                  <Mail className="h-5 w-5 text-gray-400 transition-colors duration-300 group-focus-within:text-sentinel-accent" />
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

          <div className="relative group">
            <Label htmlFor="password" className="block text-sm font-medium text-gray-200 transition-all duration-300 group-focus-within:text-sentinel-accent">
              Password
            </Label>
            <div className="mt-1 flex rounded-md shadow-sm">
              <div className="relative flex items-stretch flex-grow">
                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                  <Lock className="h-5 w-5 text-gray-400 transition-colors duration-300 group-focus-within:text-sentinel-accent" />
                </div>
                <Input
                  id="password"
                  name="password"
                  type={showPassword ? "text" : "password"}
                  autoComplete="current-password"
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
          </div>
        </div>

        <div className="flex items-center justify-between">
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
