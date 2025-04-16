
import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { Shield, Mail, Lock, AlertCircle } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Alert, AlertDescription } from "@/components/ui/alert";

const Login = () => {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const navigate = useNavigate();

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
      // For demo purposes, we'll just set the auth state in localStorage
      setTimeout(() => {
        localStorage.setItem("sentinel-auth", "true");
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
      <div className="text-center">
        <div className="mx-auto h-16 w-16 rounded-full bg-sentinel-dark/50 p-3 backdrop-blur-sm cyber-border">
          <Shield className="h-full w-full text-sentinel-accent" />
        </div>
        <h2 className="mt-6 text-3xl font-bold text-white">SentinelNet</h2>
        <p className="mt-2 text-sm text-gray-400">
          Intelligent Threat Detection & Response
        </p>
      </div>

      {error && (
        <Alert variant="destructive" className="bg-destructive/20 border-destructive/50">
          <AlertCircle className="h-4 w-4" />
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      <form className="mt-8 space-y-6" onSubmit={handleSubmit}>
        <div className="space-y-4 rounded-md">
          <div>
            <Label htmlFor="email" className="block text-sm font-medium text-gray-200">
              Email
            </Label>
            <div className="mt-1 flex rounded-md shadow-sm">
              <div className="relative flex items-stretch flex-grow">
                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                  <Mail className="h-5 w-5 text-gray-400" />
                </div>
                <Input
                  id="email"
                  name="email"
                  type="email"
                  autoComplete="email"
                  required
                  className="pl-10"
                  placeholder="you@example.com"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                />
              </div>
            </div>
          </div>

          <div>
            <Label htmlFor="password" className="block text-sm font-medium text-gray-200">
              Password
            </Label>
            <div className="mt-1 flex rounded-md shadow-sm">
              <div className="relative flex items-stretch flex-grow">
                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                  <Lock className="h-5 w-5 text-gray-400" />
                </div>
                <Input
                  id="password"
                  name="password"
                  type="password"
                  autoComplete="current-password"
                  required
                  className="pl-10"
                  placeholder="••••••••"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                />
              </div>
            </div>
          </div>
        </div>

        <div className="flex items-center justify-between">
          <div className="text-sm">
            <span className="text-gray-400 mr-1">Don't have an account?</span>
            <Link to="/register" className="font-medium text-sentinel-accent hover:text-sentinel-accent/80">
              Sign up
            </Link>
          </div>
        </div>

        <Button
          type="submit"
          className="w-full bg-sentinel-accent hover:bg-sentinel-accent/90 text-sentinel-dark"
          disabled={isLoading}
        >
          {isLoading ? "Signing in..." : "Sign in"}
        </Button>
      </form>
    </div>
  );
};

export default Login;
