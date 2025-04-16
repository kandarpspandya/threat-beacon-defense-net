
import { Toaster } from "@/components/ui/toaster";
import { Toaster as Sonner } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import { ThemeProvider } from "@/components/theme-provider";
import "@fontsource/inter/400.css";
import "@fontsource/inter/500.css";
import "@fontsource/inter/600.css";
import "@fontsource/inter/700.css";

// Pages
import Dashboard from "./pages/Dashboard";
import Login from "./pages/Login";
import Register from "./pages/Register";
import AlertsPage from "./pages/AlertsPage";
import TrafficAnalysis from "./pages/TrafficAnalysis";
import Settings from "./pages/Settings";
import NotFound from "./pages/NotFound";
import AuthLayout from "./components/layouts/AuthLayout";
import DashboardLayout from "./components/layouts/DashboardLayout";

// New Detection Tools Pages
import SignatureDetection from "./pages/detection/SignatureDetection";
import AnomalyDetection from "./pages/detection/AnomalyDetection";
import ProtocolAnalysis from "./pages/detection/ProtocolAnalysis";

// New Response Tools Pages
import TrafficBlocking from "./pages/response/TrafficBlocking";
import AlertManagement from "./pages/response/AlertManagement";
import Logging from "./pages/response/Logging";
import Reporting from "./pages/response/Reporting";

// IDPS Tools Pages
import SuricataTool from "./pages/tools/SuricataTool";
import SecurityOnion from "./pages/tools/SecurityOnion";
import OwaspZap from "./pages/tools/OwaspZap";
import RequestShield from "./pages/tools/RequestShield";

// Documentation
import Documentation from "./pages/Documentation";

const queryClient = new QueryClient();

const App = () => (
  <QueryClientProvider client={queryClient}>
    <ThemeProvider defaultTheme="dark" storageKey="sentinelnet-theme">
      <TooltipProvider>
        <Toaster />
        <Sonner />
        <BrowserRouter>
          <Routes>
            {/* Auth Routes */}
            <Route element={<AuthLayout />}>
              <Route path="/login" element={<Login />} />
              <Route path="/register" element={<Register />} />
            </Route>
            
            {/* App Routes */}
            <Route element={<DashboardLayout />}>
              <Route path="/" element={<Dashboard />} />
              <Route path="/alerts" element={<AlertsPage />} />
              <Route path="/traffic" element={<TrafficAnalysis />} />
              <Route path="/settings" element={<Settings />} />
              
              {/* Detection Methods */}
              <Route path="/signature-detection" element={<SignatureDetection />} />
              <Route path="/anomaly-detection" element={<AnomalyDetection />} />
              <Route path="/protocol-analysis" element={<ProtocolAnalysis />} />
              
              {/* Response Tools */}
              <Route path="/response/blocking" element={<TrafficBlocking />} />
              <Route path="/response/alerting" element={<AlertManagement />} />
              <Route path="/response/logging" element={<Logging />} />
              <Route path="/response/reporting" element={<Reporting />} />
              
              {/* IDPS Tools */}
              <Route path="/tools/suricata" element={<SuricataTool />} />
              <Route path="/tools/security-onion" element={<SecurityOnion />} />
              <Route path="/tools/zap" element={<OwaspZap />} />
              <Route path="/tools/requestshield" element={<RequestShield />} />
              
              {/* Documentation */}
              <Route path="/documentation" element={<Documentation />} />
            </Route>
            
            {/* Catch All */}
            <Route path="*" element={<NotFound />} />
          </Routes>
        </BrowserRouter>
      </TooltipProvider>
    </ThemeProvider>
  </QueryClientProvider>
);

export default App;
