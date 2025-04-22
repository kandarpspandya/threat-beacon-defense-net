import { Download } from "lucide-react";
import { Button } from "@/components/ui/button";
import { toast } from "sonner";

const Documentation = () => {
  const handleDownloadPDF = () => {
    // URL to your PDF file (replace with actual PDF URL)
    const pdfUrl = "/documentation/user-guide.pdf";
    
    try {
      // Create a temporary link element
      const link = document.createElement("a");
      link.href = pdfUrl;
      link.download = "idps-user-guide.pdf";
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      
      toast.success("Documentation download started");
    } catch (error) {
      console.error("Download error:", error);
      toast.error("Failed to download documentation");
    }
  };
  
  return (
    <div className="container mx-auto px-4 py-6 max-w-4xl">
      <div className="flex items-center justify-between mb-8">
        <h1 className="text-3xl font-bold">Documentation</h1>
        <Button onClick={handleDownloadPDF} variant="default" className="gap-2">
          <Download className="h-4 w-4" />
          Download User Guide
        </Button>
      </div>
      
      <section className="mb-6">
        <h2 className="text-2xl font-semibold mb-4">Introduction</h2>
        <p className="text-gray-400">
          Welcome to the IDPS.net documentation. This guide provides you with
          the necessary information to understand, configure, and utilize our
          Intelligent Detection & Prevention System effectively.
        </p>
      </section>

      <section className="mb-6">
        <h2 className="text-2xl font-semibold mb-4">
          Getting Started
        </h2>
        <h3 className="text-xl font-semibold mb-2">
          Installation
        </h3>
        <p className="text-gray-400 mb-2">
          To install IDPS.net, follow these steps:
        </p>
        <ol className="list-decimal pl-5 text-gray-400">
          <li>Download the latest version from our website.</li>
          <li>Run the installer and follow the on-screen instructions.</li>
          <li>Configure the necessary network settings.</li>
        </ol>
      </section>

      <section className="mb-6">
        <h2 className="text-2xl font-semibold mb-4">
          Configuration
        </h2>
        <h3 className="text-xl font-semibold mb-2">
          Network Settings
        </h3>
        <p className="text-gray-400 mb-2">
          Configure your network settings to ensure proper monitoring and
          prevention.
        </p>
        <ul className="list-disc pl-5 text-gray-400">
          <li>Set up the correct network interface.</li>
          <li>Define the IP address ranges to monitor.</li>
          <li>Configure any necessary firewall rules.</li>
        </ul>
      </section>

      <section className="mb-6">
        <h2 className="text-2xl font-semibold mb-4">
          Usage
        </h2>
        <h3 className="text-xl font-semibold mb-2">
          Dashboard Overview
        </h3>
        <p className="text-gray-400 mb-2">
          The dashboard provides a comprehensive view of your network security
          status.
        </p>
        <ul className="list-disc pl-5 text-gray-400">
          <li>Monitor real-time traffic and threat levels.</li>
          <li>View recent alerts and security events.</li>
          <li>Customize the dashboard to display relevant information.</li>
        </ul>
      </section>

      <section className="mb-6">
        <h2 className="text-2xl font-semibold mb-4">
          Troubleshooting
        </h2>
        <h3 className="text-xl font-semibold mb-2">
          Common Issues
        </h3>
        <p className="text-gray-400 mb-2">
          Here are some common issues and their solutions:
        </p>
        <ul className="list-disc pl-5 text-gray-400">
          <li>
            <strong>Issue:</strong> No network traffic is being monitored.
            <br />
            <strong>Solution:</strong> Check your network settings and ensure
            the correct interface is selected.
          </li>
          <li>
            <strong>Issue:</strong> High false positive rate.
            <br />
            <strong>Solution:</strong> Adjust the sensitivity settings and
            review your custom rules.
          </li>
        </ul>
      </section>

      <section className="mb-6">
        <h2 className="text-2xl font-semibold mb-4">
          Advanced Features
        </h2>
        <h3 className="text-xl font-semibold mb-2">
          Custom Rules
        </h3>
        <p className="text-gray-400 mb-2">
          Create custom rules to detect specific threats and behaviors.
        </p>
        <ul className="list-disc pl-5 text-gray-400">
          <li>Use our rule editor to define custom patterns.</li>
          <li>Test your rules to ensure they function correctly.</li>
          <li>Deploy your rules to the live monitoring system.</li>
        </ul>
      </section>

      <section className="mb-6">
        <h2 className="text-2xl font-semibold mb-4">
          Support
        </h2>
        <p className="text-gray-400">
          If you encounter any issues or have questions, please contact our
          support team at <a href="mailto:support@idps.net">support@idps.net</a>.
        </p>
      </section>
    </div>
  );
};

export default Documentation;
