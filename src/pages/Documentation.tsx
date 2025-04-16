
import { useState } from "react";
import { Shield, BookOpen, FileText, Terminal, Search, ExternalLink, Coffee, Code, Network, Globe, Lock, AlertTriangle, Database, Zap } from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";

const Documentation = () => {
  const [searchQuery, setSearchQuery] = useState("");
  
  const documentationSections = [
    {
      id: "getting-started",
      title: "Getting Started",
      description: "Introduction to SentinelNet and basic concepts",
      icon: Shield,
      content: `
# Getting Started with SentinelNet

SentinelNet is an advanced cybersecurity platform that provides real-time monitoring, intelligent detection, and automated prevention of malicious network activity. The platform combines signature-based detection, anomaly-based detection, and stateful protocol analysis to provide comprehensive protection against a wide range of threats.

## Core Components

- **Dashboard**: Central command center displaying security metrics and real-time alerts
- **Alert Management**: Review and respond to detected security incidents
- **Traffic Analysis**: In-depth examination of network traffic patterns
- **Detection Methods**: Multiple detection engines working in parallel
- **Response Tools**: Automated and manual response capabilities

## Key Benefits

- Real-time monitoring of network traffic
- Intelligent detection using multiple methodologies
- Automated prevention of malicious activity
- Comprehensive logging and reporting
- Integration with popular security tools

## System Requirements

- Modern web browser (Chrome, Firefox, Safari, Edge)
- Network connection to monitored assets
- Admin privileges for configuration changes
      `
    },
    {
      id: "dashboard",
      title: "Dashboard",
      description: "Understanding the main dashboard",
      icon: BarChart2,
      content: `
# Dashboard

The SentinelNet dashboard provides a comprehensive overview of your security posture and real-time metrics.

## Key Elements

### Overview Stats
The top section displays critical metrics:
- Active Threats: Currently unresolved security issues
- Blocked Attacks: Total prevented intrusions
- Traffic Analyzed: Volume of network data processed
- System Uptime: Reliability metrics

### Network Activity Chart
The central chart displays:
- Traffic volume over time
- Overlay of detected anomalies
- Selectable time periods (1h, 24h, 7d, 30d)

### Threat Detection Panel
Shows recent malicious activities with details on:
- Threat type and severity
- Source and destination
- Time of detection
- Current status

### Protocol Distribution
Visual breakdown of network traffic by protocol type:
- HTTP/HTTPS
- DNS
- SSH
- SMTP
- Other protocols

### Detection Performance
Metrics on system accuracy:
- Detection rate percentage
- False positive rate

## Data Refresh Rate
Dashboard data is automatically refreshed at these intervals:
- Critical metrics: 60 seconds
- Charts and graphs: 5 minutes
- Threat detections: Real-time
      `
    },
    {
      id: "signature-detection",
      title: "Signature Detection",
      description: "Pattern matching against known threats",
      icon: FileText,
      content: `
# Signature-Based Detection

Signature-based detection identifies malicious activity by comparing network traffic against a database of known threat patterns.

## Working Principle

SentinelNet's signature detection engine operates by:
1. Analyzing network packets against rule definitions
2. Matching pattern signatures for known exploits, malware, and attacks
3. Triggering alerts when signatures match traffic patterns
4. Optionally blocking traffic based on rule actions

## Rule Management

Rules can be:
- Enabled/disabled individually
- Created using the rule editor
- Imported from threat intelligence feeds
- Exported for sharing or backup

## Rule Syntax

Rules follow this basic structure:
\`\`\`
action protocol source_ip source_port direction destination_ip destination_port (options)
\`\`\`

Example:
\`\`\`
alert tcp any any -> $HOME_NET 22 (msg:"SSH brute force attempt"; 
flow:to_server; threshold:type threshold, track by_src, count 5, 
seconds 60; classtype:attempted-admin; sid:1000001; rev:1;)
\`\`\`

## Performance Considerations

- Each rule adds processing overhead
- Use targeted rules for optimal performance
- Consider disabling rules for protocols not in use
- Regular rule updates are important for protection against new threats
      `
    },
    {
      id: "anomaly-detection",
      title: "Anomaly Detection",
      description: "Machine learning-based unusual behavior detection",
      icon: Brain,
      content: `
# Anomaly-Based Detection

Anomaly detection uses machine learning algorithms to identify unusual patterns and behaviors in network traffic that might indicate security threats.

## Machine Learning Approach

SentinelNet employs:
- Unsupervised learning to establish network baselines
- Supervised classification for known anomaly types
- Online learning to adapt to evolving network conditions

## Detection Capabilities

Identifies anomalies such as:
- Unusual traffic spikes or patterns
- Data exfiltration attempts
- Beaconing (regular communication indicative of C2)
- Protocol violations
- DNS tunneling and abnormalities
- Unusual port usage

## Sensitivity Configuration

Adjust detection sensitivity:
- Higher sensitivity: More alerts, possible false positives
- Lower sensitivity: Fewer alerts, possible missed threats
- Recommended: Start high and adjust based on environment

## Model Training

The anomaly detection model:
- Requires a baseline learning period
- Continuously improves with new data
- Can be manually retrained when network changes occur
- Adapts to your environment's normal patterns

## Alert Evaluation

Each anomaly is scored:
- 0.0-1.0 scale (higher = more anomalous)
- Context provides supporting evidence
- Visual representation in timeline view
- Investigation and remediation tools
      `
    },
    {
      id: "protocol-analysis",
      title: "Protocol Analysis",
      description: "Stateful inspection of network protocols",
      icon: Network,
      content: `
# Stateful Protocol Analysis

Stateful Protocol Analysis examines network traffic against predetermined profiles of generally accepted definitions of benign protocol activity.

## Protocol State Tracking

SentinelNet maintains:
- Session state tables for active connections
- Protocol transition states (establishing, active, closing)
- Expected behavior models for each protocol
- Violation detection for unexpected transitions

## Supported Protocols

Detailed analysis for:
- HTTP/HTTPS (including TLS negotiation)
- DNS (query/response validation)
- SSH (authentication sequence verification)
- FTP (command sequence monitoring)
- SMB/CIFS (Windows file sharing)
- RDP (Remote Desktop Protocol)

## Detection Capabilities

Identifies:
- Protocol downgrade attempts
- Invalid state transitions
- Malformed packets and headers
- Command injection attempts
- Protocol abuse tactics
- Authentication bypass attempts

## Session Inspection

For each connection:
- Full session reconstruction
- Bi-directional traffic analysis
- Content inspection where applicable
- Statistical anomaly detection
- Behavioral pattern matching

## Response Actions

When violations occur:
- Alert generation with context
- Optional session termination
- Historical correlation with similar violations
- Automatic rule generation for repeated violations
      `
    },
    {
      id: "traffic-blocking",
      title: "Traffic Blocking",
      description: "Automated threat prevention",
      icon: Ban,
      content: `
# Traffic Blocking

SentinelNet's traffic blocking capabilities provide automated prevention of malicious network activity.

## Blocking Methods

Multiple enforcement mechanisms:
- IP address blocking
- Port blocking (TCP/UDP)
- Protocol restrictions
- Custom firewall rules
- Connection termination

## Configuration Options

For each block type:
- Temporary or permanent duration
- Source/destination options
- Protocol specificity
- Manual or automated triggers
- Block reason documentation

## IPS vs. IDS Mode

Two operational modes:
- **IDS Mode (Passive)**: Detection only, no packet dropping
- **IPS Mode (Active)**: Automatic prevention by dropping malicious packets

## Automated Response

Configuration options:
- Severity thresholds for automatic blocking
- Whitelisting trusted sources
- Alert-to-block escalation rules
- Block duration policies

## Block Management

Administrative tools:
- Block history and audit trail
- Manual block addition and removal
- Block effectiveness metrics
- Exemption management
- Scheduled block expiration
      `
    },
    {
      id: "logging",
      title: "Logging & Reporting",
      description: "Comprehensive event recording and analysis",
      icon: Clock,
      content: `
# Logging & Reporting

SentinelNet provides comprehensive logging of security events and system actions with powerful reporting capabilities.

## Log Types

Categories of logs maintained:
- Security event logs
- System audit logs
- User activity logs
- Network traffic logs
- Configuration change logs

## Log Detail Levels

Available granularity:
- Critical: Severe security events requiring immediate attention
- High: Significant security events
- Medium: Notable but not urgent security events
- Low: Informational security-related events
- Info: General system operations

## Storage & Retention

Log management features:
- Configurable retention periods
- Storage optimization
- Automatic archiving
- Compliance-oriented retention policies

## Search & Filter

Advanced query capabilities:
- Full-text search
- Time range filtering
- Source/destination filtering
- Severity filtering
- Event type filtering

## Export Options

Data portability:
- CSV export for spreadsheet analysis
- JSON export for programmatic use
- PDF reports for executive summaries
- Scheduled report generation
- Email delivery options
      `
    },
    {
      id: "tools",
      title: "Security Tools",
      description: "Integrated third-party security tools",
      icon: Terminal,
      content: `
# Integrated Security Tools

SentinelNet integrates with popular open-source security tools to enhance detection and response capabilities.

## Snort

Network intrusion detection system:
- Signature-based packet inspection
- Rule management interface
- Real-time alert monitoring
- Custom rule creation
- IPS capabilities for packet dropping

## Suricata

High-performance network IDS/IPS:
- Multi-threaded architecture
- Application layer inspection
- File extraction and analysis
- TLS certificate validation
- Protocol anomaly detection

## Security Onion

Network security monitoring platform:
- Full packet capture
- Network flow analysis
- Host-based detection
- Indicator of compromise scanning
- Threat intelligence integration

## OWASP ZAP

Web application security scanner:
- Active and passive scanning
- API security testing
- Web crawler functionality
- Authentication testing
- Vulnerability reporting

## RequestShield

API security monitoring:
- API traffic analysis
- Request/response validation
- Schema enforcement
- Rate limiting visualization
- Authentication monitoring
      `
    },
    {
      id: "configuration",
      title: "Configuration",
      description: "System setup and customization",
      icon: Settings,
      content: `
# Configuration

SentinelNet offers extensive configuration options to tailor the system to your security needs.

## System Settings

Core configuration:
- Network interfaces monitoring
- Logging verbosity
- Default alert thresholds
- Performance tuning
- Update preferences

## User Management

Access control:
- User roles and permissions
- Authentication methods
- Session policies
- Activity auditing
- Role-based views

## Integration Settings

External connections:
- Threat intelligence feeds
- SIEM integration
- Email notifications
- Webhook alerts
- API access tokens

## Alerting Configuration

Notification settings:
- Alert priorities
- Delivery methods
- Aggregation rules
- Escalation policies
- On-call scheduling

## Backup & Recovery

Data protection:
- Configuration backup
- Rule export/import
- Automated backups
- Disaster recovery options
- Version control for configurations
      `
    }
  ];
  
  const filteredSections = searchQuery 
    ? documentationSections.filter(section => 
        section.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
        section.description.toLowerCase().includes(searchQuery.toLowerCase()) ||
        section.content.toLowerCase().includes(searchQuery.toLowerCase())
      )
    : documentationSections;
  
  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-3xl font-bold tracking-tight">Documentation</h2>
          <p className="text-muted-foreground">
            User guides and reference materials for SentinelNet
          </p>
        </div>
        <div className="flex items-center space-x-2">
          <Button variant="outline">
            <FileText className="mr-2 h-4 w-4" />
            Download PDF
          </Button>
        </div>
      </div>
      
      <div className="relative">
        <Search className="absolute left-2 top-3 h-4 w-4 text-muted-foreground" />
        <Input
          placeholder="Search documentation..."
          className="pl-8"
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
        />
      </div>
      
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        <div className="col-span-1 space-y-4">
          <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm">
            <CardHeader>
              <CardTitle>Contents</CardTitle>
            </CardHeader>
            <CardContent>
              <ul className="space-y-2">
                {documentationSections.map((section) => (
                  <li key={section.id}>
                    <a 
                      href={`#${section.id}`}
                      className="flex items-center py-1 px-2 rounded-md hover:bg-sentinel-light/10 text-sm transition-colors"
                      onClick={(e) => {
                        e.preventDefault();
                        document.getElementById(section.id)?.scrollIntoView({ behavior: 'smooth' });
                      }}
                    >
                      <section.icon className="h-4 w-4 mr-2 text-sentinel-accent" />
                      {section.title}
                    </a>
                  </li>
                ))}
              </ul>
            </CardContent>
          </Card>
          
          <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm">
            <CardHeader>
              <CardTitle>Related Resources</CardTitle>
            </CardHeader>
            <CardContent>
              <ul className="space-y-2">
                <li>
                  <a 
                    href="#" 
                    className="flex items-center py-1 px-2 rounded-md hover:bg-sentinel-light/10 text-sm transition-colors"
                  >
                    <Globe className="h-4 w-4 mr-2 text-sentinel-info" />
                    Online Knowledge Base
                  </a>
                </li>
                <li>
                  <a 
                    href="#" 
                    className="flex items-center py-1 px-2 rounded-md hover:bg-sentinel-light/10 text-sm transition-colors"
                  >
                    <Coffee className="h-4 w-4 mr-2 text-sentinel-warning" />
                    Community Forums
                  </a>
                </li>
                <li>
                  <a 
                    href="#" 
                    className="flex items-center py-1 px-2 rounded-md hover:bg-sentinel-light/10 text-sm transition-colors"
                  >
                    <Code className="h-4 w-4 mr-2 text-sentinel-danger" />
                    API Reference
                  </a>
                </li>
                <li>
                  <a 
                    href="#" 
                    className="flex items-center py-1 px-2 rounded-md hover:bg-sentinel-light/10 text-sm transition-colors"
                  >
                    <ExternalLink className="h-4 w-4 mr-2 text-sentinel-success" />
                    Video Tutorials
                  </a>
                </li>
              </ul>
            </CardContent>
          </Card>
        </div>
        
        <div className="col-span-1 md:col-span-3 space-y-6">
          {filteredSections.length > 0 ? (
            filteredSections.map((section) => (
              <Card 
                key={section.id} 
                id={section.id}
                className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm scroll-mt-6"
              >
                <CardHeader>
                  <div className="flex items-center space-x-2">
                    <section.icon className="h-5 w-5 text-sentinel-accent" />
                    <CardTitle>{section.title}</CardTitle>
                  </div>
                  <CardDescription>
                    {section.description}
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="prose prose-invert max-w-none">
                    <div dangerouslySetInnerHTML={{ 
                      __html: section.content
                        .replace(/^# (.*$)/gm, '<h2 class="text-2xl font-bold mt-4 mb-2">$1</h2>')
                        .replace(/^## (.*$)/gm, '<h3 class="text-xl font-bold mt-4 mb-2">$1</h3>')
                        .replace(/^### (.*$)/gm, '<h4 class="text-lg font-bold mt-3 mb-1">$1</h4>')
                        .replace(/^\- (.*$)/gm, '<li class="ml-4">$1</li>')
                        .replace(/^\d\. (.*$)/gm, '<li class="ml-4">$1</li>')
                        .replace(/```([\s\S]*?)```/g, '<pre class="bg-sentinel-dark/50 p-3 rounded-md text-sm overflow-x-auto my-3">$1</pre>')
                        .split('\n').join('<br />')
                    }} />
                  </div>
                </CardContent>
              </Card>
            ))
          ) : (
            <Card className="border-sentinel-light/10 bg-card/50 backdrop-blur-sm">
              <CardHeader>
                <CardTitle>No Results Found</CardTitle>
                <CardDescription>
                  No documentation sections match your search query.
                </CardDescription>
              </CardHeader>
              <CardContent>
                <p>Try adjusting your search terms or browse the available sections in the contents menu.</p>
                <Button 
                  variant="outline" 
                  className="mt-4"
                  onClick={() => setSearchQuery("")}
                >
                  Clear Search
                </Button>
              </CardContent>
            </Card>
          )}
        </div>
      </div>
    </div>
  );
};

export default Documentation;

function BarChart2(props: any) {
  return (
    <svg
      {...props}
      xmlns="http://www.w3.org/2000/svg"
      width="24"
      height="24"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <line x1="18" x2="18" y1="20" y2="10" />
      <line x1="12" x2="12" y1="20" y2="4" />
      <line x1="6" x2="6" y1="20" y2="14" />
    </svg>
  );
}

function Ban(props: any) {
  return (
    <svg
      {...props}
      xmlns="http://www.w3.org/2000/svg"
      width="24"
      height="24"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <circle cx="12" cy="12" r="10" />
      <line x1="4.93" x2="19.07" y1="4.93" y2="19.07" />
    </svg>
  );
}

function Brain(props: any) {
  return (
    <svg
      {...props}
      xmlns="http://www.w3.org/2000/svg"
      width="24"
      height="24"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <path d="M9.5 2A2.5 2.5 0 0 1 12 4.5v15a2.5 2.5 0 0 1-4.96.44 2.5 2.5 0 0 1-2.96-3.08 3 3 0 0 1-.34-5.58 2.5 2.5 0 0 1 1.32-4.24 2.5 2.5 0 0 1 1.98-3A2.5 2.5 0 0 1 9.5 2Z" />
      <path d="M14.5 2A2.5 2.5 0 0 0 12 4.5v15a2.5 2.5 0 0 0 4.96.44 2.5 2.5 0 0 0 2.96-3.08 3 3 0 0 0 .34-5.58 2.5 2.5 0 0 0-1.32-4.24 2.5 2.5 0 0 0-1.98-3A2.5 2.5 0 0 0 14.5 2Z" />
    </svg>
  );
}

function Settings(props: any) {
  return (
    <svg
      {...props}
      xmlns="http://www.w3.org/2000/svg"
      width="24"
      height="24"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <path d="M12.22 2h-.44a2 2 0 0 0-2 2v.18a2 2 0 0 1-1 1.73l-.43.25a2 2 0 0 1-2 0l-.15-.08a2 2 0 0 0-2.73.73l-.22.38a2 2 0 0 0 .73 2.73l.15.1a2 2 0 0 1 1 1.72v.51a2 2 0 0 1-1 1.74l-.15.09a2 2 0 0 0-.73 2.73l.22.38a2 2 0 0 0 2.73.73l.15-.08a2 2 0 0 1 2 0l.43.25a2 2 0 0 1 1 1.73V20a2 2 0 0 0 2 2h.44a2 2 0 0 0 2-2v-.18a2 2 0 0 1 1-1.73l.43-.25a2 2 0 0 1 2 0l.15.08a2 2 0 0 0 2.73-.73l.22-.39a2 2 0 0 0-.73-2.73l-.15-.08a2 2 0 0 1-1-1.74v-.5a2 2 0 0 1 1-1.74l.15-.09a2 2 0 0 0 .73-2.73l-.22-.38a2 2 0 0 0-2.73-.73l-.15.08a2 2 0 0 1-2 0l-.43-.25a2 2 0 0 1-1-1.73V4a2 2 0 0 0-2-2z" />
      <circle cx="12" cy="12" r="3" />
    </svg>
  );
}
