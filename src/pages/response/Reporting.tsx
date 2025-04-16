
import { useState } from "react";
import { 
  FileText, 
  Calendar, 
  Download, 
  RefreshCw, 
  PieChart,
  BarChart2,
  Shield,
  Clock,
  ChevronDown,
  Check
} from "lucide-react";
import { 
  Card, 
  CardContent, 
  CardDescription, 
  CardFooter, 
  CardHeader, 
  CardTitle 
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import { 
  Table, 
  TableBody, 
  TableCaption, 
  TableCell, 
  TableHead, 
  TableHeader, 
  TableRow 
} from "@/components/ui/table";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { 
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { toast } from "sonner";

// Mock report templates
const reportTemplates = [
  {
    id: 1,
    name: "Monthly Security Summary",
    description: "Overview of all security events and incidents",
    lastGenerated: "2025-04-01T10:30:00Z",
    type: "scheduled"
  },
  {
    id: 2,
    name: "Critical Events Report",
    description: "Detailed analysis of critical security events",
    lastGenerated: "2025-04-10T15:45:00Z",
    type: "scheduled"
  },
  {
    id: 3,
    name: "Data Exfiltration Analysis",
    description: "Analysis of suspected data exfiltration attempts",
    lastGenerated: "2025-04-12T08:20:00Z",
    type: "on-demand"
  },
  {
    id: 4,
    name: "Compliance Report",
    description: "Security events categorized by compliance requirements",
    lastGenerated: "2025-03-31T11:15:00Z",
    type: "scheduled"
  },
  {
    id: 5,
    name: "Threat Intelligence Summary",
    description: "Summary of detected threats with intelligence context",
    lastGenerated: "2025-04-15T09:30:00Z",
    type: "on-demand"
  }
];

// Mock generated reports
const generatedReports = [
  {
    id: 1,
    name: "Monthly Security Summary - March 2025",
    template: "Monthly Security Summary",
    generatedAt: "2025-04-01T10:30:00Z",
    size: "2.4MB",
    format: "PDF"
  },
  {
    id: 2,
    name: "Critical Events Report - March 2025",
    template: "Critical Events Report",
    generatedAt: "2025-03-31T15:45:00Z",
    size: "1.8MB",
    format: "PDF"
  },
  {
    id: 3,
    name: "Critical Events Report - February 2025",
    template: "Critical Events Report",
    generatedAt: "2025-03-01T16:20:00Z",
    size: "1.5MB",
    format: "PDF"
  },
  {
    id: 4,
    name: "Data Exfiltration Analysis - Q1 2025",
    template: "Data Exfiltration Analysis",
    generatedAt: "2025-04-12T08:20:00Z",
    size: "3.2MB",
    format: "PDF"
  },
  {
    id: 5,
    name: "Compliance Report - Q1 2025",
    template: "Compliance Report",
    generatedAt: "2025-03-31T11:15:00Z",
    size: "4.7MB",
    format: "PDF"
  },
  {
    id: 6,
    name: "Compliance Report - Q4 2024",
    template: "Compliance Report",
    generatedAt: "2025-01-05T10:30:00Z",
    size: "4.5MB",
    format: "PDF"
  },
  {
    id: 7,
    name: "Threat Intelligence Summary - Week 15",
    template: "Threat Intelligence Summary",
    generatedAt: "2025-04-15T09:30:00Z",
    size: "1.1MB",
    format: "PDF"
  },
  {
    id: 8,
    name: "Monthly Security Summary - February 2025",
    template: "Monthly Security Summary",
    generatedAt: "2025-03-01T09:15:00Z",
    size: "2.2MB",
    format: "PDF"
  }
];

const Reporting = () => {
  const [activeTab, setActiveTab] = useState("templates");

  // Handler for generating a report
  const generateReport = (templateId) => {
    const template = reportTemplates.find(t => t.id === templateId);
    toast.success(`Generating ${template.name}`, {
      description: "Your report will be available in a few moments"
    });
  };

  // Handler for downloading a report
  const downloadReport = (reportId) => {
    const report = generatedReports.find(r => r.id === reportId);
    toast.success(`Downloading ${report.name}`, {
      description: `${report.format} file (${report.size})`
    });
  };

  return (
    <div className="container mx-auto p-4 space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Security Reports</h1>
        <p className="text-muted-foreground">Generate, schedule, and manage security reports</p>
      </div>

      <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
        <TabsList className="grid grid-cols-2 w-full max-w-md">
          <TabsTrigger value="templates">Report Templates</TabsTrigger>
          <TabsTrigger value="generated">Generated Reports</TabsTrigger>
        </TabsList>
        
        {/* Report Templates Tab */}
        <TabsContent value="templates" className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {reportTemplates.map((template) => (
              <Card key={template.id} className="overflow-hidden">
                <CardHeader className="pb-4">
                  <div className="flex justify-between items-start">
                    <div className="space-y-1">
                      <CardTitle className="text-lg">{template.name}</CardTitle>
                      <CardDescription>{template.description}</CardDescription>
                    </div>
                    {template.type === "scheduled" ? (
                      <Badge className="bg-blue-500 hover:bg-blue-600">Scheduled</Badge>
                    ) : (
                      <Badge variant="outline">On-demand</Badge>
                    )}
                  </div>
                </CardHeader>
                <CardContent className="pb-2">
                  <div className="flex items-center text-sm text-muted-foreground">
                    <Calendar className="h-4 w-4 mr-1" />
                    Last generated: {new Date(template.lastGenerated).toLocaleDateString()}
                  </div>
                </CardContent>
                <CardFooter className="flex justify-between pt-2">
                  <Button 
                    variant="outline" 
                    size="sm"
                    onClick={() => {
                      toast.info(`Editing ${template.name} template`, {
                        description: "Template editor would open here"
                      });
                    }}
                  >
                    Edit Template
                  </Button>
                  <Button 
                    size="sm"
                    onClick={() => generateReport(template.id)}
                    className="flex items-center gap-1"
                  >
                    <RefreshCw className="h-3.5 w-3.5" />
                    Generate
                  </Button>
                </CardFooter>
              </Card>
            ))}
            
            {/* Create New Template Card */}
            <Card className="border-dashed">
              <CardHeader>
                <CardTitle className="text-lg">Create New Template</CardTitle>
                <CardDescription>Design a custom report template</CardDescription>
              </CardHeader>
              <CardContent className="flex flex-col items-center justify-center py-6">
                <Button
                  variant="outline"
                  className="h-10 w-10 rounded-full"
                  onClick={() => {
                    toast.info("Creating new report template", {
                      description: "Template editor would open here"
                    });
                  }}
                >
                  +
                </Button>
                <p className="mt-2 text-sm text-muted-foreground">Add Template</p>
              </CardContent>
            </Card>
          </div>
        </TabsContent>
        
        {/* Generated Reports Tab */}
        <TabsContent value="generated" className="space-y-4">
          <Card>
            <CardHeader>
              <div className="flex flex-col md:flex-row justify-between md:items-center gap-4">
                <div>
                  <CardTitle>Generated Reports</CardTitle>
                  <CardDescription>Access and download previously generated reports</CardDescription>
                </div>
                <div className="flex flex-col sm:flex-row gap-2">
                  <Select defaultValue="all">
                    <SelectTrigger className="w-full sm:w-[180px]">
                      <SelectValue placeholder="Filter by template" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="all">All Templates</SelectItem>
                      {reportTemplates.map((template) => (
                        <SelectItem key={template.id} value={template.name}>
                          {template.name}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                  <Button 
                    variant="outline"
                    className="flex items-center gap-1"
                    onClick={() => {
                      toast.info("Refreshing report list", {
                        description: "Report list updated"
                      });
                    }}
                  >
                    <RefreshCw className="h-4 w-4" />
                    Refresh
                  </Button>
                </div>
              </div>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Report Name</TableHead>
                    <TableHead>Template</TableHead>
                    <TableHead>Generated</TableHead>
                    <TableHead>Format</TableHead>
                    <TableHead>Size</TableHead>
                    <TableHead className="text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {generatedReports.map((report) => (
                    <TableRow key={report.id}>
                      <TableCell className="font-medium">{report.name}</TableCell>
                      <TableCell>{report.template}</TableCell>
                      <TableCell>
                        {new Date(report.generatedAt).toLocaleString()}
                      </TableCell>
                      <TableCell>
                        <Badge variant="outline">{report.format}</Badge>
                      </TableCell>
                      <TableCell>{report.size}</TableCell>
                      <TableCell className="text-right">
                        <DropdownMenu>
                          <DropdownMenuTrigger asChild>
                            <Button variant="ghost" size="sm">
                              <ChevronDown className="h-4 w-4" />
                            </Button>
                          </DropdownMenuTrigger>
                          <DropdownMenuContent align="end">
                            <DropdownMenuItem
                              onClick={() => downloadReport(report.id)}
                              className="flex items-center gap-2"
                            >
                              <Download className="h-4 w-4" />
                              <span>Download</span>
                            </DropdownMenuItem>
                            <DropdownMenuItem
                              onClick={() => {
                                toast.info("Viewing report", {
                                  description: "Report viewer would open here"
                                });
                              }}
                              className="flex items-center gap-2"
                            >
                              <FileText className="h-4 w-4" />
                              <span>View</span>
                            </DropdownMenuItem>
                            <DropdownMenuItem
                              onClick={() => {
                                toast.info("Sending report", {
                                  description: "Email dialog would open here"
                                });
                              }}
                              className="flex items-center gap-2"
                            >
                              <Check className="h-4 w-4" />
                              <span>Email</span>
                            </DropdownMenuItem>
                          </DropdownMenuContent>
                        </DropdownMenu>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
          
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-lg flex items-center gap-2">
                  <FileText className="h-5 w-5 text-blue-500" />
                  Total Reports
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-3xl font-bold">{generatedReports.length}</div>
                <p className="text-xs text-muted-foreground">Reports generated</p>
              </CardContent>
            </Card>
            
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-lg flex items-center gap-2">
                  <PieChart className="h-5 w-5 text-green-500" />
                  Templates
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-3xl font-bold">{reportTemplates.length}</div>
                <p className="text-xs text-muted-foreground">Active templates</p>
              </CardContent>
            </Card>
            
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-lg flex items-center gap-2">
                  <BarChart2 className="h-5 w-5 text-purple-500" />
                  Most Generated
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-lg font-medium">Monthly Summary</div>
                <p className="text-xs text-muted-foreground">2 reports this quarter</p>
              </CardContent>
            </Card>
            
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-lg flex items-center gap-2">
                  <Clock className="h-5 w-5 text-orange-500" />
                  Next Scheduled
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-lg font-medium">Critical Events</div>
                <p className="text-xs text-muted-foreground">In 2 days (Apr 18)</p>
              </CardContent>
            </Card>
          </div>
        </TabsContent>
      </Tabs>
    </div>
  );
};

export default Reporting;
