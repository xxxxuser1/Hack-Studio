#!/usr/bin/env python3
"""
Report Generator for Ethical Hacking Toolkit
Generates professional security assessment reports
"""

import json
import argparse
from datetime import datetime
from typing import Dict, List, Any
import os


class ReportGenerator:
    def __init__(self, output_dir: str = "./reports"):
        self.output_dir = output_dir
        self.report_data = {
            "metadata": {},
            "findings": [],
            "recommendations": [],
            "summary": {}
        }
        
        # Create output directory if it doesn't exist
        os.makedirs(output_dir, exist_ok=True)
        
    def set_metadata(self, target: str, tester: str, date: str = None):
        """Set report metadata"""
        self.report_data["metadata"] = {
            "target": target,
            "tester": tester,
            "date": date or datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "toolkit_version": "1.0"
        }
        
    def add_finding(self, category: str, severity: str, title: str, description: str, 
                   evidence: str = "", recommendation: str = ""):
        """Add a security finding to the report"""
        finding = {
            "id": len(self.report_data["findings"]) + 1,
            "category": category,
            "severity": severity.upper(),
            "title": title,
            "description": description,
            "evidence": evidence,
            "recommendation": recommendation
        }
        self.report_data["findings"].append(finding)
        
    def add_recommendation(self, category: str, title: str, description: str):
        """Add a general recommendation to the report"""
        recommendation = {
            "id": len(self.report_data["recommendations"]) + 1,
            "category": category,
            "title": title,
            "description": description
        }
        self.report_data["recommendations"].append(recommendation)
        
    def set_summary(self, total_tests: int, vulnerabilities_found: int, 
                   critical: int, high: int, medium: int, low: int):
        """Set report summary statistics"""
        self.report_data["summary"] = {
            "total_tests": total_tests,
            "vulnerabilities_found": vulnerabilities_found,
            "severity_breakdown": {
                "critical": critical,
                "high": high,
                "medium": medium,
                "low": low
            }
        }
        
    def generate_json_report(self, filename: str = None) -> str:
        """Generate JSON report"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"security_report_{timestamp}.json"
            
        filepath = os.path.join(self.output_dir, filename)
        
        with open(filepath, 'w') as f:
            json.dump(self.report_data, f, indent=2)
            
        print(f"[+] JSON report saved to: {filepath}")
        return filepath
        
    def generate_text_report(self, filename: str = None) -> str:
        """Generate human-readable text report"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"security_report_{timestamp}.txt"
            
        filepath = os.path.join(self.output_dir, filename)
        
        with open(filepath, 'w') as f:
            # Header
            f.write("=" * 80 + "\n")
            f.write("ETHICAL HACKING SECURITY ASSESSMENT REPORT\n")
            f.write("=" * 80 + "\n\n")
            
            # Metadata
            meta = self.report_data["metadata"]
            f.write(f"Target: {meta['target']}\n")
            f.write(f"Tester: {meta['tester']}\n")
            f.write(f"Date: {meta['date']}\n")
            f.write(f"Toolkit Version: {meta['toolkit_version']}\n")
            f.write("\n")
            
            # Summary
            summary = self.report_data["summary"]
            if summary:
                f.write("EXECUTIVE SUMMARY\n")
                f.write("-" * 20 + "\n")
                f.write(f"Total Tests Performed: {summary['total_tests']}\n")
                f.write(f"Vulnerabilities Found: {summary['vulnerabilities_found']}\n")
                f.write("Severity Breakdown:\n")
                for severity, count in summary["severity_breakdown"].items():
                    f.write(f"  {severity.capitalize()}: {count}\n")
                f.write("\n")
                
            # Findings
            if self.report_data["findings"]:
                f.write("DETAILED FINDINGS\n")
                f.write("-" * 20 + "\n")
                for finding in self.report_data["findings"]:
                    f.write(f"[{finding['id']}] {finding['title']} ({finding['severity']})\n")
                    f.write(f"Category: {finding['category']}\n")
                    f.write(f"Description: {finding['description']}\n")
                    if finding['evidence']:
                        f.write(f"Evidence: {finding['evidence']}\n")
                    if finding['recommendation']:
                        f.write(f"Recommendation: {finding['recommendation']}\n")
                    f.write("\n")
                    
            # Recommendations
            if self.report_data["recommendations"]:
                f.write("GENERAL RECOMMENDATIONS\n")
                f.write("-" * 25 + "\n")
                for rec in self.report_data["recommendations"]:
                    f.write(f"[{rec['id']}] {rec['title']}\n")
                    f.write(f"Category: {rec['category']}\n")
                    f.write(f"Description: {rec['description']}\n")
                    f.write("\n")
                    
        print(f"[+] Text report saved to: {filepath}")
        return filepath
        
    def generate_html_report(self, filename: str = None) -> str:
        """Generate HTML report"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"security_report_{timestamp}.html"
            
        filepath = os.path.join(self.output_dir, filename)
        
        with open(filepath, 'w') as f:
            f.write("""
<!DOCTYPE html>
<html>
<head>
    <title>Ethical Hacking Security Assessment Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        h1, h2, h3 { color: #333; }
        .header { background-color: #f0f0f0; padding: 20px; border-radius: 5px; }
        .finding { border: 1px solid #ddd; margin: 10px 0; padding: 15px; border-radius: 5px; }
        .critical { border-left: 5px solid #d9534f; }
        .high { border-left: 5px solid #f0ad4e; }
        .medium { border-left: 5px solid #5bc0de; }
        .low { border-left: 5px solid #5cb85c; }
        .summary-table { border-collapse: collapse; width: 100%; }
        .summary-table td, .summary-table th { border: 1px solid #ddd; padding: 8px; }
        .summary-table tr:nth-child(even){ background-color: #f2f2f2; }
        .summary-table th { padding-top: 12px; padding-bottom: 12px; text-align: left; background-color: #4CAF50; color: white; }
    </style>
</head>
<body>
            """)
            
            # Header
            meta = self.report_data["metadata"]
            f.write(f"<div class='header'>\n")
            f.write(f"<h1>Ethical Hacking Security Assessment Report</h1>\n")
            f.write(f"<p><strong>Target:</strong> {meta['target']}</p>\n")
            f.write(f"<p><strong>Tester:</strong> {meta['tester']}</p>\n")
            f.write(f"<p><strong>Date:</strong> {meta['date']}</p>\n")
            f.write(f"<p><strong>Toolkit Version:</strong> {meta['toolkit_version']}</p>\n")
            f.write(f"</div>\n\n")
            
            # Summary
            summary = self.report_data["summary"]
            if summary:
                f.write("<h2>Executive Summary</h2>\n")
                f.write("<table class='summary-table'>\n")
                f.write("<tr><th>Metric</th><th>Value</th></tr>\n")
                f.write(f"<tr><td>Total Tests Performed</td><td>{summary['total_tests']}</td></tr>\n")
                f.write(f"<tr><td>Vulnerabilities Found</td><td>{summary['vulnerabilities_found']}</td></tr>\n")
                for severity, count in summary["severity_breakdown"].items():
                    f.write(f"<tr><td>{severity.capitalize()} Severity</td><td>{count}</td></tr>\n")
                f.write("</table>\n\n")
                
            # Findings
            if self.report_data["findings"]:
                f.write("<h2>Detailed Findings</h2>\n")
                for finding in self.report_data["findings"]:
                    severity_class = finding['severity'].lower()
                    f.write(f"<div class='finding {severity_class}'>\n")
                    f.write(f"<h3>[{finding['id']}] {finding['title']} <span style='color: {'#d9534f' if severity_class == 'critical' else '#f0ad4e' if severity_class == 'high' else '#5bc0de' if severity_class == 'medium' else '#5cb85c'}'>({finding['severity']})</span></h3>\n")
                    f.write(f"<p><strong>Category:</strong> {finding['category']}</p>\n")
                    f.write(f"<p><strong>Description:</strong> {finding['description']}</p>\n")
                    if finding['evidence']:
                        f.write(f"<p><strong>Evidence:</strong> {finding['evidence']}</p>\n")
                    if finding['recommendation']:
                        f.write(f"<p><strong>Recommendation:</strong> {finding['recommendation']}</p>\n")
                    f.write("</div>\n")
                    
            # Recommendations
            if self.report_data["recommendations"]:
                f.write("<h2>General Recommendations</h2>\n")
                for rec in self.report_data["recommendations"]:
                    f.write(f"<div class='finding'>\n")
                    f.write(f"<h3>[{rec['id']}] {rec['title']}</h3>\n")
                    f.write(f"<p><strong>Category:</strong> {rec['category']}</p>\n")
                    f.write(f"<p><strong>Description:</strong> {rec['description']}</p>\n")
                    f.write("</div>\n")
                    
            f.write("</body>\n</html>")
            
        print(f"[+] HTML report saved to: {filepath}")
        return filepath
        
    def load_from_json(self, filepath: str):
        """Load report data from JSON file"""
        try:
            with open(filepath, 'r') as f:
                self.report_data = json.load(f)
            print(f"[+] Report data loaded from: {filepath}")
        except Exception as e:
            print(f"[-] Error loading report: {e}")


def main():
    parser = argparse.ArgumentParser(description='Report Generator for Ethical Hacking Toolkit')
    parser.add_argument('-t', '--target', help='Target of the assessment')
    parser.add_argument('--tester', help='Name of the tester')
    parser.add_argument('--format', choices=['json', 'text', 'html'], default='text', help='Report format')
    parser.add_argument('--output', help='Output filename')
    parser.add_argument('--load', help='Load report data from JSON file')
    
    args = parser.parse_args()
    
    # Create report generator
    generator = ReportGenerator()
    
    # Load existing report if specified
    if args.load:
        generator.load_from_json(args.load)
    else:
        # Set metadata
        generator.set_metadata(
            target=args.target or "Unknown Target",
            tester=args.tester or "Anonymous Tester"
        )
        
        # Add sample findings (in a real scenario, these would come from actual tests)
        generator.add_finding(
            category="Web Application",
            severity="high",
            title="Missing Security Headers",
            description="The web application is missing several important security headers.",
            evidence="X-Frame-Options, X-Content-Type-Options, and Strict-Transport-Security headers are not set.",
            recommendation="Add security headers to all HTTP responses."
        )
        
        generator.add_finding(
            category="Network",
            severity="medium",
            title="Open Ports Detected",
            description="Several unnecessary ports are open on the target system.",
            evidence="Ports 22, 80, and 443 are open.",
            recommendation="Close unnecessary ports and implement proper firewall rules."
        )
        
        # Add recommendations
        generator.add_recommendation(
            category="General Security",
            title="Implement Regular Security Audits",
            description="Conduct regular security assessments to identify and remediate vulnerabilities."
        )
        
        # Set summary
        generator.set_summary(
            total_tests=15,
            vulnerabilities_found=2,
            critical=0,
            high=1,
            medium=1,
            low=0
        )
        
    # Generate report
    if args.format == 'json':
        generator.generate_json_report(args.output)
    elif args.format == 'text':
        generator.generate_text_report(args.output)
    elif args.format == 'html':
        generator.generate_html_report(args.output)


if __name__ == "__main__":
    main()